"""E1b. Diagnostico de la asimetria bloqueo/desbloqueo observada en E1.

En E1 el trafico se detiene ~4 ms despues de la orden de bloqueo, pero tarda ~10 ms
en reanudarse tras el desbloqueo. Este experimento separa tres explicaciones:

  api_poll        : replica de E1 (API REST + sondeo de la tabla con ovs-ofctl cada 1 ms)
  api_nopoll      : API REST sin sondeo de la tabla (descarta que el sondeo frene a OVS)
  api_nopoll_purge: igual, y tras la respuesta HTTP se vacia la cache del datapath
                    (ovs-appctl revalidator/purge); si el retraso viene de la
                    revalidacion de la cache, el desbloqueo deberia acelerarse
  direct          : reglas anadidas/borradas con ovs-ofctl sin pasar por Ryu
                    (aisla el comportamiento de OVS del controlador)

Uso (root, Ryu en ejecucion con FW_MIRROR=0 FW_DETECT=0):
    sudo -E python3 exp1b_unblock_diagnosis.py --reps 30
"""
import argparse
import re
import subprocess
import time

import common as U
import config as C
from topo import host_ip, start_net

VARIANTS = ("api_poll", "api_nopoll", "api_nopoll_purge", "direct")


def ofctl(*args):
    t = time.time()
    subprocess.run(["ovs-ofctl", "-O", C.OF_VERSION, *args], check=False,
                   capture_output=True)
    return time.time() - t


def direct_block(ip):
    lat = 0.0
    for f in (f"nw_src={ip}", f"nw_dst={ip}"):
        lat += ofctl("add-flow", C.SWITCH,
                     f"priority={C.DROP_PRIORITY},ip,{f},actions=drop")
    return 200, None, lat


def direct_unblock(ip):
    lat = 0.0
    for f in (f"nw_src={ip}", f"nw_dst={ip}"):
        lat += ofctl("--strict", "del-flows", C.SWITCH,
                     f"priority={C.DROP_PRIORITY},ip,{f}")
    return 200, None, lat


def run(hosts, reps, variants):
    net = start_net(hosts)
    src = net.get("h1")
    target = host_ip(hosts)
    log = U.CsvLog("e1b_unblock_diag", [
        "rep", "variant", "action", "status", "t_cmd_ms", "t_flow_ms", "t_dp_ms",
        "t_dp_below_probe"])
    U.clear_all_rules()
    try:
        for variant in variants:
            for rep in range(-C.WARMUP, reps):
                for action in ("block", "unblock"):
                    src.cmd(f"stdbuf -oL ping -D -i 0.002 {target} > /tmp/e1b_ping.txt 2>&1 &")
                    probe_pid = src.cmd("echo $!").strip()
                    time.sleep(1.0)
                    t0 = time.time()
                    if variant == "direct":
                        fn = direct_block if action == "block" else direct_unblock
                    else:
                        fn = U.block if action == "block" else U.unblock
                    st, _, lat = fn(target)
                    if variant == "api_nopoll_purge":
                        subprocess.run(["ovs-appctl", "revalidator/purge"], check=False,
                                       capture_output=True)
                    t_flow = None
                    if variant == "api_poll":
                        t_flow = U.wait_flow_state(target, present=(action == "block"))
                    time.sleep(2.0)
                    src.cmd(f"kill -INT {probe_pid}")
                    time.sleep(0.2)
                    out = src.cmd("cat /tmp/e1b_ping.txt")
                    replies = [float(m) for m in
                               re.findall(r"\[(\d+\.\d+)\][^\n]*bytes from", out)]
                    if action == "block":
                        after_t0 = [t for t in replies if t0 <= t <= t0 + C.TIMEOUT]
                        t_dp = (max(after_t0) - t0) if after_t0 else 0.0
                        below = int(not after_t0)
                    else:
                        after = [t for t in replies if t >= t0]
                        t_dp = (min(after) - t0) if after else None
                        below = 0
                    if rep >= 0:
                        log.row(rep=rep, variant=variant, action=action, status=st,
                                t_cmd_ms=round(lat * 1000, 3),
                                t_flow_ms=round((t_flow - t0) * 1000, 3) if t_flow else "",
                                t_dp_ms=round(t_dp * 1000, 3) if t_dp is not None else "",
                                t_dp_below_probe=below)
                    time.sleep(0.5)
                # dejar el switch sin reglas DROP entre variantes
                U.clear_all_rules()
                ofctl("--strict", "del-flows", C.SWITCH, f"priority={C.DROP_PRIORITY},ip,nw_src={target}")
                ofctl("--strict", "del-flows", C.SWITCH, f"priority={C.DROP_PRIORITY},ip,nw_dst={target}")
    finally:
        log.close()
        U.clear_all_rules()
        net.stop()


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--hosts", type=int, default=3)
    ap.add_argument("--reps", type=int, default=C.REPETITIONS)
    ap.add_argument("--variants", default=",".join(VARIANTS))
    a = ap.parse_args()
    # no se llama a U.save_environment(): conserva el registro del entorno de la campana principal
    run(a.hosts, a.reps, a.variants.split(","))
