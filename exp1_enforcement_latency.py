"""E1. Latencia de aplicacion de politicas (RQ1).

Mide, para cada orden de bloqueo/desbloqueo enviada por la API REST:
  t_api   : tiempo de respuesta HTTP de la API
  t_flow  : tiempo hasta que las reglas DROP aparecen (o desaparecen) en la tabla del switch
  t_dp    : tiempo hasta que el trafico de datos deja de (o vuelve a) llegar al destino

Uso (como root, con Ryu ya en ejecucion):
    sudo -E python3 exp1_enforcement_latency.py --hosts 3 --reps 30
"""
import argparse
import re
import time

import common as U
import config as C
from topo import host_ip, start_net


def run(hosts, reps):
    net = start_net(hosts)
    src, dst = net.get("h1"), net.get(f"h{hosts}")
    target = host_ip(hosts)
    log = U.CsvLog("e1_enforcement", [
        "rep", "hosts", "action", "status", "t_api_ms", "t_flow_ms", "t_dp_ms",
        "t_dp_below_probe"])
    U.clear_all_rules()
    try:
        for rep in range(-C.WARMUP, reps):
            for action in ("block", "unblock"):
                # sonda de datos: ping cada 2 ms con marcas de tiempo
                src.cmd(f"stdbuf -oL ping -D -i 0.002 {target} > /tmp/e1_ping.txt 2>&1 &")
                probe_pid = src.cmd("echo $!").strip()
                time.sleep(1.0)
                t0 = time.time()
                if action == "block":
                    st, _, lat = U.block(target)
                    t_flow = U.wait_flow_state(target, present=True)
                else:
                    st, _, lat = U.unblock(target)
                    t_flow = U.wait_flow_state(target, present=False)
                time.sleep(2.0)
                src.cmd(f"kill -INT {probe_pid}")
                time.sleep(0.2)
                out = src.cmd("cat /tmp/e1_ping.txt")
                replies = [float(m) for m in
                           re.findall(r"\[(\d+\.\d+)\][^\n]*bytes from", out)]
                if action == "block":
                    before = [t for t in replies if t <= t0 + C.TIMEOUT]
                    after_t0 = [t for t in before if t >= t0]
                    # sin ecos despues de t0: el corte ocurrio antes del siguiente sondeo
                    t_dp = (max(after_t0) - t0) if after_t0 else 0.0
                    below = int(not after_t0)
                else:
                    after = [t for t in replies if t >= t0]
                    t_dp = (min(after) - t0) if after else None
                    below = 0
                if rep >= 0:
                    log.row(rep=rep, hosts=hosts, action=action, status=st,
                            t_api_ms=round(lat * 1000, 3),
                            t_flow_ms=round((t_flow - t0) * 1000, 3) if t_flow else "",
                            t_dp_ms=round(t_dp * 1000, 3) if t_dp is not None else "",
                            t_dp_below_probe=below)
                time.sleep(0.5)
    finally:
        log.close()
        U.clear_all_rules()
        net.stop()


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--hosts", type=int, default=3)
    ap.add_argument("--reps", type=int, default=C.REPETITIONS)
    a = ap.parse_args()
    U.save_environment()
    run(a.hosts, a.reps)
