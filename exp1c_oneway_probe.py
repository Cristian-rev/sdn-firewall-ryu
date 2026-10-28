"""E1c. Latencia de aplicacion medida con una sonda de tasa fija y captura en el destino.

E1b mostro que `ping -i 0.002` deja de enviar cada 2 ms cuando no recibe respuestas
(baja a ~1 paquete cada 10 ms), de modo que la reapertura tras un desbloqueo se mide con
una resolucion de ~10 ms. Aqui:
  - h1 envia ICMP echo a tasa fija con hping3 (un paquete cada 1 ms, sin depender de respuestas)
  - h3 registra con un socket crudo la hora de llegada de cada paquete
  t_dp(block)   = ultima llegada posterior a t0
  t_dp(unblock) = primera llegada posterior a t0
La medida es de un solo sentido (h1 -> h3), afectada solo por la regla nw_dst.

Uso (root, Ryu en ejecucion con FW_MIRROR=0 FW_DETECT=0):
    sudo -E python3 exp1c_oneway_probe.py --reps 30
"""
import argparse
import time

import common as U
import config as C
from topo import host_ip, start_net

RECEIVER = r'''
import socket, time, sys
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
s.settimeout(0.5)
end = time.time() + float(sys.argv[1])
with open(sys.argv[2], "w", buffering=1) as f:
    while time.time() < end:
        try:
            data = s.recv(2048)
        except socket.timeout:
            continue
        t = time.time()
        if len(data) > 20 and data[20] == 8:      # echo request
            f.write("%.6f\n" % t)
'''


def run(hosts, reps, interval_us):
    net = start_net(hosts)
    src, dst = net.get("h1"), net.get(f"h{hosts}")
    target = host_ip(hosts)
    with open("/tmp/e1c_rx.py", "w") as fh:
        fh.write(RECEIVER)
    log = U.CsvLog("e1c_oneway", [
        "rep", "action", "status", "t_api_ms", "t_dp_ms", "probe_interval_ms",
        "rx_packets", "first_rel_ms", "last_rel_ms", "n_before_t0"])
    U.clear_all_rules()
    try:
        for rep in range(-C.WARMUP, reps):
            for action in ("block", "unblock"):
                dst.cmd("python3 /tmp/e1c_rx.py 4.0 /tmp/e1c_rx.txt > /dev/null 2>&1 &")
                rx_pid = dst.cmd("echo $!").strip()
                time.sleep(0.3)
                src.cmd(f"hping3 --icmp -i u{interval_us} -q {target} > /dev/null 2>&1 &")
                tx_pid = src.cmd("echo $!").strip()
                time.sleep(1.0)
                t0 = time.time()
                st, _, lat = U.block(target) if action == "block" else U.unblock(target)
                time.sleep(2.0)
                src.cmd(f"kill -INT {tx_pid}")
                dst.cmd(f"kill {rx_pid}")
                time.sleep(0.3)
                arr = [float(x) for x in dst.cmd("cat /tmp/e1c_rx.txt").split()]
                if action == "block":
                    after = [t for t in arr if t0 <= t <= t0 + C.TIMEOUT]
                    t_dp = (max(after) - t0) if after else 0.0
                else:
                    after = [t for t in arr if t >= t0]
                    t_dp = (min(after) - t0) if after else None
                gaps = sorted(b - a for a, b in zip(arr, arr[1:]))
                gap = gaps[len(gaps) // 2] * 1000 if gaps else ""
                if rep >= 0:
                    log.row(rep=rep, action=action, status=st,
                            t_api_ms=round(lat * 1000, 3),
                            t_dp_ms=round(t_dp * 1000, 3) if t_dp is not None else "",
                            probe_interval_ms=round(gap, 3) if gap != "" else "",
                            rx_packets=len(arr),
                            first_rel_ms=round((arr[0]-t0)*1000, 1) if arr else "",
                            last_rel_ms=round((arr[-1]-t0)*1000, 1) if arr else "",
                            n_before_t0=sum(t < t0 for t in arr))
                time.sleep(0.5)
    finally:
        log.close()
        U.clear_all_rules()
        net.stop()


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--hosts", type=int, default=3)
    ap.add_argument("--reps", type=int, default=C.REPETITIONS)
    ap.add_argument("--interval-us", type=int, default=1000)
    a = ap.parse_args()
    run(a.hosts, a.reps, a.interval_us)
