"""E2. Sobrecarga en el plano de datos (RQ2).

Compara una linea base sin firewall (p. ej. ryu.app.simple_switch_13) contra
el firewall, con trafico entre hosts NO bloqueados.

Escenarios usados en el articulo:
    ryu-manager ryu.app.simple_switch_13  ->  --scenario baseline
    ryu-manager firewall_seguro.py        ->  --scenario firewall_empty
    ryu-manager firewall_seguro.py        ->  --scenario firewall_rules --preload 100
    sudo -E python3 exp2_dataplane_overhead.py --scenario baseline --reps 30
"""
import argparse
import json
import re
import time

import common as U
import config as C
from topo import host_ip, start_net


def ping_stats(out):
    loss = re.search(r"(\d+(?:\.\d+)?)% packet loss", out)
    rtt = re.search(r"= ([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+) ms", out)
    return (float(loss.group(1)) if loss else None,
            float(rtt.group(2)) if rtt else None,
            float(rtt.group(4)) if rtt else None)


def _iperf(host, args, duration):
    """Ejecuta iperf3 con tiempo maximo; devuelve {} si falla o se cuelga."""
    out = host.cmd(f"timeout {duration + 15} iperf3 --connect-timeout 3000 {args}")
    try:
        return json.loads(out)
    except ValueError:
        return {}


def run(scenario, hosts, reps, duration, preload=0):
    net = start_net(hosts)
    if preload:
        U.clear_all_rules()
        for i in range(preload):
            U.block(f"10.1.{i // 250}.{i % 250 + 1}")
        time.sleep(2)
    h1, h2 = net.get("h1"), net.get("h2")
    log = U.CsvLog(f"e2_overhead_{scenario}", [
        "rep", "scenario", "preload", "hosts", "loss_pct", "rtt_avg_ms", "rtt_mdev_ms",
        "tcp_mbps", "udp_jitter_ms", "udp_loss_pct"])
    h2.cmd("iperf3 -s -D")
    time.sleep(1)
    try:
        for rep in range(-C.WARMUP, reps):
            loss, rtt, mdev = ping_stats(h1.cmd(f"ping -c 100 -i 0.05 {host_ip(2)}"))
            tcp = _iperf(h1, f"-c {host_ip(2)} -t {duration} -J", duration)
            udp = _iperf(h1, f"-c {host_ip(2)} -u -b 10M -t {duration} -J", duration)
            tcp_mbps = tcp.get("end", {}).get("sum_received", {}).get("bits_per_second")
            us = udp.get("end", {}).get("sum", {})
            if rep >= 0:
                log.row(rep=rep, scenario=scenario, preload=preload, hosts=hosts, loss_pct=loss,
                        rtt_avg_ms=rtt, rtt_mdev_ms=mdev,
                        tcp_mbps=round(tcp_mbps / 1e6, 3) if tcp_mbps else "",
                        udp_jitter_ms=us.get("jitter_ms", ""),
                        udp_loss_pct=us.get("lost_percent", ""))
    finally:
        h2.cmd("pkill iperf3")
        if preload:
            U.clear_all_rules()
        log.close()
        net.stop()


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--scenario", required=True,
                    help="baseline | firewall_empty | firewall_rules (etiqueta libre)")
    ap.add_argument("--preload", type=int, default=0,
                    help="reglas DROP de relleno (10.1.x.y) antes de medir")
    ap.add_argument("--hosts", type=int, default=3)
    ap.add_argument("--reps", type=int, default=C.REPETITIONS)
    ap.add_argument("--duration", type=int, default=5)
    a = ap.parse_args()
    U.save_environment()
    run(a.scenario, a.hosts, a.reps, a.duration, a.preload)
