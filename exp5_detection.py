"""E5. Deteccion y mitigacion automatica (RQ5).

Roles: h1 = victima/servidor, h2 = cliente legitimo, h_n = atacante.
Escenarios:
  benign_ping : h2 hace ping a h1 a 1 paquete/s (trafico interactivo ligero)
  benign_bulk : h2 transfiere datos a h1 con iperf3 TCP durante 5 s
  dos         : inundacion ICMP desde el atacante a --rate paquetes/s
  portscan    : escaneo TCP SYN de 200 puertos a --rate paquetes/s
En dos y portscan se mantiene el ping legitimo de fondo (1 paquete/s).

Por repeticion registra: bloqueo del atacante, tiempo de deteccion (desde el
inicio del ataque hasta que su IP aparece en /fw/rules), bloqueo del cliente
legitimo y bloqueo de la victima (ambos son falsos positivos).

    sudo -E python3 exp5_detection.py --scenario dos --rate 100 --reps 30
"""
import argparse
import time

import common as U
import config as C
from topo import host_ip, start_net


def wait_blocked(ip, timeout):
    t0 = time.time()
    while time.time() - t0 < timeout:
        if ip in U.blocked_ips():
            return time.time()
        time.sleep(0.05)
    return None


def run(scenario, rate, reps, hosts, window):
    net = start_net(hosts)
    victim, client, attacker = net.get("h1"), net.get("h2"), net.get(f"h{hosts}")
    v_ip, c_ip, a_ip = host_ip(1), host_ip(2), host_ip(hosts)
    victim.cmd("iperf3 -s -D")
    log = U.CsvLog(f"e5_detection_{scenario}", [
        "rep", "scenario", "rate_pps", "attacker_blocked", "t_detect_ms",
        "client_blocked", "victim_blocked", "blocked_list"])
    try:
        for rep in range(reps):
            U.clear_all_rules()
            time.sleep(2)
            t0 = time.time()
            if scenario == "benign_bulk":
                client.cmd(f"iperf3 -c {v_ip} -t 5 > /dev/null 2>&1 &")
            else:
                client.cmd(f"ping -i 1 {v_ip} > /dev/null 2>&1 &")
            client_pid = client.cmd("echo $!").strip()
            if scenario == "dos":
                attacker.cmd(f"hping3 -1 -i u{max(int(1e6 / rate), 1)} {v_ip} "
                             f"> /dev/null 2>&1 &")
            elif scenario == "portscan":
                attacker.cmd(f"nmap -sS -Pn -n -p 1-200 --max-rate {rate} {v_ip} "
                             f"> /dev/null 2>&1 &")
            t_block = None
            if scenario in ("dos", "portscan"):
                t_block = wait_blocked(a_ip, window)
                time.sleep(1.0)          # deja ver efectos colaterales tras el bloqueo
            else:
                time.sleep(window)
            attacker.cmd("pkill hping3; pkill nmap")
            client.cmd(f"kill {client_pid} 2>/dev/null")
            blocked = U.blocked_ips()
            log.row(rep=rep, scenario=scenario, rate_pps=rate if scenario in ("dos", "portscan") else "",
                    attacker_blocked=int(a_ip in blocked),
                    t_detect_ms=round((t_block - t0) * 1000, 1) if t_block else "",
                    client_blocked=int(c_ip in blocked), victim_blocked=int(v_ip in blocked),
                    blocked_list=";".join(blocked))
    finally:
        victim.cmd("pkill iperf3")
        U.clear_all_rules()
        log.close()
        net.stop()


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--scenario", choices=["benign_ping", "benign_bulk", "dos", "portscan"],
                    required=True)
    ap.add_argument("--rate", type=int, default=100, help="paquetes/s del ataque")
    ap.add_argument("--reps", type=int, default=C.REPETITIONS)
    ap.add_argument("--hosts", type=int, default=3)
    ap.add_argument("--window", type=float, default=15.0, help="s de observacion")
    a = ap.parse_args()
    U.save_environment()
    run(a.scenario, a.rate, a.reps, a.hosts, a.window)
