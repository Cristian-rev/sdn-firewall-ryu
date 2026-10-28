"""E3. Escalabilidad de la gestion de politicas (RQ3).

Para cada combinacion (numero de hosts x numero de reglas precargadas) mide:
latencia de la API, latencia hasta la regla en el switch, tamano de la tabla
de flujos y consumo de CPU/RAM del proceso Ryu.

Las reglas de relleno usan direcciones 10.1.x.y, que no pertenecen a ningun host,
para no alterar el trafico de prueba.

    sudo -E python3 exp3_scalability.py --reps 30
"""
import argparse
import time

import common as U
import config as C
from topo import host_ip, start_net


def filler_ips(n):
    return [f"10.1.{i // 250}.{i % 250 + 1}" for i in range(n)]


def run(host_counts, rule_counts, reps):
    log = U.CsvLog("e3_scalability", [
        "hosts", "rules", "rep", "t_api_block_ms", "t_flow_ms", "t_get_rules_ms",
        "flow_table_size", "ryu_cpu_ms_per_cycle", "ryu_mem_mb"])
    proc = U.ryu_process()
    for hosts in host_counts:
        net = start_net(hosts)
        target = host_ip(hosts)
        try:
            for k in rule_counts:
                U.clear_all_rules()
                for ip in filler_ips(k):
                    U.block(ip)
                time.sleep(2)
                for rep in range(-C.WARMUP, reps):
                    c0 = sum(proc.cpu_times()[:2]) if proc else None
                    t0 = time.time()
                    _, _, lat = U.block(target)
                    t_flow = U.wait_flow_state(target, present=True)
                    _, _, lat_get = U.api("GET", C.EP_RULES)
                    size = U.flow_table_size()
                    U.unblock(target)
                    U.wait_flow_state(target, present=False)
                    # CPU consumida por Ryu durante el ciclo bloqueo+consulta+desbloqueo
                    cpu = round((sum(proc.cpu_times()[:2]) - c0) * 1000, 2) if proc else ""
                    mem = round(proc.memory_info().rss / 1e6, 2) if proc else ""
                    if rep >= 0:
                        log.row(hosts=hosts, rules=k, rep=rep,
                                t_api_block_ms=round(lat * 1000, 3),
                                t_flow_ms=round((t_flow - t0) * 1000, 3) if t_flow else "",
                                t_get_rules_ms=round(lat_get * 1000, 3),
                                flow_table_size=size, ryu_cpu_ms_per_cycle=cpu, ryu_mem_mb=mem)
                    time.sleep(0.2)
        finally:
            U.clear_all_rules()
            net.stop()
    log.close()


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--hosts", type=int, nargs="+", default=C.HOST_COUNTS)
    ap.add_argument("--rules", type=int, nargs="+", default=C.RULE_COUNTS)
    ap.add_argument("--reps", type=int, default=C.REPETITIONS)
    a = ap.parse_args()
    U.save_environment()
    run(a.hosts, a.rules, a.reps)
