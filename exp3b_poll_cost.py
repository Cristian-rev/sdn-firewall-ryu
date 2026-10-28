"""E3b. Costo del propio sondeo de la tabla de flujos.

t_flow se mide consultando `ovs-ofctl dump-flows` en bucle. Con tablas grandes
cada consulta tarda mas, de modo que parte del aumento de t_flow puede deberse
al instrumento y no al controlador. Este script mide cuanto tarda una consulta
segun el numero de reglas instaladas, para poder separar ambos efectos.

    sudo -E python3 exp3b_poll_cost.py --reps 100
"""
import argparse
import subprocess
import time

import common as U
import config as C
from topo import start_net


def run(rule_counts, reps):
    net = start_net(3)
    log = U.CsvLog("e3b_poll_cost", ["rules", "flow_table_size", "rep", "dump_ms"])
    try:
        for k in rule_counts:
            U.clear_all_rules()
            for i in range(k):
                U.block(f"10.1.{i // 250}.{i % 250 + 1}")
            time.sleep(2)
            size = U.flow_table_size()
            for rep in range(reps):
                t0 = time.perf_counter()
                out = subprocess.run(["ovs-ofctl", "-O", C.OF_VERSION, "dump-flows", C.SWITCH],
                                     capture_output=True, text=True, check=False).stdout
                U.drop_rules_for("10.0.0.3", out)  # mismo analisis de texto que el sondeo
                log.row(rules=k, flow_table_size=size, rep=rep,
                        dump_ms=round((time.perf_counter() - t0) * 1000, 3))
    finally:
        U.clear_all_rules()
        log.close()
        net.stop()


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--rules", type=int, nargs="+", default=C.RULE_COUNTS)
    ap.add_argument("--reps", type=int, default=100)
    a = ap.parse_args()
    run(a.rules, a.reps)
