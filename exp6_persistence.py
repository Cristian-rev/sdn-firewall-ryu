"""E6. Persistencia y consistencia de politicas (RQ6).

1) Bloquea k IP, detiene el controlador, comprueba si el switch conserva las
   reglas, vacia la tabla de flujos, relanza el controlador y mide cuanto tarda
   en reinstalar todas las reglas (y si lo logra).
2) Consistencia: compara /fw/rules con las reglas DROP reales en la tabla de flujos.

El script lanza y detiene Ryu por su cuenta usando config.RYU_CMD, asi que
NO debe haber otra instancia de Ryu corriendo.

    sudo -E RYU_CMD="ryu-manager firewall_seguro.py" python3 exp6_persistence.py --rules 10 --reps 30
"""
import argparse
import shlex
import subprocess
import time

import common as U
import config as C
from topo import start_net


def start_ryu():
    p = subprocess.Popen(shlex.split(C.RYU_CMD), stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL)
    for _ in range(100):
        try:
            if U.api("GET", C.EP_RULES)[0] == 200:
                return p
        except Exception:  # noqa: BLE001
            pass
        time.sleep(0.1)
    return p


def consistency(ips):
    flows = U.dump_flows()
    missing = [ip for ip in ips if U.drop_rules_for(ip, flows) < 2]
    return len(missing)


def run(k, reps):
    ryu = start_ryu()
    net = start_net(3)
    ips = [f"10.2.0.{i + 1}" for i in range(k)]
    log = U.CsvLog("e6_persistence", [
        "rep", "rules", "kept_while_down", "restored_all", "t_restore_ms",
        "missing_after_restore", "api_rules_count"])
    try:
        U.clear_all_rules()
        for ip in ips:
            U.block(ip)
        time.sleep(2)
        for rep in range(reps):
            ryu.terminate()
            ryu.wait(timeout=10)
            # con el controlador caido el switch (fail_mode=secure) conserva sus flujos;
            # se vacia la tabla para simular la perdida de estado del switch
            kept = len(ips) - consistency(ips)
            subprocess.run(["ovs-ofctl", "-O", C.OF_VERSION, "del-flows", C.SWITCH], check=False)
            t0 = time.time()
            ryu = start_ryu()
            t_ok = None
            while time.time() - t0 < 30:
                if consistency(ips) == 0:
                    t_ok = time.time()
                    break
                time.sleep(0.05)
            log.row(rep=rep, rules=k, kept_while_down=kept, restored_all=int(t_ok is not None),
                    t_restore_ms=round((t_ok - t0) * 1000, 1) if t_ok else "",
                    missing_after_restore=consistency(ips),
                    api_rules_count=len(U.blocked_ips()))
    finally:
        U.clear_all_rules()
        log.close()
        net.stop()
        ryu.terminate()


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--rules", type=int, default=10)
    ap.add_argument("--reps", type=int, default=C.REPETITIONS)
    a = ap.parse_args()
    U.save_environment()
    run(a.rules, a.reps)
