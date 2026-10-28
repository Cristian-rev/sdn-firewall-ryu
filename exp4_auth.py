"""E4. Seguridad y coste de la interfaz de gestion (RQ4).

1) Control de acceso: para cada endpoint protegido envia peticiones con
   credenciales validas, invalidas y sin credenciales; registra el codigo HTTP.
   Se espera 2xx/404 con credenciales validas y 401 en los otros dos casos.
2) Coste de la autenticacion: latencia de GET /fw/rules con y sin autenticacion.
   Para la comparacion "sin autenticacion" ejecute una variante del firewall con
   la autenticacion desactivada y use --mode noauth.

No requiere Mininet.
    python3 exp4_auth.py --mode auth --n 1000
"""
import argparse

import common as U
import config as C

TEST_IP = "10.9.9.9"
ENDPOINTS = [
    ("GET", C.EP_RULES), ("GET", C.EP_STATS), ("GET", C.EP_METRICS),
    ("POST", C.EP_BLOCK.format(ip=TEST_IP)),
    ("DELETE", C.EP_UNBLOCK.format(ip=TEST_IP)),
]


def access_control(n):
    log = U.CsvLog("e4_access_control", [
        "rep", "method", "endpoint", "credential", "status", "latency_ms"])
    for rep in range(n):
        for method, ep in ENDPOINTS:
            for cred in ("valid", "invalid", "none"):
                st, _, lat = U.api(method, ep, valid_auth=(cred == "valid"),
                                   use_auth=(cred != "none"))
                log.row(rep=rep, method=method, endpoint=ep, credential=cred,
                        status=st, latency_ms=round(lat * 1000, 3))
    U.unblock(TEST_IP)
    log.close()


def overhead(mode, n):
    log = U.CsvLog(f"e4_overhead_{mode}", ["rep", "mode", "status", "latency_ms"])
    for rep in range(-50, n):  # 50 peticiones de calentamiento
        st, _, lat = U.api("GET", C.EP_RULES, use_auth=(mode == "auth"))
        if rep >= 0:
            log.row(rep=rep, mode=mode, status=st, latency_ms=round(lat * 1000, 3))
    log.close()


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["auth", "noauth"], default="auth")
    ap.add_argument("--n", type=int, default=1000)
    ap.add_argument("--access-reps", type=int, default=C.REPETITIONS)
    a = ap.parse_args()
    if a.mode == "auth":
        access_control(a.access_reps)
    overhead(a.mode, a.n)
