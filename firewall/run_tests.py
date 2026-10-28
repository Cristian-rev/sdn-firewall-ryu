"""Suite funcional del firewall y del panel (12 comprobaciones).

Requiere Ryu con firewall_seguro.py y dashboard.py en ejecucion.
    FW_PASS=... python3 run_tests.py -v
"""
import os
import sys

import requests

API = os.environ.get("FW_API", "http://127.0.0.1:8080")
DASH = os.environ.get("FW_DASH", "http://127.0.0.1:5000")
AUTH = (os.environ.get("FW_USER", "admin"), os.environ.get("FW_PASS", ""))
BAD = (AUTH[0], "credencial_invalida")
TEST_IP = "10.250.250.250"
VERBOSE = "-v" in sys.argv


def g(path, auth=AUTH, method="GET"):
    return requests.request(method, API + path, auth=auth, timeout=5)


def rules():
    return g("/fw/rules").json()["blocked_ips"]


CHECKS = [
    ("Health check (/fw/health)", lambda: g("/fw/health", auth=None).status_code == 200),
    ("Auth protection (401 on invalid credentials)",
     lambda: g("/fw/rules", auth=BAD).status_code == 401
     and g("/fw/rules", auth=None).status_code == 401),
    ("Manual blocking of an IP",
     lambda: g(f"/fw/block/{TEST_IP}", method="POST").json().get("status") == "blocked"),
    ("Idempotent blocking",
     lambda: g(f"/fw/block/{TEST_IP}", method="POST").status_code == 200
     and rules().count(TEST_IP) == 1),
    ("Consistency: IP appears in /rules", lambda: TEST_IP in rules()),
    ("Manual unblocking of an IP",
     lambda: g(f"/fw/unblock/{TEST_IP}", method="DELETE").json().get("status") == "unblocked"),
    ("Consistency: IP removed from /rules", lambda: TEST_IP not in rules()),
    ("404 when unblocking a non-blocked IP",
     lambda: g(f"/fw/unblock/{TEST_IP}", method="DELETE").status_code == 404),
    ("Structure of metrics and thresholds",
     lambda: {"auto_blocks", "thresholds", "reaction_ms_avg"} <= set(g("/fw/metrics").json())),
    ("OpenFlow statistics endpoint",
     lambda: isinstance(g("/fw/stats").json().get("flows"), list)),
    ("Dashboard HTML and proxy",
     lambda: "Firewall SDN" in requests.get(DASH + "/", timeout=5).text
     and "blocked_ips" in requests.get(DASH + "/api/fw/rules", timeout=5).json()),
    ("Cleanup of test IP",
     lambda: (g(f"/fw/unblock/{TEST_IP}", method="DELETE").status_code in (200, 404)
              and TEST_IP not in rules())),
]


def main():
    passed = failed = 0
    print("=" * 64)
    print("SUITE DE PRUEBAS - FIREWALL SDN & DASHBOARD")
    print("=" * 64)
    for name, fn in CHECKS:
        try:
            ok = bool(fn())
        except Exception as e:  # noqa: BLE001
            ok = False
            if VERBOSE:
                print("   error:", e)
        passed += ok
        failed += not ok
        print(f"{name:.<55} {'PASS' if ok else 'FAIL'}")
    print("=" * 64)
    print(f"RESULTADO FINAL: {passed} PASSED | {failed} FAILED")
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
