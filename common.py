"""Funciones auxiliares compartidas por los experimentos."""
import csv
import datetime as dt
import json
import os
import platform
import re
import subprocess
import time

import requests
from requests.auth import HTTPBasicAuth

import config as C

SESSION = requests.Session()


def auth(valid=True):
    if valid:
        return HTTPBasicAuth(C.FW_USER, C.FW_PASS)
    return HTTPBasicAuth(C.FW_USER, "credencial_invalida")


def api(method, path, valid_auth=True, use_auth=True, timeout=5):
    """Llama a la API y devuelve (status, json|None, latencia_s)."""
    url = C.API_BASE + path
    kw = {"timeout": timeout}
    if use_auth:
        kw["auth"] = auth(valid_auth)
    t0 = time.perf_counter()
    r = SESSION.request(method, url, **kw)
    lat = time.perf_counter() - t0
    try:
        body = r.json()
    except ValueError:
        body = None
    return r.status_code, body, lat


def block(ip):
    return api("POST", C.EP_BLOCK.format(ip=ip))


def unblock(ip):
    return api("DELETE", C.EP_UNBLOCK.format(ip=ip))


def blocked_ips():
    st, body, _ = api("GET", C.EP_RULES)
    if st != 200 or not body:
        return []
    return body.get("blocked_ips", [])


def clear_all_rules():
    for ip in blocked_ips():
        unblock(ip)


# ---------------- Tabla de flujos (OVS) ----------------

def dump_flows(switch=C.SWITCH):
    out = subprocess.run(
        ["ovs-ofctl", "-O", C.OF_VERSION, "dump-flows", switch],
        capture_output=True, text=True, check=False).stdout
    return out


def drop_rules_for(ip, flows_text=None):
    """Cuenta reglas DROP instaladas para ip (como origen o destino)."""
    text = flows_text if flows_text is not None else dump_flows()
    n = 0
    for line in text.splitlines():
        if ip in line and ("actions=drop" in line or re.search(r"actions=\s*$", line)):
            if f"nw_src={ip}" in line or f"nw_dst={ip}" in line:
                n += 1
    return n


def wait_flow_state(ip, present, expected=2, timeout=C.TIMEOUT):
    """Espera hasta que existan (present=True) o desaparezcan las reglas DROP.

    Devuelve el instante (time.time()) en que se cumplio la condicion, o None.
    """
    t_end = time.time() + timeout
    while time.time() < t_end:
        n = drop_rules_for(ip)
        if (present and n >= expected) or (not present and n == 0):
            return time.time()
        time.sleep(C.POLL_INTERVAL)
    return None


def flow_table_size(switch=C.SWITCH):
    return sum(1 for l in dump_flows(switch).splitlines() if "priority=" in l)


# ---------------- Proceso del controlador ----------------

def ryu_process():
    try:
        import psutil
    except ImportError:
        return None
    for p in psutil.process_iter(["name", "cmdline"]):
        cmd = " ".join(p.info.get("cmdline") or [])
        if C.RYU_PROCESS_NAME in cmd:
            return p
    return None


def ryu_usage(proc, interval=0.5):
    """CPU (%) y memoria RSS (MB) del proceso Ryu."""
    if proc is None:
        return None, None
    cpu = proc.cpu_percent(interval=interval)
    mem = proc.memory_info().rss / 1e6
    return cpu, mem


# ---------------- Registro de resultados ----------------

def results_path(name):
    os.makedirs(C.RESULTS_DIR, exist_ok=True)
    stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    return os.path.join(C.RESULTS_DIR, f"{name}_{stamp}.csv")


class CsvLog:
    def __init__(self, name, fields):
        self.path = results_path(name)
        self.f = open(self.path, "w", newline="", encoding="utf-8")
        self.w = csv.DictWriter(self.f, fieldnames=fields)
        self.w.writeheader()

    def row(self, **kw):
        self.w.writerow(kw)
        self.f.flush()

    def close(self):
        self.f.close()
        print(f"Resultados guardados en {self.path}")


def save_environment():
    """Guarda versiones de software y recursos para la tabla del manuscrito."""
    def cmd(c):
        try:
            return subprocess.run(c, shell=True, capture_output=True, text=True,
                                  timeout=10).stdout.strip() or \
                   subprocess.run(c, shell=True, capture_output=True, text=True,
                                  timeout=10).stderr.strip()
        except Exception as e:  # noqa: BLE001
            return f"error: {e}"
    info = {
        "fecha": dt.datetime.now().isoformat(),
        "os": cmd("lsb_release -ds"),
        "kernel": platform.release(),
        "python": platform.python_version(),
        "ryu": cmd(os.environ.get("RYU_BIN", "ryu-manager") + " --version"),
        "mininet": cmd("mn --version"),
        "ovs": cmd("ovs-vsctl --version | head -1"),
        "iperf3": cmd("iperf3 --version | head -1"),
        "hping3": cmd("hping3 --version 2>&1 | head -1"),
        "nmap": cmd("nmap --version | head -1"),
        "cpu": cmd("lscpu | grep 'Model name' | sed 's/Model name:\\s*//'"),
        "nucleos": cmd("nproc"),
        "ram_total": cmd("free -h | awk '/Mem:/{print $2}'"),
    }
    os.makedirs(C.RESULTS_DIR, exist_ok=True)
    path = os.path.join(C.RESULTS_DIR, "environment.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(info, f, indent=2, ensure_ascii=False)
    print(json.dumps(info, indent=2, ensure_ascii=False))
    return info
