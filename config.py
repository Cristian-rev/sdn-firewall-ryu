"""Configuracion comun de los experimentos.

Ajuste estos valores a su reimplementacion antes de ejecutar.
Las credenciales se leen de variables de entorno para no dejarlas en el codigo:
    export FW_USER=admin
    export FW_PASS='su_clave'
"""
import os

# --- API del firewall (Ryu) ---
API_BASE = os.environ.get("FW_API", "http://127.0.0.1:8080")
FW_USER = os.environ.get("FW_USER", "admin")
FW_PASS = os.environ.get("FW_PASS", "")          # nunca dejar la clave escrita aqui
EP_RULES = "/fw/rules"            # GET
EP_BLOCK = "/fw/block/{ip}"       # POST
EP_UNBLOCK = "/fw/unblock/{ip}"   # DELETE
EP_STATS = "/fw/stats"            # GET
EP_METRICS = "/fw/metrics"        # GET
EP_HEALTH = "/fw/health"          # GET

# --- Controlador ---
CONTROLLER_IP = "127.0.0.1"
CONTROLLER_PORT = 6653
# Comando para (re)lanzar el controlador en el experimento de persistencia
RYU_CMD = os.environ.get("RYU_CMD", "ryu-manager firewall_seguro.py")
RYU_PROCESS_NAME = "ryu-manager"

# --- Plano de datos ---
SWITCH = "s1"
OF_VERSION = "OpenFlow13"
DROP_PRIORITY = 100               # prioridad de las reglas DROP en su implementacion

# --- Diseno experimental ---
REPETITIONS = 30                  # repeticiones por condicion
WARMUP = 3                        # corridas de calentamiento descartadas
POLL_INTERVAL = 0.001             # s, sondeo de la tabla de flujos
TIMEOUT = 10.0                    # s, tiempo maximo de espera por evento

HOST_COUNTS = [3, 10, 20, 40]
RULE_COUNTS = [1, 10, 50, 100, 250, 500]

RESULTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "results")
