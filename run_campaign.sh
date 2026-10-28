#!/usr/bin/env bash
# Campana experimental no interactiva: lanza y detiene Ryu con la configuracion
# que necesita cada fase. Ejecutar como root:
#   FW_PASS=... RYU_BIN=/ruta/ryu-manager OVS_DATAPATH=user REPS=30 bash run_campaign.sh
# OVS_DATAPATH=user solo si no hay modulo openvswitch en el kernel.
set -uo pipefail
cd "$(dirname "$0")"
: "${FW_PASS:?Defina FW_PASS}"
export FW_PASS FW_USER="${FW_USER:-admin}" OVS_DATAPATH="${OVS_DATAPATH:-kernel}"
RYU_BIN="${RYU_BIN:-ryu-manager}"
REPS="${REPS:-30}"
LOG="${LOG_DIR:-./logs}"; mkdir -p "$LOG"
FW_DIR="$(pwd)/firewall"
export FW_RULES_FILE="$FW_DIR/firewall_rules.json"
RYU_PID=""; DASH_PID=""
export RYU_BIN

# Open vSwitch debe estar corriendo (en contenedores no arranca solo)
if ! ovs-vsctl show >/dev/null 2>&1; then
  /usr/share/openvswitch/scripts/ovs-ctl start --system-id=random >/dev/null 2>&1 || service openvswitch-switch start
fi

# Reanudable: cada paso deja una marca en $LOG/done/ y se omite si ya existe
mkdir -p "$LOG/done"
run() {  # run <id> <comando...>
  local id="$1"; shift
  [[ -f "$LOG/done/$id" ]] && { echo "omitido $id"; return 0; }
  # borrar CSV parciales de un paso interrumpido (mas nuevos que la ultima marca)
  local last; last=$(ls -t "$LOG/done/"* 2>/dev/null | head -1)
  if [[ -n "$last" ]]; then find results -name '*.csv' -newer "$last" -delete; fi
  step "$id"
  if "$@"; then touch "$LOG/done/$id"; else step "FALLO $id"; fi
}

start_ryu() {   # $1 = app, resto = VAR=valor
  local app="$1"; shift
  stop_ryu
  rm -f "$FW_RULES_FILE"
  ( cd "$FW_DIR" && env "$@" setsid "$RYU_BIN" "$app" >"$LOG/ryu_$(date +%H%M%S).log" 2>&1 < /dev/null ) &
  RYU_PID=$!
  for _ in $(seq 1 50); do
    curl -s -m 1 localhost:8080/fw/health >/dev/null 2>&1 && return 0
    [[ "$app" == *simple_switch_13* ]] && { sleep 2; return 0; }
    sleep 0.2
  done
  echo "Ryu no respondio" >&2; return 1
}
stop_ryu() {
  pkill -f "^$RYU_BIN" 2>/dev/null || pkill -f "ryu-manager" 2>/dev/null || true
  sleep 1
}
step() { echo "[$(date +%H:%M:%S)] $*" | tee -a "$LOG/campaign.log"; }

SS13="$(dirname "$RYU_BIN")/../lib/python3.9/site-packages/ryu/app/simple_switch_13.py"
[[ -f "$SS13" ]] || SS13="ryu.app.simple_switch_13"

# ---- Fase A: gestion de politicas (sin copia al controlador ni deteccion)
step "Fase A: E1, E3, E3b, E4(auth) y suite funcional"
start_ryu firewall_seguro.py FW_MIRROR=0 FW_DETECT=0
( cd "$FW_DIR" && setsid python3 dashboard.py >"$LOG/dashboard.log" 2>&1 < /dev/null ) & DASH_PID=$!
sleep 2
run tests bash -c "cd '$FW_DIR' && python3 run_tests.py -v | tee '$LOG/run_tests.txt'"
kill "$DASH_PID" 2>/dev/null
for h in 3 10 20 40; do run "e1_h$h" bash -c "python3 exp1_enforcement_latency.py --hosts $h --reps $REPS >>'$LOG/e1.log' 2>&1"; done
for h in 3 10 20 40; do run "e3_h$h" bash -c "python3 exp3_scalability.py --hosts $h --reps $REPS >>'$LOG/e3.log' 2>&1"; done
run e3b bash -c "python3 exp3b_poll_cost.py --reps 100 >>'$LOG/e3.log' 2>&1"
run e4_auth bash -c "python3 exp4_auth.py --mode auth --access-reps $REPS >>'$LOG/e4.log' 2>&1"

# ---- Fase B: variante sin autenticacion
step "Fase B: E4(noauth)"
start_ryu firewall_seguro.py FW_AUTH=0 FW_MIRROR=0 FW_DETECT=0
run e4_noauth bash -c "python3 exp4_auth.py --mode noauth >>'$LOG/e4.log' 2>&1"

# ---- Fase C: sobrecarga en el plano de datos
step "Fase C: E2"
start_ryu "$SS13"
run e2_baseline bash -c "python3 exp2_dataplane_overhead.py --scenario baseline --reps $REPS >>'$LOG/e2.log' 2>&1"
start_ryu firewall_seguro.py FW_MIRROR=0 FW_DETECT=0
run e2_empty bash -c "python3 exp2_dataplane_overhead.py --scenario firewall_empty --reps $REPS >>'$LOG/e2.log' 2>&1"
run e2_rules bash -c "python3 exp2_dataplane_overhead.py --scenario firewall_rules --preload 100 --reps $REPS >>'$LOG/e2.log' 2>&1"
start_ryu firewall_seguro.py FW_MIRROR=1 FW_DETECT=0
run e2_mirror bash -c "python3 exp2_dataplane_overhead.py --scenario firewall_mirror --reps $REPS >>'$LOG/e2.log' 2>&1"

# ---- Fase D: deteccion y mitigacion (todo activado)
step "Fase D: E5"
start_ryu firewall_seguro.py FW_MIRROR=1 FW_DETECT=1
for s in benign_ping benign_bulk; do run "e5_$s" bash -c "python3 exp5_detection.py --scenario $s --reps $REPS >>'$LOG/e5.log' 2>&1"; done
for r in 10 100 500; do
  run "e5_dos_$r" bash -c "python3 exp5_detection.py --scenario dos --rate $r --reps $REPS >>'$LOG/e5.log' 2>&1"
  run "e5_scan_$r" bash -c "python3 exp5_detection.py --scenario portscan --rate $r --reps $REPS >>'$LOG/e5.log' 2>&1"
done

# ---- Fase E: persistencia (el script lanza Ryu por su cuenta)
step "Fase E: E6"
stop_ryu
export RYU_CMD="env FW_MIRROR=0 FW_DETECT=0 $RYU_BIN $FW_DIR/firewall_seguro.py"
for k in 1 10 100; do run "e6_k$k" bash -c "python3 exp6_persistence.py --rules $k --reps $REPS >>'$LOG/e6.log' 2>&1"; done

step "Analisis"
python3 analyze.py >>"$LOG/analyze.log" 2>&1
step "Campana terminada"
