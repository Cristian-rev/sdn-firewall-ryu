# Firewall SDN sobre Ryu: reimplementación y scripts de medición

Este paquete contiene la reimplementación del firewall (carpeta `firewall/`) y los scripts que generan los datos del artículo para JNSM. Cada experimento responde a una pregunta de investigación (RQ) del protocolo y escribe un CSV con fecha en `results/`.

## Contenido

| Archivo | Función |
|---|---|
| `firewall/firewall_seguro.py` | Aplicación Ryu 4.34: política de IP bloqueadas, API REST con HTTP Basic, persistencia JSON, detección por umbrales, estadísticas |
| `firewall/dashboard.py` | Panel Flask (puerto 5000) que hace de proxy hacia la API |
| `firewall/run_tests.py` | Suite funcional de 12 comprobaciones |
| `exp1` … `exp6` | Experimentos E1 a E6 (ver tabla) |
| `analyze.py` | Tablas resumen, pruebas estadísticas y figuras |
| `run_campaign.sh` | Campaña completa, no interactiva y reanudable |

## Configuración del firewall (variables de entorno)

| Variable | Valor por defecto | Efecto |
|---|---|---|
| `FW_USER` / `FW_PASS` | `admin` / — | Credenciales de la API. `FW_PASS` es obligatoria |
| `FW_AUTH` | 1 | 0 = variante sin autenticación (solo para E4) |
| `FW_MIRROR` | 1 | La regla por defecto envía además una copia de 128 bytes al controlador |
| `FW_DETECT` | 1 | Bloqueo automático por umbrales (DoS 30 paquetes/10 s; escaneo 8 puertos/15 s) |
| `FW_RULES_FILE` | `firewall_rules.json` | Archivo de persistencia |

Los experimentos de gestión (E1, E3, E4 y E6) usan `FW_MIRROR=0 FW_DETECT=0`. Si se dejan activos, la sonda de E1 (500 paquetes/s) supera el umbral de DoS y el propio host de medición termina bloqueado. E5 usa todo activado.

## Requisitos

```bash
sudo apt install mininet openvswitch-switch iperf3 hping3 nmap ethtool
pip3 install requests psutil pandas scipy matplotlib flask
# Ryu 4.34 requiere Python 3.9 y eventlet 0.30.2:
python3.9 -m venv /opt/ryuenv
PBR_VERSION=4.34 /opt/ryuenv/bin/pip install "setuptools<58" wheel
PBR_VERSION=4.34 /opt/ryuenv/bin/pip install --no-build-isolation ryu==4.34 eventlet==0.30.2
```

## Ejecución

```bash
sudo FW_PASS='su_clave' RYU_BIN=/opt/ryuenv/bin/ryu-manager REPS=30 bash run_campaign.sh
```

- Use `OVS_DATAPATH=user` si el kernel no tiene el módulo `openvswitch` (contenedores). En ese modo, `topo.py` desactiva la descarga de checksum de las interfaces. Sin ese ajuste, TCP y UDP fallan.
- La campaña es reanudable: cada paso terminado deja una marca en `logs/done/`. Si se interrumpe, al relanzarla omite lo hecho y borra los CSV parciales del paso interrumpido.
- **No use `mn -c` con Ryu en marcha.** Ese comando termina `ryu-manager` y borra `/tmp/*.log`. `topo.cleanup()` limpia los restos de Mininet sin tocar el controlador.

| Exp. | RQ | Qué mide |
|---|---|---|
| E1 | RQ1 | Latencia orden REST → regla en el switch → efecto en el tráfico (sonda ICMP cada 2 ms) |
| E2 | RQ2 | RTT, pérdida y throughput: `simple_switch_13`, firewall vacío, firewall con 100 reglas, firewall con copia al controlador |
| E3 | RQ3 | Escalabilidad según el número de hosts (3–40) y de reglas (1–500), y CPU de Ryu por ciclo |
| E4 | RQ4 | Códigos HTTP por tipo de credencial y latencia con y sin autenticación |
| E5 | RQ5 | Detección: tráfico benigno ligero y masivo, DoS ICMP y escaneo SYN a 10, 100 y 500 paquetes/s |
| E6 | RQ6 | Restauración de la política tras reiniciar Ryu con la tabla del switch vaciada |

Al terminar, `results/analysis/` contiene `summary_*.csv`, `tests.txt` y las figuras a 300 dpi. `results/environment.json` guarda las versiones y los recursos del equipo.
