"""Panel de control Flask (puerto 5000) que actua como proxy hacia la API de Ryu.

Las credenciales viven solo en el servidor (variables FW_USER / FW_PASS);
el navegador nunca habla con el controlador.
    FW_PASS=... python3 dashboard.py
"""
import os

import requests
from flask import Flask, Response, jsonify

RYU = os.environ.get("FW_API", "http://127.0.0.1:8080")
AUTH = (os.environ.get("FW_USER", "admin"), os.environ.get("FW_PASS", ""))
app = Flask("dashboard")

PAGE = """<!doctype html><html lang="es"><head><meta charset="utf-8">
<title>Firewall SDN - Panel</title>
<style>body{font-family:sans-serif;background:#0f172a;color:#e2e8f0;margin:24px}
.card{background:#1e293b;border-radius:8px;padding:14px;margin:10px 0}
.kpis{display:flex;gap:10px}.kpis .card{flex:1}table{width:100%;border-collapse:collapse}
td,th{padding:6px;border-bottom:1px solid #334155;text-align:left}</style></head><body>
<h1>Firewall SDN - Panel de Control</h1><div id="st">...</div>
<div class="kpis"><div class="card">IPs bloqueadas<h2 id="nb">-</h2></div>
<div class="card">Bloqueos automaticos<h2 id="na">-</h2></div>
<div class="card">Reaccion promedio<h2 id="ra">-</h2></div>
<div class="card">Reaccion maxima<h2 id="rm">-</h2></div></div>
<div class="card"><h3>Gestionar reglas</h3><input id="ip" value="10.0.0.3">
<button onclick="act('POST','block')">Bloquear</button>
<button onclick="act('DELETE','unblock')">Desbloquear</button><ul id="rules"></ul></div>
<div class="card"><h3>Estadisticas OpenFlow</h3><table><thead><tr><th>Regla</th>
<th>Accion</th><th>Paquetes</th><th>Bytes</th></tr></thead><tbody id="fl"></tbody></table></div>
<script>
async function j(u,m){const r=await fetch(u,{method:m||'GET'});return r.json()}
async function act(m,a){await j('/api/fw/'+a+'/'+document.getElementById('ip').value,m);load()}
async function load(){try{
 const r=await j('/api/fw/rules'),m=await j('/api/fw/metrics'),s=await j('/api/fw/stats');
 st.textContent='RYU conectado';nb.textContent=r.blocked_ips.length;na.textContent=m.auto_blocks;
 ra.textContent=(m.reaction_ms_avg??'-')+' ms';rm.textContent=(m.reaction_ms_max??'-')+' ms';
 rules.innerHTML=r.blocked_ips.map(i=>'<li>'+i+'</li>').join('');
 fl.innerHTML=s.flows.map(f=>'<tr><td>'+f.rule+'</td><td>'+f.action+'</td><td>'+f.packets+
  '</td><td>'+f.bytes+'</td></tr>').join('')}catch(e){st.textContent='RYU desconectado'}}
load();setInterval(load,5000)</script></body></html>"""


def proxy(method, path):
    r = requests.request(method, RYU + path, auth=AUTH, timeout=5)
    return Response(r.content, status=r.status_code, content_type="application/json")


@app.route("/")
def index():
    return PAGE


@app.route("/api/fw/rules")
def rules():
    return proxy("GET", "/fw/rules")


@app.route("/api/fw/stats")
def stats():
    return proxy("GET", "/fw/stats")


@app.route("/api/fw/metrics")
def metrics():
    return proxy("GET", "/fw/metrics")


@app.route("/api/fw/block/<ip>", methods=["POST"])
def block(ip):
    return proxy("POST", f"/fw/block/{ip}")


@app.route("/api/fw/unblock/<ip>", methods=["DELETE"])
def unblock(ip):
    return proxy("DELETE", f"/fw/unblock/{ip}")


@app.route("/api/health")
def health():
    try:
        return proxy("GET", "/fw/health")
    except requests.RequestException:
        return jsonify({"status": "down"}), 503


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
