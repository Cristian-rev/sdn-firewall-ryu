"""Firewall SDN sobre Ryu 4.34 (reimplementacion del diseno de la tesis).

Funciones:
  - Politica de IP bloqueadas -> dos reglas DROP por IP (origen y destino), prioridad 100.
  - Regla por defecto (prioridad 0): FLOOD y, si FW_MIRROR=1, copia truncada al
    controlador para que el detector pueda contar paquetes por origen.
  - API REST en :8080 con HTTP Basic (salvo /fw/health).
  - Persistencia en JSON y reinstalacion al conectar el switch.
  - Deteccion por umbrales (DoS y escaneo de puertos) con bloqueo automatico.
  - Estadisticas OpenFlow y metricas de deteccion.

Variables de entorno:
  FW_USER, FW_PASS   credenciales de la API (obligatoria FW_PASS si FW_AUTH=1)
  FW_AUTH            1 (por defecto) o 0 para la variante sin autenticacion
  FW_MIRROR          1 (por defecto) o 0 para desactivar la copia al controlador
  FW_DETECT          1 (por defecto) o 0 para desactivar el bloqueo automatico
  FW_RULES_FILE      ruta del JSON (por defecto ./firewall_rules.json)

Ejecucion:
  FW_PASS=... ryu-manager firewall_seguro.py
"""
import base64
import hmac
import ipaddress
import json
import logging
import os
import threading
import time
from collections import defaultdict, deque

from ryu.app.wsgi import ControllerBase, WSGIApplication, route
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.lib import hub
from ryu.lib.packet import ethernet, ipv4, packet, tcp, udp
from ryu.ofproto import ofproto_v1_3
from webob import Response

LOG = logging.getLogger("firewall")

FW_USER = os.environ.get("FW_USER", "admin")
FW_PASS = os.environ.get("FW_PASS", "")
FW_AUTH = os.environ.get("FW_AUTH", "1") == "1"
FW_MIRROR = os.environ.get("FW_MIRROR", "1") == "1"
FW_DETECT = os.environ.get("FW_DETECT", "1") == "1"
RULES_FILE = os.environ.get("FW_RULES_FILE", "firewall_rules.json")

DROP_PRIORITY = 100
DEFAULT_PRIORITY = 0
MIRROR_BYTES = 128

DOS_THRESHOLD = 30        # paquetes
DOS_WINDOW_SEC = 10       # segundos
PORTSCAN_THRESHOLD = 8    # puertos distintos
PORTSCAN_WINDOW = 15      # segundos

APP_NAME = "firewall_app"


class TrafficTracker:
    """Ventanas deslizantes por IP de origen."""

    def __init__(self):
        self._lock = threading.Lock()
        self._pkt_times = defaultdict(deque)
        self._port_times = defaultdict(deque)   # (t, puerto)

    def record_packet(self, src_ip, dst_port=None):
        now = time.time()
        dos = scan = False
        with self._lock:
            q = self._pkt_times[src_ip]
            q.append(now)
            while q and q[0] < now - DOS_WINDOW_SEC:
                q.popleft()
            if len(q) >= DOS_THRESHOLD:
                dos = True
            if dst_port is not None:
                pq = self._port_times[src_ip]
                pq.append((now, dst_port))
                while pq and pq[0][0] < now - PORTSCAN_WINDOW:
                    pq.popleft()
                if len({p for _, p in pq}) >= PORTSCAN_THRESHOLD:
                    scan = True
        return dos, scan

    def reset(self, src_ip):
        with self._lock:
            self._pkt_times.pop(src_ip, None)
            self._port_times.pop(src_ip, None)


class FirewallSDN(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {"wsgi": WSGIApplication}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if FW_AUTH and not FW_PASS:
            raise SystemExit("Defina FW_PASS (o FW_AUTH=0 para la variante sin autenticacion)")
        self.datapaths = {}
        self.blocked = set()
        self.lock = threading.Lock()
        self.tracker = TrafficTracker()
        self.auto_blocks = []         # [{ip, reason, t_detect, reaction_ms}]
        self.packet_ins = 0
        self._stats_waiters = {}
        self._stats_replies = {}
        self.load_rules()
        kwargs["wsgi"].register(FirewallRest, {APP_NAME: self})
        LOG.info("=" * 60)
        LOG.info("FIREWALL SDN - INICIADO | auth=%s mirror=%s detect=%s",
                 FW_AUTH, FW_MIRROR, FW_DETECT)
        LOG.info("Reglas cargadas: %s", sorted(self.blocked))
        LOG.info("UMBRALES: DoS=%dpkts/%ds, PortScan=%dpuertos/%ds",
                 DOS_THRESHOLD, DOS_WINDOW_SEC, PORTSCAN_THRESHOLD, PORTSCAN_WINDOW)
        LOG.info("=" * 60)

    # ------------------------------------------------------------ persistencia
    def load_rules(self):
        try:
            with open(RULES_FILE, encoding="utf-8") as f:
                self.blocked = set(json.load(f).get("blocked_ips", []))
        except (OSError, ValueError):
            self.blocked = set()

    def save_rules(self):
        tmp = RULES_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump({"blocked_ips": sorted(self.blocked)}, f)
        os.replace(tmp, RULES_FILE)

    # ------------------------------------------------------------ OpenFlow
    def _flow(self, dp, priority, match, actions, command=None):
        ofp, parser = dp.ofproto, dp.ofproto_parser
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)] if actions else []
        mod = parser.OFPFlowMod(
            datapath=dp, priority=priority, match=match, instructions=inst,
            command=ofp.OFPFC_ADD if command is None else command,
            out_port=ofp.OFPP_ANY, out_group=ofp.OFPG_ANY)
        dp.send_msg(mod)

    def _drop_matches(self, parser, ip):
        return (parser.OFPMatch(eth_type=0x0800, ipv4_src=ip),
                parser.OFPMatch(eth_type=0x0800, ipv4_dst=ip))

    def install_drop(self, dp, ip):
        for m in self._drop_matches(dp.ofproto_parser, ip):
            self._flow(dp, DROP_PRIORITY, m, [])

    def remove_drop(self, dp, ip):
        ofp = dp.ofproto
        for m in self._drop_matches(dp.ofproto_parser, ip):
            mod = dp.ofproto_parser.OFPFlowMod(
                datapath=dp, command=ofp.OFPFC_DELETE_STRICT, priority=DROP_PRIORITY,
                match=m, out_port=ofp.OFPP_ANY, out_group=ofp.OFPG_ANY)
            dp.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features(self, ev):
        dp = ev.msg.datapath
        ofp, parser = dp.ofproto, dp.ofproto_parser
        self.datapaths[dp.id] = dp
        # limpiar tabla y reinstalar politica completa
        dp.send_msg(parser.OFPFlowMod(datapath=dp, command=ofp.OFPFC_DELETE,
                                      out_port=ofp.OFPP_ANY, out_group=ofp.OFPG_ANY,
                                      match=parser.OFPMatch()))
        actions = [parser.OFPActionOutput(ofp.OFPP_FLOOD)]
        if FW_MIRROR:
            actions.append(parser.OFPActionOutput(ofp.OFPP_CONTROLLER, MIRROR_BYTES))
        self._flow(dp, DEFAULT_PRIORITY, parser.OFPMatch(), actions)
        with self.lock:
            ips = sorted(self.blocked)
        for ip in ips:
            self.install_drop(dp, ip)
        dp.send_msg(parser.OFPBarrierRequest(dp))
        LOG.info("Switch DPID=%s conectado - %d reglas DROP instaladas", dp.id, 2 * len(ips))

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER])
    def state_change(self, ev):
        pass

    # ------------------------------------------------------------ politica
    def block(self, ip, reason="manual"):
        with self.lock:
            if ip in self.blocked:
                return False
            self.blocked.add(ip)
            self.save_rules()
        for dp in list(self.datapaths.values()):
            self.install_drop(dp, ip)
        LOG.info("BLOQUEO %s (%s)", ip, reason)
        return True

    def unblock(self, ip):
        with self.lock:
            if ip not in self.blocked:
                return False
            self.blocked.discard(ip)
            self.save_rules()
        for dp in list(self.datapaths.values()):
            self.remove_drop(dp, ip)
        self.tracker.reset(ip)
        LOG.info("DESBLOQUEO %s", ip)
        return True

    # ------------------------------------------------------------ deteccion
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in(self, ev):
        self.packet_ins += 1
        if not FW_DETECT:
            return
        pkt = packet.Packet(ev.msg.data)
        ip4 = pkt.get_protocol(ipv4.ipv4)
        if ip4 is None:
            return
        src = ip4.src
        if src in self.blocked:
            return
        l4 = pkt.get_protocol(tcp.tcp) or pkt.get_protocol(udp.udp)
        dst_port = l4.dst_port if l4 is not None else None
        dos, scan = self.tracker.record_packet(src, dst_port)
        if dos or scan:
            t0 = time.perf_counter()
            reason = "dos" if dos else "portscan"
            if self.block(src, reason=reason):
                self.auto_blocks.append({
                    "ip": src, "reason": reason, "t_detect": time.time(),
                    "reaction_ms": round((time.perf_counter() - t0) * 1000, 3)})

    # ------------------------------------------------------------ estadisticas
    def flow_stats(self, timeout=2.0):
        out = []
        for dpid, dp in list(self.datapaths.items()):
            ev = hub.Event()
            self._stats_waiters[dpid] = ev
            self._stats_replies[dpid] = []
            dp.send_msg(dp.ofproto_parser.OFPFlowStatsRequest(dp))
            ev.wait(timeout=timeout)
            for st in self._stats_replies.pop(dpid, []):
                out.append(self._describe(st))
            self._stats_waiters.pop(dpid, None)
        return out

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply(self, ev):
        dpid = ev.msg.datapath.id
        self._stats_replies.setdefault(dpid, []).extend(ev.msg.body)
        if not (ev.msg.flags & ev.msg.datapath.ofproto.OFPMPF_REPLY_MORE):
            w = self._stats_waiters.get(dpid)
            if w:
                w.set()

    @staticmethod
    def _describe(st):
        m = dict(st.match.items())
        src, dst = m.get("ipv4_src", "ANY"), m.get("ipv4_dst", "ANY")
        actions = [a for i in st.instructions for a in getattr(i, "actions", [])]
        action = "DROP" if not actions else "ALLOW/FLOOD"
        return {"rule": f"{src} -> {dst} (Pri:{st.priority})", "action": action,
                "packets": st.packet_count, "bytes": st.byte_count,
                "duration_sec": st.duration_sec}


def _json(body, status=200):
    return Response(status=status, content_type="application/json",
                    charset="utf-8", body=json.dumps(body))


def _authorized(req):
    if not FW_AUTH:
        return True
    hdr = req.headers.get("Authorization", "")
    if not hdr.startswith("Basic "):
        return None
    try:
        user, _, pwd = base64.b64decode(hdr[6:]).decode("utf-8").partition(":")
    except Exception:  # noqa: BLE001
        return False
    return hmac.compare_digest(user, FW_USER) and hmac.compare_digest(pwd, FW_PASS)


def protected(fn):
    def wrapper(self, req, **kw):
        ok = _authorized(req)
        if ok is None:
            r = _json({"error": "Unauthorized. Please provide credentials."}, 401)
            r.headers["WWW-Authenticate"] = 'Basic realm="firewall"'
            return r
        if not ok:
            r = _json({"error": "Credenciales invalidas"}, 401)
            r.headers["WWW-Authenticate"] = 'Basic realm="firewall"'
            return r
        return fn(self, req, **kw)
    return wrapper


def _valid_ip(ip):
    try:
        return isinstance(ipaddress.ip_address(ip), ipaddress.IPv4Address)
    except ValueError:
        return False


class FirewallRest(ControllerBase):
    def __init__(self, req, link, data, **config):
        super().__init__(req, link, data, **config)
        self.app = data[APP_NAME]

    @route("fw", "/fw/health", methods=["GET"])
    def health(self, req, **kw):
        return _json({"status": "ok", "switches": len(self.app.datapaths)})

    @route("fw", "/fw/rules", methods=["GET"])
    @protected
    def rules(self, req, **kw):
        return _json({"blocked_ips": sorted(self.app.blocked)})

    @route("fw", "/fw/block/{ip}", methods=["POST"])
    @protected
    def block(self, req, ip, **kw):
        if not _valid_ip(ip):
            return _json({"error": "IP invalida", "ip": ip}, 400)
        new = self.app.block(ip)
        return _json({"status": "blocked" if new else "already_blocked", "ip": ip})

    @route("fw", "/fw/unblock/{ip}", methods=["DELETE"])
    @protected
    def unblock(self, req, ip, **kw):
        if not _valid_ip(ip):
            return _json({"error": "IP invalida", "ip": ip}, 400)
        if not self.app.unblock(ip):
            return _json({"error": "IP no bloqueada", "ip": ip}, 404)
        return _json({"status": "unblocked", "ip": ip})

    @route("fw", "/fw/stats", methods=["GET"])
    @protected
    def stats(self, req, **kw):
        flows = self.app.flow_stats()
        return _json({"message": "Estadisticas de flujos", "total_flows": len(flows),
                      "flows": flows})

    @route("fw", "/fw/metrics", methods=["GET"])
    @protected
    def metrics(self, req, **kw):
        rt = [b["reaction_ms"] for b in self.app.auto_blocks]
        return _json({
            "blocked_count": len(self.app.blocked),
            "auto_blocks": len(self.app.auto_blocks),
            "auto_block_events": self.app.auto_blocks[-50:],
            "reaction_ms_avg": round(sum(rt) / len(rt), 3) if rt else None,
            "reaction_ms_max": max(rt) if rt else None,
            "packet_ins": self.app.packet_ins,
            "config": {"auth": FW_AUTH, "mirror": FW_MIRROR, "detect": FW_DETECT},
            "thresholds": {"dos_packets": DOS_THRESHOLD, "dos_window_s": DOS_WINDOW_SEC,
                           "portscan_ports": PORTSCAN_THRESHOLD,
                           "portscan_window_s": PORTSCAN_WINDOW},
        })
