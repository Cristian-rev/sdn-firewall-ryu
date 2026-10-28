"""Creacion de la topologia Mininet con controlador remoto (Ryu)."""
import os
from functools import partial
from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.node import OVSSwitch, RemoteController
from mininet.topo import SingleSwitchTopo

import config as C


def cleanup():
    """Limpia restos de una corrida anterior SIN matar el controlador.

    `mn -c` no sirve aqui: termina ryu-manager y borra /tmp/*.log.
    """
    import subprocess
    subprocess.run(["ovs-vsctl", "--if-exists", "del-br", C.SWITCH], check=False)
    out = subprocess.run(["ip", "-o", "link", "show"], capture_output=True, text=True).stdout
    for line in out.splitlines():
        name = line.split(":")[1].strip().split("@")[0]
        if name.startswith(C.SWITCH + "-eth"):
            subprocess.run(["ip", "link", "del", name], check=False)
    subprocess.run(["pkill", "-9", "-f", "^bash --norc -is mininet:"], check=False)


def start_net(n_hosts=3):
    """Topologia single,n con MAC deterministas (equivalente a mn --topo single,n --mac)."""
    setLogLevel("warning")
    cleanup()
    topo = SingleSwitchTopo(k=n_hosts)
    # OVS_DATAPATH=user usa el datapath en espacio de usuario (sin modulo de kernel)
    sw = partial(OVSSwitch, datapath=os.environ.get("OVS_DATAPATH", "kernel"))
    net = Mininet(topo=topo, switch=sw, controller=None,
                  autoSetMacs=True, waitConnected=True)
    net.addController("c0", controller=RemoteController,
                      ip=C.CONTROLLER_IP, port=C.CONTROLLER_PORT)
    net.start()
    for sw in net.switches:
        sw.cmd(f"ovs-vsctl set bridge {sw.name} protocols={C.OF_VERSION}")
    net.waitConnected(timeout=15)
    if os.environ.get("OVS_DATAPATH") == "user":
        # con el datapath de usuario, la descarga de checksum de las veth corrompe TCP/UDP
        for h in net.hosts:
            for intf in h.intfList():
                h.cmd(f"ethtool -K {intf} tx off rx off >/dev/null 2>&1")
        for sw in net.switches:
            for intf in sw.intfList():
                if intf.name != "lo":
                    sw.cmd(f"ethtool -K {intf} tx off rx off >/dev/null 2>&1")
    return net


def host_ip(i):
    """IP del host hi (1-indexado) en la topologia por defecto de Mininet."""
    return f"10.0.0.{i}"
