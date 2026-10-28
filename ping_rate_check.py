import subprocess
from functools import partial
from mininet.net import Mininet
from mininet.node import OVSSwitch
from mininet.topo import SingleSwitchTopo
from mininet.log import setLogLevel
setLogLevel('warning')
net = Mininet(topo=SingleSwitchTopo(3), switch=partial(OVSSwitch, datapath='user', failMode='secure'),
              controller=None, autoSetMacs=True)
net.start()
for h in net.hosts:
    h.cmd(f"ethtool -K {h.intf()} tx off rx off >/dev/null 2>&1")
for i in net.switches[0].intfList():
    if i.name != 'lo':
        net.switches[0].cmd(f"ethtool -K {i} tx off rx off >/dev/null 2>&1")


def of(*a):
    subprocess.run(["ovs-ofctl", "-O", "OpenFlow13", *a], capture_output=True)


subprocess.run(["ovs-vsctl", "set", "bridge", "s1", "protocols=OpenFlow13"])
of("add-flow", "s1", "priority=0,actions=flood")
h1 = net.get('h1')
print(h1.cmd("ping -c2 10.0.0.3").splitlines()[-2])


def run(label):
    out = h1.cmd("ping -D -i 0.002 -w 2 10.0.0.3")
    print(label, [l for l in out.splitlines() if 'transmitted' in l])


run("libre    ")
for f in ("nw_src=10.0.0.3", "nw_dst=10.0.0.3"):
    of("add-flow", "s1", f"priority=100,ip,{f},actions=drop")
run("bloqueado")
net.stop()
