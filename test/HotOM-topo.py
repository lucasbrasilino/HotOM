#!/usr/bin/python

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.util import dumpNodeConnections
from mininet.log import setLogLevel
from mininet.cli import CLI
from mininet.node import RemoteController,OVSSwitch

class HotOMTopo(Topo):
	def __init__(self,**opts):
		Topo.__init__(self, **opts)
		s1 = self.addSwitch('s1')
		s2 = self.addSwitch('s2')
		h1 = self.addHost('h1',mac="aa:bb:cc:00:00:01",ip="10.0.0.1")
		h2 = self.addHost('h2',mac="aa:bb:cc:00:00:02",ip="10.0.0.2")
		h3 = self.addHost('h3',mac="cc:bb:aa:00:00:01",ip="10.0.0.1")
		h4 = self.addHost('h4',mac="cc:bb:aa:00:00:02",ip="10.0.0.2")
		h5 = self.addHost('h5',mac="aa:bb:cc:00:00:05",ip="10.0.0.5")
		self.addLink(s1,s2)
		self.addLink(h1,s1)
		self.addLink(h5,s1)
		self.addLink(h2,s2)
		self.addLink(h3,s1)
		self.addLink(h4,s2)

def simpletopo():
	topo = HotOMTopo()
	net = Mininet(topo, switch=OVSSwitch, controller=None)
	net.addController( 'c0', controller=RemoteController, ip='192.168.56.1', port=6633 )
	net.start()
	CLI(net)
	net.stop()

if __name__ == "__main__":
	setLogLevel('info')
	simpletopo()	
