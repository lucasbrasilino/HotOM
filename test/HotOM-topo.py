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

		
def runCmd(net):
	h1 = net.get('h1')
	h2 = net.get('h2')
	h5 = net.get('h5')
	print h1.cmd('arping -0 -c1 -I h1-eth0 10.0.0.1')
	print h2.cmd('arping -0 -c1 -I h2-eth0 10.0.0.2')
	print h5.cmd('arping -0 -c1 -I h5-eth0 10.0.0.5')
	print h1.cmd('ping -c2 10.0.0.5')
	print h1.cmd('arp -n')
	print h1.cmd('ping -c1 10.0.0.2')

def topo():
	topo = HotOMTopo()
	net = Mininet(topo, switch=OVSSwitch, controller=None)
	net.addController( 'c0', controller=RemoteController, ip='192.168.56.1', port=6633 )
	net.start()
	runCmd(net)
	CLI(net)
	net.stop()

if __name__ == "__main__":
	setLogLevel('info')
	topo()	
