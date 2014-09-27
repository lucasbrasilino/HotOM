from pox.core import core
from pox.openflow import *
import pox.lib.packet as pkt
from HotOM.lib import *

#class HotOMSwitch(object):
#    def __init__(self,event):
        

class FirstTest(object):

    def __init__(self):
        self.log = core.getLogger()
        core.openflow.addListeners(self)
        self.log.info("FirstTest initialization")
        self.sw_ports = dict()
        self.connections = set()

    def debug (self,event):
        if isinstance(event, ConnectionUp):
            self.log.debug("dpid: %s" % event.dpid)
            #self.log.debug("Switch features: %s" % event.ofp)

    def _handle_ConnectionUp (self, event):
        self.connections.add(event.connection)
        self.sw_ports[event.dpid] = list()
        for p in event.ofp.ports:
            self.sw_ports[event.dpid].append(p.port_no)

    def _handle_PacketIn (self, event):
        packet = event.parsed
        pkt_icmp = None
        if event.dpid == 1:
            if event.port == 1:
                pkt_eth = packet.find('ethernet')
                pkt_ip = packet.find('ipv4')
                pkt_hotom = hotom(net_id="AA:BB:CC", dst="00:00:02",
                                  src="00:00:01")
                pkt_eth.payload = pkt_hotom
                pkt_hotom.payload = pkt_ip
            

def launch():
    core.registerNew(FirstTest)
    
