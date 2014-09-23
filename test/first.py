from pox.core import core
from pox.openflow import *
import pox.lib.packet as pkt

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
        if packet.type == pkt.ARP_TYPE:
            

def launch():
    core.registerNew(FirstTest)
    
