from pox.core import core
import pox.openflow.libopenflow_01 as of
import pox.lib.packet as pkt
from HotOM.lib.header import *

class HotOMSwitch(object):
    def __init__(self,event):
        self.connection = event.connection
        for p in event.ofp.ports:
            if p.port_no == 65534:
                self.name = p.name
                self.hw_addr = p.hw_addr
        
class FirstTest(object):

    def __init__(self):
        self.log = core.getLogger()
        core.openflow.addListeners(self)
        self.log.info("FirstTest initialization")
        self.switches = dict()
        self.connections = set()

    def debug (self,event):
        self.log.debug("dpid: %s" % event.dpid)
           #self.log.debug("Switch features: %s" % event.ofp)

    def encapsulate(self,packet,port):
        pkt_hotom = hotom(net_id="AA:BB:CC", dst="00:00:02",src="00:00:01")
        pkt_vlan = pkt.vlan(id=2,eth_type=0x080A)
        pkt_eth = packet.find('ethernet')
        pkt_ip = packet.find('ipv4')
        pkt_eth.type = pkt.ethernet.VLAN_TYPE
        pkt_eth.payload = pkt_vlan
        pkt_vlan.payload = pkt_hotom
        pkt_hotom.payload = pkt_ip
        msg = of.ofp_packet_out(data=pkt_eth)
        msg.actions.append(of.ofp_action_output(port = port))
        return msg

    def desencapsulate(self,packet,port):
        pkt_eth = packet.find('ethernet')
        pkt_vlan = packet.find('vlan')
        pkt_hotom = packet.find('hotom')
        pkt_eth.payload = pkt_hotom.payload
        pkt_eth.type = pkt.ethernet.IP_TYPE
        msg = of.ofp_packet_out(data=pkt_eth)
        msg.actions.append(of.ofp_action_output(port = port))
        return msg

    def _handle_ConnectionUp (self, event):
        self.connections.add(event.connection)
        self.switches[event.dpid] = HotOMSwitch(event)

    def _handle_PacketIn (self, event):
        self.debug(event)
        packet = event.parsed
        if packet.find('arp') is not None:
            self.log.debug("ARP packet")
            return
        if event.port == 1:
            msg = self.encapsulate(packet,2)
            event.connection.send(msg)
        if event.port == 2:
            msg = self.desencapsulate(packet,1)
            event.connection.send(msg)
                            
def launch():
    core.registerNew(FirstTest)
    
