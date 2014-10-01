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
        core.openflow.miss_send_len = 1400
        core.openflow.addListeners(self)
        self.log.info("FirstTest initialization")
        self.switches = dict()
        self.connections = set()

    def debug (self,event):
        self.log.debug("dpid: %s" % event.dpid)

    def push_header(self,packet,port):
        pkt_hotom = hotom(net_id="AA:BB:CC", dst="00:00:02",src="00:00:01")
        pkt_vlan = pkt.vlan(id=2,eth_type=pkt.ethernet.IP_TYPE)
        pkt_eth = packet.find('ethernet')
        pkt_ip = packet.find('ipv4')
        if pkt_ip is None:
            self.log.debug("Packet not IPV4: %s" % packet)
            return
        pkt_vlan.payload = pkt_ip
        pkt_eth.payload = pkt_vlan
        pkt_eth.type = pkt.ethernet.VLAN_TYPE
        msg = of.ofp_packet_out(data=pkt_eth)
        msg.actions.append(of.ofp_action_output(port = port))
        return msg

    def pop_header(self,packet,port):
        pkt_eth = packet.find('ethernet')
        pkt_vlan = packet.find('vlan')
        pkt_eth.payload = pkt_vlan.payload
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
            msg = self.push_header(packet,2)
            if msg is not None:
                event.connection.send(msg)
        if event.port == 2:
            msg = self.pop_header(packet,1)
            if msg is not None:
                event.connection.send(msg)
                            
def launch():
    core.registerNew(FirstTest)
    
