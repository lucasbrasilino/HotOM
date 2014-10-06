from pox.core import core
import pox.openflow.libopenflow_01 as of
import pox.lib.packet as pkt
from pox.lib.addresses import EthAddr
        
class FirstTest(object):
    def __init__(self):
        self.log = core.getLogger()
        core.openflow.miss_send_len = 1400
        core.openflow.addListeners(self)
        self.log.info("FirstTest initialization")
        self.connections = set()

    def push_header(self,packet,port):
        pkt_eth = packet.find('ethernet')
        pkt_hotom = pkt.hotom()
        pkt_hotom.net_id = 0x0
        pkt_hotom.dst = pkt_eth.dst
        pkt_hotom.dst = pkt_eth.src
        pkt_vlan = pkt.vlan(id=2,eth_type=pkt.ethernet.HOTOM_TYPE)
        pkt_ip = packet.find('ipv4')
        if pkt_ip is None:
            self.log.debug("Packet not IPV4: %s" % packet)
            return
        pkt_hotom.payload = pkt_ip
        pkt_vlan.payload = pkt_hotom
        pkt_eth.payload = pkt_vlan
        pkt_eth.type = pkt.ethernet.VLAN_TYPE
        msg = of.ofp_packet_out(data=pkt_eth)
        msg.actions.append(of.ofp_action_output(port = port))
        return msg

    def pop_header(self,packet,port):
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

    def _handle_PacketIn (self, event):
        self.log.debug("dpid: %d" % event.dpid)
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
    
