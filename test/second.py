from pox.core import core
import pox.openflow.libopenflow_01 as of
import pox.lib.packet as pkt
from pox.lib.addresses import EthAddr

class HotOMSwitch(object):
    def __init__(self,event):
        self.connection = event.connection
        for p in event.ofp.ports:
            if p.port_no == 65534:
                self.name = p.name
                self.hw_addr = p.hw_addr
        
class SecondTest(object):

    def __init__(self,net_id=0x0):
        self.log = core.getLogger()
        core.openflow.miss_send_len = 1400
        core.openflow.addListeners(self)
        self.log.info("SecondTest initialization")
        self.switches = dict()
        self.connections = set()
        self.net_id = net_id

    def push_header(self,packet,sw_src,sw_dst,port):
        pkt_hotom = pkt.hotom()
        pkt_vlan = pkt.vlan(id=2,eth_type=pkt.ethernet.HOTOM_TYPE)
        pkt_eth = packet.find('ethernet')
        pkt_ip = packet.find('ipv4')
        if pkt_ip is None:
            self.log.debug("Packet not IPV4: %s" % packet)
            return
        pkt_hotom.net_id=self.net_id
        pkt_hotom.src=pkt_eth.src
        pkt_hotom.dst=pkt_eth.dst
        pkt_hotom.payload = pkt_ip
        pkt_vlan.payload = pkt_hotom
        pkt_eth.payload = pkt_vlan
        pkt_eth.type = pkt.ethernet.VLAN_TYPE
        pkt_eth.src = EthAddr(sw_src.hw_addr)
        pkt_eth.dst = EthAddr(sw_dst.hw_addr)
        msg = of.ofp_packet_out(data=pkt_eth)
        msg.actions.append(of.ofp_action_output(port = port))
        return msg

    def pop_header(self,packet,sw_src,sw_dst,port):
        pkt_eth = packet.find('ethernet')
        pkt_vlan = packet.find('vlan')
        pkt_hotom = packet.find('hotom')
        pkt_eth.src = pkt_hotom.src
        pkt_eth.dst = pkt_hotom.dst
        pkt_eth.payload = pkt_hotom.payload
        pkt_eth.type = pkt.ethernet.IP_TYPE
        msg = of.ofp_packet_out(data=pkt_eth)
        msg.actions.append(of.ofp_action_output(port = port))
        return msg

    def getswitches(self, event):
        dpid = event.dpid
        sw_src = self.switches[dpid]
        sw_dst = self.switches[(dpid%2)+1] # gets the other switch
        return (sw_src,sw_dst)

    def _handle_ConnectionUp (self, event):
        self.connections.add(event.connection)
        self.switches[event.dpid] = HotOMSwitch(event)

    def _handle_PacketIn (self, event):
        packet = event.parsed
        if not (bool(packet.find('ipv4')) or bool(packet.find('vlan'))):
            self.log.debug("PacketIn: Neither IPv4 or VLAN => %s" % packet)
            return
        sw_src,sw_dst = self.getswitches(event)
        self.log.debug("Src Sw: %s | Dst Sw: %s" % 
                       (sw_src.hw_addr,sw_dst.hw_addr))
        if event.port == 1:
            msg = self.push_header(packet,sw_src,sw_dst,2)
            if msg is not None:
                event.connection.send(msg)
        if event.port == 2:
            msg = self.pop_header(packet,sw_src,sw_dst,1)
            if msg is not None:
                event.connection.send(msg)
                            
def launch():
    core.registerNew(SecondTest)
    
