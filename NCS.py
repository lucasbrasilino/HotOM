from pox.core import core
import pox.openflow.libopenflow_01 as of
import pox.lib.packet as pkt
from pox.lib.addresses import *
from pox.lib.recoco import Timer
from HotOM.lib.HotOMTenant import *

class NCS(object):
    def __init__(self):
        self.net = dict()
        self.log = core.getLogger()
        core.openflow.miss_send_len = 1400
        core.openflow.addListeners(self)
        self.log.info("NCS initialization")
        self.timer = dict()
        self.timer[0] = Timer(10, self.gratuitousARP, args=[None],recurring=True)
        self.timer[1] = Timer(5, self.dump,recurring=True)
        self.net[0xaabbcc] = HotOMNet(0xaabbcc)

    def dump(self):
        self.log.debug(self.net[0xaabbcc])

    def gratuitousARP(self,vs):
        if vs is None:
            vswitches = self.net[0xaabbcc].vswitch
        else:
            vswitches = dict(only=vs)
        for k in vswitches.keys():
            v = vswitches[k]
            pkt_eth = pkt.ethernet(dst=pkt.ETHER_BROADCAST,src=v.hw_addr)
            pkt_eth.type = pkt.ethernet.VLAN_TYPE
            pkt_vlan = pkt.vlan(id=v.vstag)
            pkt_vlan.eth_type = pkt.ethernet.ARP_TYPE
            grat = pkt.arp()
            grat.opcode = pkt.arp.REQUEST
            grat.hwsrc = pkt_eth.src
            grat.hwdst = pkt_eth.dst
            grat.payload = b'\x0f' * 8
            pkt_eth.payload=pkt_vlan
            pkt_vlan.payload=grat
            dpid = self.net[0xaabbcc].getDPID(v)
            msg = of.ofp_packet_out(data=pkt_eth)
            msg.actions.append(of.ofp_action_output(port = v.uplink))
            try:
                conn = core.openflow.getConnection(dpid)
                self.log.debug("Sending gratuitousARP for %s" % v)
                conn.send(msg)
            except:
                raise RuntimeError("can't send msg to vSwitch %s" % v)

    def _handle_ConnectionUp(self,event):
        vm = HotOMVM()
        vm.hw_addr = "00:00:00:00:00:0%d" % event.dpid
        vm.ip_addr = "10.0.0.%d" % event.dpid
        if event.dpid == 1:
            vstag = 4051
        else:
            vstag = 4052
        vs = HotOMvSwitch(vstag)
        vs.uplink = 2
        vs.addVM(vm,1)
        self.net[0xaabbcc].addvSwitch(event.dpid,vs)
        self.gratuitousARP(vs)

    def _handle_ConnectionDown(self,event):
        self.net[0xaabbcc].removevSwitch(event.dpid)

    def inbound(self,dpid,packet):
        vs = self.net[0xaabbcc].vswitch[dpid]
        vstag = vs.vstag
        pkt_eth = packet.find('ethernet')
        pkt_vlan = packet.find('vlan')
        pkt_hotom = packet.find('hotom')
        if pkt_hotom is None:
            return
        pkt_eth.src = EthAddr(self.net[0xaabbcc].toRaw() + pkt_hotom.src.toRaw()[3:])
        pkt_eth.dst = EthAddr(self.net[0xaabbcc].toRaw() + pkt_hotom.dst.toRaw()[3:])
        port = vs.getPort(pkt_hotom.dst)
        msg = of.ofp_packet_out(data=pkt_eth)
        msg.actions.append(of.ofp_action_output(port = port))
        try:
            conn = core.openflow.getConnection(dpid)
            conn.send(msg)
        except:
            raise RuntimeError("can't send msg to vSwitch %s" % v)
    
    def outbound(self,dpid,packet):
        vs = self.net[0xaabbcc].vswitch[dpid]
        vstag = vs.vstag
        pkt_eth = packet.find('ethernet')
        
        

    def is_inboundmatch(self,dpid,packet):
        vs = self.net[0xaabbcc].vswitch[dpid]
        vstag = vs.vstag
        pkt_eth = packet.find('ethernet')
        pkt_vlan = packet.find('vlan')
        if pkt_vlan is None:
            return False
        if (pkt_eth.dst == vs.hw_addr) and (pkt_vlan.id == vstag):
            return True
        else:
            return False

    def _handle_PacketIn(self,event):
        packet = event.parsed
        port = event.port
        dpid = event.dpid
        vs = self.net[0xaabbcc].vswitch[dpid]
        if not (bool(packet.find('ipv4')) or bool(packet.find('vlan'))):
            self.log.debug("PacketIn: Neither IPv4 or VLAN => %s" % packet)
            return
        if port == vs.uplink:
            if self.is_inboundmatch(dpid,packet):
                self.inbound(dpid,packet)
        else:
            self.outbound(dpid,packet)

def launch():
    core.registerNew(NCS)


