from pox.core import core
import pox.openflow.libopenflow_01 as of
import pox.lib.packet as pkt
from pox.lib.addresses import *
from pox.lib.recoco import Timer
from pox.lib.util import dpid_to_str
from HotOM.lib.HotOMTenant import *
from HotOM.lib.tools import *
from HotOM.lib.db import *
import sys

FLOW_TIMEOUT = 600

def getUplink(event,uplink_iface):
    ports_list = event.connection.features.ports
    [ port ] = [ p for p in ports_list if p.name == uplink_iface ]
    return int(port.port_no)

def createGratuitousARP(vstag,hw_addr):
    eth = pkt.ethernet(dst=pkt.ETHER_BROADCAST,src=hw_addr)
    eth.type = pkt.ethernet.VLAN_TYPE
    vlan = pkt.vlan(id=vstag)
    vlan.eth_type = pkt.ethernet.ARP_TYPE
    grat = pkt.arp()
    grat.opcode = pkt.arp.REQUEST
    grat.hwsrc = eth.src
    grat.hwdst = eth.dst
    grat.payload = b'\x0f' * 8
    eth.payload=vlan
    vlan.payload=grat
    return eth

def createARPReply(net_id,vstag,hotom_addr,eth):
    hw_addr_src = fromHotOMtoEthAddr(hotom_addr)
    eth_reply = pkt.ethernet(dst=eth.src,src=hw_addr_src)
    eth_reply.type = pkt.ethernet.ARP_TYPE
    arp_reply = pkt.arp(opcode=pkt.arp.REPLY)
    arp_reply.hwsrc = hw_addr_src
    arp_reply.hwdst = eth.src
    arp_reply.protosrc = eth.payload.protodst
    arp_reply.protodst = eth.payload.protosrc
    eth_reply.payload = arp_reply
    return eth_reply

class LAS(object):
    def __init__(self,vstag,uplink,dbcache):
        self.log = core.getLogger()
        self.log.info("LAS initialization. vstag=%s" % vstag)
        self.vstag = int(vstag)
        self.log.debug("Opening dbcache %s" % dbcache)
        self.dbcache = dbCache(dbcache)
        self.uplink_iface = uplink
        self.uplink = None
        self.conn = None
        core.openflow.miss_send_len = 1450
        core.openflow.addListeners(self)
#        Timer(10, self.dump,recurring=True)
        # CAM Table (net_id,ip_addr) => cam_entry (vstag,hw_addr)
        self.cam = dict()
   

    def _handle_ConnectionUp(self,event):
        self.hw_addr = getEthAddrFromVstag(self.vstag)
        self.log.info("Now controlling vswitch %s", self.hw_addr)
        self.dpid = event.dpid
        self.conn = event.connection
        self.uplink = getUplink(event,self.uplink_iface)
        self.log.debug("Setting uplink to %s" % str(self.uplink))
        self.garp = createGratuitousARP(self.vstag,self.hw_addr)
        self.gratuitousARP(self.dpid)
        Timer(15, self.gratuitousARP, args=[None],recurring=True)

    def _handle_PacketIn(self,event):
        eth = event.parsed.find('ethernet')
        vlan = event.parsed.find('vlan')
        ipv4 = event.parsed.find('ipv4')
        arp = event.parsed.find('arp')
        if event.port == self.uplink:
            if not (bool(ipv4) or bool(vlan)):
                self.log.debug("PacketIn: Neither IPv4 or VLAN (%s)" % eth)
                return
            # must be some packet from a VM or Gratuitous ARP
            # I will do it later
            if bool(vlan) and (vlan.type == pkt.ethernet.ARP_TYPE):
                self.log.debug("Receive gratuitous ARP: %s" % vlan)
                return
            if bool(vlan) and (vlan.id == self.vstag):
                self.inboundFromRemoteVM(event,vlan)
        else:
            # Packet from a local VM
            # If it's ARP without VLAN, probably is a local VM querying for IP
            if bool(arp) and not bool(vlan):
                self.handle_ARP(event,eth,arp)
                return
            # Not ARP? Must be traffic from local VMs
            self.inboundFromLocalVM(event,eth)

    def gratuitousARP(self,dpid):
        '''Send gratuitous ARP for one or all vswitches'''
        self.send(self.garp,of.OFPP_ALL)

    def send(self,packet,port):
        msg = of.ofp_packet_out(data=packet)
        msg.actions.append(of.ofp_action_output(port = port))
        try:
            self.conn.send(msg)
        except:
            raise RuntimeError("can't send msg to vswitch vstag=%d" % \
                               self.vstag)

    def handle_ARP(self,event,eth,arp):
        ports_list = self.conn.features.ports
        [ port ] = [ p for p in ports_list if p.port_no == event.port ]
        self.log.debug("ARP from port = %d port.name = %s" % 
                      (event.port,port.name))
        # return (net_id,vstag,hotom_addr)
        (net_id,vstag,hotom_addr,p) = self.dbcache.getDstVMFromIngressPort(self.vstag,port.name,arp.protodst.toStr())
        arp_reply = createARPReply(net_id,vstag,hotom_addr,eth)
        self.log.debug("Sending ARP reply to %s that asked for %s" % \
                       (eth.src.toStr(),arp.protodst.toStr()))
        self.send(arp_reply,event.port)

    def inboundFromLocalVM(self,event,eth):
        ip = event.parsed.find('ipv4')
        if ip is None:
            self.log.debug("Non IPv4 packet received: %s", eth.payload)
            return
        ports_list = self.conn.features.ports
        [ port ] = [ p for p in ports_list if p.port_no == event.port ]
        self.log.debug("Packet from port = %d port.name = %s" % 
                      (event.port,port.name))
        # return (net_id,vstag,hotom_addr)
        (net_id,dst_vstag,dst_hotom_addr,dst_port_name) = \
        self.dbcache.getDstVMFromIngressPort(self.vstag,port.name,
                                             ip.dstip.toStr())
        if dst_vstag == self.vstag:
            self.log.debug("Same vswitch traffic. Installing L2 pair");
            [ dst_port ] = [ p for p in ports_list if p.name == dst_port_name ]
            self.installL2Pair(event,eth,dst_port.port_no)
        else:
            # Frame to a remote VM, encapsule it and send out
            self.outboundToRemoteVM(eth,net_id,dst_vstag)

    def inboundFromRemoteVM(self,event,vlan):
        self.log.debug("Traffic from remote VM")
        hotom = event.parsed.find('hotom')
        hotom_addr_dst = hotom.dst.toStr()[9:]
        port_name = self.dbcache.getDstVMFromUplinkPort(hotom.net_id,hotom_addr_dst)
        ports_list = self.conn.features.ports
        [ port ] = [ p for p in ports_list if p.name == port_name ]
        eth = pkt.ethernet(type=pkt.ethernet.IP_TYPE)
        eth.dst = hotom.dst
        eth.src = hotom.src
        eth.payload = hotom.payload
        self.send(eth,port.port_no)
        return

    def installL2Pair(self,event,eth,port):
        '''If packet reaches installL2Pair, there's no match'''
        # First, install the 'packet response' entry
        msg = of.ofp_flow_mod()
        msg.idle_timeout = of.OFP_FLOW_PERMANENT
        msg.hard_timeout = of.OFP_FLOW_PERMANENT
        msg.match.dl_type = eth.type
        msg.match.dl_src = eth.dst
        msg.match.dl_dst = eth.src
        msg.match.in_port = port
        msg.actions.append(of.ofp_action_output(port = event.port))
        self.conn.send(msg)
        # Then install forwarding rule and send packet
        msg = of.ofp_flow_mod()
        msg.idle_timeout = of.OFP_FLOW_PERMANENT
        msg.hard_timeout = of.OFP_FLOW_PERMANENT
        msg.data = event.ofp
        msg.match.dl_type = eth.type
        msg.match.dl_src = eth.src
        msg.match.dl_dst = eth.dst
        msg.match.in_port = event.port
        msg.actions.append(of.ofp_action_output(port = port))
        self.conn.send(msg)

    def outboundToRemoteVM(self,eth,net_id,dst_vstag):
        dst_eth = getEthAddrFromVstag(dst_vstag)
        # Create HotOM header from original frame
        hotom = pkt.hotom()
        hotom.net_id = net_id
        hotom.dst = eth.dst
        hotom.src = eth.src
        hotom.type = pkt.hotom.IP_TYPE
        hotom.payload = eth.payload
        # Create VLAN header
        vlan = pkt.vlan(id=dst_vstag, eth_type=pkt.ethernet.HOTOM_TYPE)
        # Replace ethernet addresses and encapsulate
        eth.src = self.hw_addr
        eth.dst = dst_eth
        eth.type = pkt.ethernet.VLAN_TYPE
        vlan.payload = hotom
        eth.payload = vlan
        self.send(eth,self.uplink)

def launch(vstag,uplink):
    if int(vstag) > 4095:
        print "Invalid vstag: %s" % vstag
        sys.exit(1)
    core.registerNew(LAS,vstag,uplink,dbcache="lcache-"+str(vstag)+".db")
