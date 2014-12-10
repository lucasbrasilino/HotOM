from pox.core import core
import pox.openflow.libopenflow_01 as of
import pox.lib.packet as pkt
from pox.lib.addresses import *
from pox.lib.recoco import Timer
from pox.lib.util import dpid_to_str
from HotOM.lib.HotOMTenant import *
from HotOM.lib.tools import *
import csv

FLOW_TIMEOUT = 300

class NCS(object):
    def __init__(self,conf):
        self.net = dict()
        self.avs = dict()
        self.confvstag = dict() # vstag table from config file
        self.log = core.getLogger()
        core.openflow.miss_send_len = 1400
        core.openflow.addListeners(self)
        self.log.info("NCS initialization")
        self.parseConf(conf)
        Timer(30, self.gratuitousARP, args=[None],recurring=True)
        Timer(10, self.dump,recurring=True)

    def dump(self):
        for k in self.net.keys():
            self.log.debug(self.net[k])

    def handle_registerVM2Net(self,event,eth):
        '''Register VM to a Net. If it does not exist, create one'''
        net_id = fromBytesToInt(getNetIDEthAddr(eth.src))
        vm = HotOMVM(hw_addr=eth.src,ip_addr=eth.payload.protodst)
        self.avs[event.dpid].addVM(vm,event.port)
        if not self.net.has_key(net_id):
            self.log.info("Creating HotOM network: %s" % hex(net_id))
            self.net[net_id] = HotOMNet(net_id)
        self.log.debug("Adding VM %s to HotOM network %s" % (eth.src,hex(net_id)))
        self.net[net_id].addvSwitch(event.dpid,self.avs[event.dpid])
        
    def handle_ARP(self,event,eth,arp):
        '''Handle ARP requests'''
        if arp.protosrc == IP_ANY:
            # No IP address assigned VM does an ARP
            self.handle_registerVM2Net(event,eth)
            return
        # Get AVS handling ARP
        vs = self.avs[event.dpid]
        ## Check if ARP comes from VM
        if event.port == vs.uplink:
            return
        # Query hw addr from IP in database
        net_id = fromBytesToInt(getNetIDEthAddr(eth.src))
        hw_dst = self.net[net_id].getVMfromIP(eth.payload.protodst)
        if hw_dst is None:
            return
        resp = self.net[net_id].createARPResponse(eth,hw_dst)
        self.send(event.dpid,resp,event.port)

    def send(self,dpid,packet,port):
        msg = of.ofp_packet_out(data=packet)
        msg.actions.append(of.ofp_action_output(port = port))
        try:
            conn = core.openflow.getConnection(dpid)
            conn.send(msg)
        except:
            raise RuntimeError("can't send msg to vSwitch %d" % dpid)
        
    def gratuitousARP(self,dpid):
        '''Send gratuitous ARP for one or all vswitches'''
        if dpid is None:
            dpid_list = core.openflow.connections.keys()
        else:
            dpid_list = list()
            dpid_list.append(dpid)
        for k in dpid_list:
            vs = self.avs[k]
            eth = vs.createGratuitousARP()
            self.send(k,eth,vs.uplink)

    def _handle_ConnectionUp(self,event):
        
        try:
            vstag = self.confvstag[dpid_to_str(event.dpid)]
        except KeyError:
            self.log.debug("No vstag associated to dpid %s | Ignored" % \
                           dpid_to_str(event.dpid))
            return
        self.log.debug("Adding vswitch vstag=%d",vstag)
        vs = HotOMvSwitch(vstag)
        self.avs[event.dpid] = vs
        vs.uplink = 1
        self.gratuitousARP(event.dpid)

    def _handle_ConnectionDown(self,event):
        for (k,net) in self.net.iteritems():
            try:
                net.removevSwitch(event.dpid)
            except:
                self.log.debug("Removing unknown switch: %d" % event.dpid)
        del(self.avs[event.dpid])

    def _handle_PacketIn(self,event):
        try:
            vs = self.avs[event.dpid]
        except KeyError:
            self.log.info("PacketIn from unknown dpid:%s" % dpid_to_str(event.dpid))
            return
        packet = event.parsed
        eth = packet.find('ethernet')
        vlan = packet.find('vlan')
        arp = packet.find('arp')
        # If it's ARP without VLAN, probably is a VM checking for IP
        if bool(arp) and not bool(vlan):
            self.handle_ARP(event,eth,arp)
        if not (bool(packet.find('ipv4')) or bool(packet.find('vlan'))):
            #self.log.debug("PacketIn: Neither IPv4 or VLAN => %s" % packet)
            return
        # If it's from a port other than uplink, must be a VM sending something
        if event.port == vs.uplink:
            if self.isInboundMatch(event):
                self.inbound(event)
        else:
            self.outbound(event)

    def outbound(self,event):
        packet = event.parsed
        eth = packet.find('ethernet')
        net_id = fromBytesToInt(getNetIDEthAddr(eth.src))
        vs = self.net[net_id].vswitch[event.dpid]
        vstag = vs.vstag
        try:
            port = vs.getPort(eth.dst)
            self.installL2Pair(event,port)
        except KeyError:
            self.log.debug("Outbount to network core: %s" % eth)
            self.outbound2Network(event)

    def installL2Pair(self,event,port):
        '''If packet reaches installL2Pair, there's no match'''
        packet = event.parsed
        eth = packet.find('ethernet')
        # First, install the 'packet response' entry
        msg = of.ofp_flow_mod()
        msg.idle_timeout = FLOW_TIMEOUT
        msg.hard_timeout = 5*FLOW_TIMEOUT
        msg.match.dl_type = eth.type
        msg.match.dl_src = eth.dst
        msg.match.dl_dst = eth.src
        msg.match.in_port = port
        msg.actions.append(of.ofp_action_output(port = event.port))
        event.connection.send(msg)
        # Then install forwarding rule and send packet
        msg = of.ofp_flow_mod()
        msg.idle_timeout = FLOW_TIMEOUT
        msg.hard_timeout = 5*FLOW_TIMEOUT
        msg.data = event.ofp
        msg.match.dl_type = eth.type
        msg.match.dl_src = eth.src
        msg.match.dl_dst = eth.dst
        msg.match.in_port = event.port
        msg.actions.append(of.ofp_action_output(port = port))
        event.connection.send(msg)

    def outbound2Network(self,event):
        remote_vstag = None
        remote_vs_hw = None
        vs_hw = self.avs[event.dpid].hw_addr
        uplink = self.avs[event.dpid].uplink
        packet = event.parsed
        eth = packet.find('ethernet')
        net_id = fromBytesToInt(getNetIDEthAddr(eth.src))
        hw_dst = removeNetIDEthAddr(eth.dst)
        (remote_vstag,remote_vs_hw) = self.net[net_id].getRemotevSwitchData(hw_dst)
        if remote_vstag is None:
            self.log.info("External packet to a unknown destination: %s" % eth.dst)
            return
        vlan = pkt.vlan(id=remote_vstag, eth_type=pkt.ethernet.HOTOM_TYPE)
        hotom = pkt.hotom()
        hotom.net_id = net_id
        hotom.dst = eth.dst
        hotom.src = eth.src
        eth.src = vs_hw
        eth.dst = remote_vs_hw
        hotom.payload = eth.payload
        vlan.payload = hotom
        eth.payload = vlan
        eth.type = pkt.ethernet.VLAN_TYPE
        self.send(event.dpid,eth,uplink)

    def isInboundMatch(self,event):
        # Test if inbound vlan ID matches vstag and dst hw addr matches AVS hw addr
        vs=self.avs[event.dpid]
        packet = event.parsed
        eth = packet.find('ethernet')
        vlan = packet.find('vlan')
        if vlan is None:
            return False
        if bool(eth.dst == vs.hw_addr) and bool(vlan.id == vs.vstag):
            return True
        else:
            return False

    def inbound(self,event):
        packet = event.parsed
        eth = packet.find('ethernet')
        vlan = packet.find('vlan')
        hotom = packet.find('hotom')
        if hotom is None:
            return
        try:
            vs = self.net[hotom.net_id].vswitch[event.dpid]
        except KeyError:
            self.log.debug("Packet arrived from an alien network: %d" \
                           % pkt_hotom.net_id)
        eth.dst = hotom.dst
        eth.src = hotom.src
        eth.type = pkt.ethernet.IP_TYPE
        eth.payload = hotom.payload
        port = vs.getPort(removeNetIDEthAddr(hotom.dst))
        self.send(event.dpid,eth,port)

    def parseConf(self,conf):
        if conf == False:
            # hardcoded
            self.confvstag['00-00-00-00-00-01'] = 4051
            self.confvstag['00-00-00-00-00-02'] = 4052
            return
        self.log.info("Parsing configuration file: %s" % conf)
        with open(conf) as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                self.log.debug("Associating dpid %s to vstag %d" % \
                               (row['dpid'],int(row['vstag'])))
                self.confvstag[row['dpid']] = int(row['vstag'])

def launch(conf=False):
    core.registerNew(NCS,conf)
