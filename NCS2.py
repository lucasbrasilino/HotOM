from pox.core import core
import pox.openflow.libopenflow_01 as of
import pox.lib.packet as pkt
from pox.lib.addresses import *
from pox.lib.recoco import Timer
from HotOM.lib.HotOMTenant import *
from HotOM.lib.tools import *

class NCS(object):
    def __init__(self):
        self.net = dict()
        self.avs = dict()
        self.log = core.getLogger()
        core.openflow.miss_send_len = 1400
        core.openflow.addListeners(self)
        self.log.info("NCS initialization")
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
            self.log.debug("Creating HotOM network: %s" % hex(net_id))
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
        if event.dpid == 1:
            vstag = 4051
        else:
            vstag = 4052
        vs = HotOMvSwitch(vstag)
        self.avs[event.dpid] = vs
        vs.uplink = 1
        self.gratuitousARP(event.dpid)

    def _handle_PacketIn(self,event):
        packet = event.parsed
        port = event.port
        dpid = event.dpid
        eth = packet.find('ethernet')
        vlan = packet.find('vlan')
        arp = packet.find('arp')
        if bool(arp) and not bool(vlan):
            self.handle_ARP(event,eth,arp)
        if not (bool(packet.find('ipv4')) or bool(packet.find('vlan'))):
            self.log.debug("PacketIn: Neither IPv4 or VLAN => %s" % packet)
            return



def launch():
    core.registerNew(NCS)
