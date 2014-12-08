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
        Timer(5, self.dump,recurring=True)

    def handle_registerVM2Net(event,eth):
        '''Register VM to a Net. If it does not exist, create one'''
        net_id = getNetIDEthAddr(eth.src)
        vm = HotOMVM(nw_addr=eth.src,ip_addr=eth.payload.protodst)
        self.avs[event.dpid].addVM(vm,event.port)
        if not self.net.has_key(net_id):
            self.log.debug("Creating HotOM network: %s" % net_id)
            self.net[net_id] = HotOMNet(net_id)
        self.log.debug("Adding VM %s to HotOM network %s" % (eth.src,net_id))
        self.net[net_id].addvSwitch(event.dpid,self.avs[event.dpid])
        
    def handle_ARP(self,event,eth,arp):
        '''Handle ARP requests'''
        if arp.protosrc == ipv4.IP_ANY:
            # VM does an ARP before assign IP
            self.handle_registerVM2Net(event,eth)

    def _handle_ConnectionUp(self,event):
        if event.dpid == 1:
            vstag = 4051
        else:
            vstag = 4052
        vs = HotOMvSwitch(vstag)
        self.avs[event.dpid] = vs
        vs.uplink = 1
        self.gratuitousARP(vs)

    def _handle_PacketIn(self,event):
        packet = event.parsed
        port = event.port
        dpid = event.dpid
        eth = packet.find('ethernet')
        arp = packet.find('arp')
        if arp is not None:
            self.handle_ARP(event,eth,arp)
        if not (bool(packet.find('ipv4')) or bool(packet.find('vlan'))):
            self.log.debug("PacketIn: Neither IPv4 or VLAN => %s" % packet)
            return



def launch():
    core.registerNew(NCS)
