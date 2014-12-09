from HotOM.lib.tools import *
from pox.lib.addresses import *
import pox.lib.packet as pkt
import struct

class HotOMVM(object):
    def __init__(self,hw_addr=None,ip_addr=None):
        self.hw_addr = hw_addr
        self.ip_addr = ip_addr

    @property
    def ip_addr(self):
        return self._ip_addr

    @ip_addr.setter
    def ip_addr(self,val):
        if val is None:
            self._ip_addr = val
        elif isinstance(val,str):
            self._ip_addr = IPAddr(val)
        elif isinstance(val,IPAddr):
            self._ip_addr = val
        else:
            raise TypeError

    @property
    def hw_addr(self):
        return self._hw_addr

    @hw_addr.setter
    def hw_addr(self,val):
        if val is None:
            self._hw_addr = None
            return
        if isinstance(val,bytes):
            if len(val) == 6:
                buf = '\x00' * 3 + val[3:]
            elif len(val) == 17:
                buf = '00:00:00:' + val[9:]
            else:
                raise ValueError
            self._hw_addr = EthAddr(buf)
        elif isinstance(val,EthAddr):
            buf = val.toRaw()
            buf = '\x00' * 3 + buf[3:]
            self._hw_addr = EthAddr(buf)
        else:
            raise TypeError

    def __str__(self):
        return "[HotOMVM: hw_addr = {0} | ip_addr = {1} ]".format(self.hw_addr,
                                                                  self.ip_addr)

class HotOMvSwitch(object):

    def __init__(self,vstag):
        self.vstag = vstag
        self._setHwAddr(vstag)
        self._vm = dict()
        self._cam = dict()
        self.uplink = 0

    @property
    def vstag(self):
        return self._vstag

    @vstag.setter
    def vstag(self,val):
        self._vstag = self._intsetter(val)
        
    @property
    def uplink(self):
        return self._uplink

    @uplink.setter
    def uplink(self,val):
        self._uplink = self._intsetter(val)

    def _intsetter(self,val):
        if isinstance(val,int):
            return val
        else:
            raise TypeError

    def _setHwAddr(self,vstag):
        m = vstag >> 8
        l = (0x000f & vstag)
        buf = '\x00' * 4 + struct.pack('!2B',m,l)
        self.hw_addr = EthAddr(buf)

    def addVM(self,vm,port):
        if isinstance(port,int) and isinstance(vm,HotOMVM):
            self._vm[port] = vm
            if vm.hw_addr is not None:
                self._cam[vm.hw_addr] = port
            if vm.ip_addr is not None:
                self._cam[vm.ip_addr] = port
        else:
            raise TypeError
    
    def getPort(self,hw_addr):
        '''Get Port for a given MAC, removing net_id first'''
        return self._cam[removeNetIDEthAddr(hw_addr)]

    def __str__(self):
        buf = "[HotOMvSwitch: hw_addr = %s" % self.hw_addr + "\n"
        for k in self._vm.keys():
            buf = buf + "               port %s => %s\n" % (k,self._vm[k]) 
        return buf[:len(buf)-1]+"]"

    def createGratuitousARP(self):
        eth = pkt.ethernet(dst=pkt.ETHER_BROADCAST,src=self.hw_addr)
        eth.type = pkt.ethernet.VLAN_TYPE
        vlan = pkt.vlan(id=self.vstag)
        vlan.eth_type = pkt.ethernet.ARP_TYPE
        grat = pkt.arp()
        grat.opcode = pkt.arp.REQUEST
        grat.hwsrc = eth.src
        grat.hwdst = eth.dst
        grat.payload = b'\x0f' * 8
        eth.payload=vlan
        vlan.payload=grat
        return eth

class HotOMNet(object):
    def __init__(self,net_id):
        self.net_id = net_id
        self.vswitch = dict()
        self.vm = list()

    @property
    def net_id(self):
        return self._net_id

    @net_id.setter
    def net_id(self,val):
        if val is None:
            self._net_id = val
        elif isinstance(val,int):
            self._net_id = val
        else:
            raise TypeError

    def addvSwitch(self,dpid,val):
        if isinstance(val,HotOMvSwitch) and isinstance(dpid,int):
            self.vswitch[dpid]=val
        else:
            raise TypeError

    def removevSwitch(self,dpid):
        if self.vswitch.has_key(dpid):
            del(self.vswitch[dpid])
        else:
            raise RuntimeError("Switch does not exist")

    def getDPID(self,val):
        if isinstance(val,HotOMvSwitch):
            for k in self.vswitch.keys():
                if self.vswitch[k] == val:
                    return k
            return None
        else:
            raise TypeError

    def toRaw(self):
        return struct.pack('!H',self.net_id>>8) + \
            struct.pack('!B',0xff&self.net_id)

    def __str__(self):
        buf = "[HotOMNet: net_id = %s" % (hex(self.net_id)) + "\n"
        for k in self.vswitch.keys():
            buf = buf + "      dpid = %s => %s\n" % (k,self.vswitch[k])
        return buf[:len(buf)-1]+"]"

    def getVMfromIP(self,addr):
        '''Return hw addr from IP. Used to support ARP resolution'''
        if isinstance(addr,IPAddr):
            for v in self.vswitch.keys():
                vs = self.vswitch[v]
                for i in vs._vm:
                    if addr == vs._vm[i].ip_addr:
                        return vs._vm[i].hw_addr
            return None
        else:
            raise TypeError

    def createARPResponse(self,pkt_eth,hw_addr):
        '''Get ARP query ethernet frame and create ARP response'''
        hw_src = addNetIDEthAddr(hw_addr,self.net_id)
        eth = pkt.ethernet(dst=pkt_eth.src,src=hw_src)
        eth.type = pkt.ethernet.ARP_TYPE
        arp = pkt.arp(opcode=pkt.arp.REPLY)
        arp.hwsrc = hw_src
        arp.hwdst = pkt_eth.src
        arp.protosrc = pkt_eth.payload.protodst
        arp.protodst = pkt_eth.payload.protosrc
        eth.payload = arp
        return eth
