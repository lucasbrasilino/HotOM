from pox.lib.addresses import *
from pox.lib.util import initHelper
import struct
import os
import sys
from sqlalchemy import Column, ForeignKey, Integer, String, BINARY
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine


Base = declarative_base()

class HotOMBaseComp(object):
    def _init (self, kw):
        initHelper(self,kw)

class HotOMvSwitch(Base,HotOMBaseComp):
    __tablename__="vs"
    id = Column(Integer,primary_key=True)
    _vs_tag = Column(Integer, nullable=False)
    _hw_addr = Column(String(17), nullable=False)
    _up_link = Column(Integer, nullable=False)

    def __init__(self,vstag,uplink = 0):
        self.vstag = vstag
        self.hw_addr = None
        self._setHwAddr(vstag)
        self._vm = dict()
        self._cam = dict()
        self.uplink = uplink

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

class HotOMVM(Base,HotOMBaseComp):

    __tablename__="vm"
    id = Column(Integer,primary_key=True)
    _net_id = Column(String(8), nullable=True)
    _hw_addr = Column(String(17), nullable=False)
    _ip_addr = Column(String(15), nullable=False)
    name = Column(String(12), nullable=True)
    vs_id = Column(Integer, ForeignKey('vs.id'))
    vs = relationship(HotOMvSwitch)

    def __init__(self, **kw):
        self.hw_addr = "00:00:00:00:00:00"
        self.ip_addr = "0.0.0.0"
        self.net_id = 0
        self._init(kw)

    @property
    def ip_addr(self):
        return IPAddr(self._ip_addr)

    @ip_addr.setter
    def ip_addr(self,val):
        ''' _ip_addr is str to be easily stored in db '''
        if isinstance(val,str):
            # Creating IPAddr object to parse address
            self._ip_addr = IPAddr(val).toStr()
        elif isinstance(val,IPAddr):
            self._ip_addr = val.toStr()
        else:
            raise TypeError

    @property
    def hw_addr(self):
        return EthAddr(self._hw_addr)

    @hw_addr.setter
    def hw_addr(self,val):
        if isinstance(val,bytes):
            if len(val) == 6:
                buf = '\x00' * 3 + val[3:]
            elif len(val) == 17:
                buf = '00:00:00:' + val[9:]
            else:
                raise ValueError
            self._hw_addr = EthAddr(buf).toStr()
        elif isinstance(val,EthAddr):
            buf = val.toRaw()
            buf = '\x00' * 3 + buf[3:]
            self._hw_addr = EthAddr(buf).toStr()
        else:
            raise TypeError

    @property
    def net_id(self):
        return int(self._net_id,16)

    @net_id.setter
    def net_id(self, val):
        if isinstance(val, int):
            self._net_id = hex(val)
        else:
            raise TypeError

    def __str__(self):
        return "[HotOMVM: net_id = 0x{0:x} | hw_addr = {1} | ip_addr = {2} ]".format(self.net_id, self.hw_addr, self.ip_addr)


engine = create_engine('sqlite:///dc.db')
Base.metadata.create_all(engine)
