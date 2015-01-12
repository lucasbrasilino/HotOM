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

class HotOMVM(Base,HotOMBaseComp):

    __tablename__="vm"
    id = Column(Integer,primary_key=True)
    name = Column(String(12), nullable=True)
    _hw_addr = Column(String(17), nullable=False)
    _ip_addr = Column(String(15), nullable=False)
    _net_id = Column(Integer, nullable=True)
    

    def __init__(self, **kw):
        self.hw_addr = "00:00:00:00:00:00"
        self.ip_addr = "0.0.0.0"
        self.net_id = 0
        print self
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
        return self._net_id

    @net_id.setter
    def net_id(self, val):
        if isinstance(val, int):
            self._net_id = val
        else:
            raise TypeError

    def __str__(self):
        return "[HotOMVM: net_id = {0} | hw_addr = {1} | ip_addr = {2} ]".format(self.net_id, self.hw_addr, self.ip_addr)

engine = create_engine('sqlite:///dc.db')
Base.metadata.create_all(engine)
