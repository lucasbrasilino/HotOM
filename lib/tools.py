from pox.lib.addresses import EthAddr
import struct

def addNetIDEthAddr(addr,net_id):
    '''Return an EthAddr object with net_id MAC'''
    if not isinstance(addr,EthAddr):
        raise TypeError
    ni_bytes = struct.pack('!H',net_id>>8) + struct.pack('!B',0xff&net_id)
    return EthAddr(ni_bytes+addr.toRaw()[3:]) 
    
def removeNetIDEthAddr(addr):
    '''Return the EthAddr without net_id in MAC, as stored in DB'''
    if not isinstance(addr,EthAddr):
        raise TypeError
    return EthAddr('\x00\x00\x00'+addr.toRaw()[3:])

def fromHotOMtoEthAddr(hotom_addr):
    return EthAddr("00:00:00:"+hotom_addr)

def getNetIDEthAddr(addr):
    '''Get the net_id in MAC'''
    if not isinstance(addr,EthAddr):
        raise TypeError
    return addr.toRaw()[:3]

def fromBytesToInt(b):
    '''Get hex bytes and return int'''
    if not isinstance(b,bytes):
        raise TypeError
    return 65536*ord(b[0])+256*ord(b[1]) + ord(b[2])

def getEthAddrFromVstag(vstag):
    e_bytes = b'\x00\x00\x00\x00' + chr((0xff00&vstag)>>8) + chr(0xff&vstag)
    return EthAddr(e_bytes)
