import struct

from pox.lib.packet.packet_base import packet_base
from pox.lib.addresses import *

class hotom(packet_base):
    "HotOM header"

    LEN = 9

    def __init__(self, raw=None, prev=None, net_id=None, dst=None, src=None, **kw):
        packet_base.__init__(self)

        self.prev = prev
        self.next = None

        self.net_id = EthAddr('00:00:00:' + net_id)
        self.dstsrc = EthAddr(dst + ':' + src)

        if raw is not None:
            self.parse(raw)

        self._init(kw)

    def __str__(self):
        s = "[HotOM net_id={0} dst={1} src={2}]".format(
            self.net_id.toStr()[9:],
            self.dstsrc.toStr()[0:8],
            self.dstsrc.toStr()[9:])
        return s

    def parse(self, raw):
        assert isinstance(raw,bytes)
        self.next = None
        self.raw = raw
        alen = len(raw)
        if alen < hotom.LEN:
            self.msg('warning HotOM packet data too short to parse header: data len %u' % (alen,))
            return

        self.net_id = EthAddr('\x00\x00\x00'+raw[:3])
        self.dstsrc = EthAddr(raw[3:9])
        self.next = raw[hotom.LEN:]
        self.parsed = True

    def hdr(self,payload):
        return struct.pack('!3s6s', self.net_id.toRaw()[3:],
                           self.dstsrc.toRaw())
