import struct

from pox.lib.packet.packet_base import packet_base

class hotom(packet_base):
    "HotOM header"

    LEN = 9

    def __init__(self, raw=None, prev=None, net_id=None, dst=None, src=None, **kw):
        packet_base.__init__(self)

        self.prev = prev
        self.next = None

        self.net_id = net_id
        self.dst = dst
        self.src = src

        if raw is not None:
            self.parse(raw)

        self._init(kw)

    def __str__(self):
        s = "[HotOM net_id={0} dst={1} src={2}]".format(self.net_id,
                                                        self.dst,self.src)
        return s

    def parse(self, raw):
        assert isinstance(raw,bytes)
        self.next = None
        self.raw = raw
        #self.net_id = raw[:6]
        #self.dst = raw[6:12]
        #self.src = raw[12:18]
        (self.net_id, self.dst, self.src) = struct.unpack('!3s3s3s',
                                                          raw[:hotom.LEN])
        self.next = raw[hotom.LEN:]
        self.parsed = True

    def hdr(self,payload):
        return struct.pack('!3s3s3s',self.net_id,self.dst,self.src)
