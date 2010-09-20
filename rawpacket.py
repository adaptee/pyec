#!/usr/bin/env python
# vim: set fileencoding=utf-8 :

from struct import pack
from pack import *

class ECRawPacket:
    def __init__(self, flag, packet=None):
        self.flag = flag
        self.packet = packet

    def _assert(self):
        assert self.packet

    def debugrepr(self):
        self._assert()

        result = ""
        result += "flag: %s\n" % bin(self.flag)
        result += self.packet.debugrepr()

        return result


    def pack(self):
        self._assert()
        result = ""

        result += self._pack_flag()

        data = self.packet.pack()
        data = self._compress_data(data)

        result += pack_uint32( len(data) )
        result += data

        return result

    def _compress_data(self, data):
        if self.flag & codes2.flags['zlib'] :
            return  zlib.compress(data)
        else:
            return data

    def _pack_flag():
        return pack_uint32(self.flag)


def unpack_raw_packet(sock):




