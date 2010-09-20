#!/usr/bin/env python
# vim: set fileencoding=utf-8 :

import codes2

from pack import *
from unpack import *

class ECRawPacket:

    # current, only use the simplest flag when sending data
    # of course, we still support other advanced features when
    # dealying with received data.
    def __init__(self, packet, flag=codes2.flags['base'] ):
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

    def _pack_flag(self):
        return pack_uint32(self.flag)


# responsible for extract out flag and length from the given 8 bytes
def unpack_rawpacket_header(header):
    assert len(header) == 8

    flag,  _ = unpack_uint32(header[:4])
    length,_ = unpack_uint32(header[4:])

    return flag, length

def unpack_rawpacket_data(data, flag):

    if (flag & codes2.flags['zlib']):
        return zlib.decompress(data)
    else:
        return data





