#!/usr/bin/env python
# vim: set fileencoding=utf-8 :

import zlib
import codes2


from pack import *
from unpack import unpack_uint8, unpack_uint16
from tag2 import unpack_ectag

class ECPacket:
    def __init__(self, op, tags=None):
        self.op   = op
        self.tags = tags

    def _assert(self):
        assert self.op in codes2.ops.keys()
        assert self.tags

    def debugrepr(self):

        self._assert()

        result = ""
        result += "op: %s \n" % self.op
        result += "tagcount: %d \n" % len(self.tags)

        for tag in self.tags:
            result += tag.debugrepr()

        return result

    def settags(self, tags):
        assert tags;
        self.tags = tags

    def pack(self):

        self._assert()

        result = ""

        result += self._pack_op()
        result += self._pack_tagscount()

        for tag in self.tags:
            result += tag.pack()

        return result

    def _pack_op(self):
        op = codes2.ops[self.op]
        return pack_uint8(op)

    def _pack_tagscount(self):
        count = len(self.tags)
        return pack_uint16(count)


def unpack_ecpacket(data, utf8_num=True ):

    op, data       = unpack_ecpacket_op(data)

    op = codes2.ops_rev[op]

    tagcount, data = unpack_ecpacket_tagcount(data, utf8_num)

    tags = [ ]

    for i in range(tagcount):
        tag, data = unpack_ectag(data, utf8_num)
        tags.append(tag)

    assert len(data) == 0

    return ECPacket( op, tags)

def unpack_ecpacket_op(data):
    length =  1
    #value, = unpack("!B",data[length:])
    value, _= unpack_uint8(data)

    return value, data[length:]

def unpack_ecpacket_tagcount(data, utf8_num=True ):

    value  = -1
    length = -1

    if utf8_num:
        #value, length = unpack_utf8_num(data)
        return unpack_utf8_num(data)
    else:
        length = 2
        #value, = unpack( '!H', data[:length] )
        value, _ = unpack_uint16( data )
        return value, data[length:]


