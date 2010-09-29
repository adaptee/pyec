#!/usr/bin/env python
# vim: set fileencoding=utf-8 :

import codes

from pack import pack_uint8
from unpack import unpack_uint8
from tag import ECTag, unpack_ectag, unpack_ectag_tagcount
from misc import indentext

class ECPacket(ECTag):
    def __init__(self, op, subtags=[ ]):
        ECTag.__init__(self,)
        self.op   = op
        self.subtags = subtags

    def assertself(self):
        assert self.op in codes.ops.keys()
        for subtag in self.subtags:
            subtag.assertself()

    def pack(self):

        self.assertself()

        result = ""

        result += self._pack_op()
        result += self._pack_tagcount()

        for tag in self.subtags:
            result += tag.pack()

        return result

    def _pack_op(self):
        op = codes.ops[self.op]
        return pack_uint8(op)

    def debugrepr(self, indent_level=0 ):

        self.assertself()

        result = ""
        result += indentext( self._op_debugrepr(), indent_level )
        result += indentext( "tagcount: %d \n" % len(self.subtags),
                             indent_level )

        for tag in self.subtags:
            result += tag.debugrepr(indent_level + 1)

        return result

    def _op_debugrepr(self):
        opcode = codes.ops[self.op]
        #return "op: %s | %s | %d \n" % ( self.op, hex(opcode), opcode )
        return "op: %s | %s \n" % ( self.op, hex(opcode), )

def unpack_ecpacket(data, utf8_num=True ):

    op, data = unpack_ecpacket_op(data)

    op = codes.ops_rev[op]

    tagcount, data = unpack_ectag_tagcount(data, utf8_num)

    subtags = [ ]

    for i in range(tagcount):
        tag, data, _ = unpack_ectag(data, utf8_num)
        subtags.append(tag)

    return ECPacket( op, subtags)

def unpack_ecpacket_op(data):
    length =  1
    value, _ = unpack_uint8(data)

    return value, data[length:]
