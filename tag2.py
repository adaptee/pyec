#!/usr/bin/env python
# vim: set fileencoding=utf-8 :

import types
import struct

import codes
from tagtypes import tagtype


class ECTag:

    def __init__ (self, name=None, type=None, subtags = [ ], data=[ ] ):
        self.name = name
        self.type = type
        self.subtags = subtags
        self.data = data

    def _assert(self):
        """ called befor packing, or after unpacking"""
        assert self.name in codes.tag.keys()
        assert self.type in tagtype.keys()


    def debugprint (self):
        result = ""
        result += "%s\n" % self.name
        result += "%s\n" % self.type

        for tag in self.subtags:
            result += tag.debugprint()

        for item in  self.data:
            result += "%s\n" % str(item)

        return result

    def setname(self, name):
        assert name in codes.tag.keys()
        self.name = name

    def settype(self, type):

        assert type in tagtype.keys()
        self.type = type

    def setdata(self, data):
        """create ECTag method #1, based upon readable data from ourside """

        self.data = data

    def addsubtag(self, subtag):
        self.subtags.append(subtag)

    def packup(self):
        """create the binary representatio of this ECTag, which is used in
        communication"""
        self._assert()

        result = ""

        result += self._pack_name()
        result += self._pack_type()

        subtags = self._pack_subtags()
        data = self._pack_data()

        length = len(subtags) + len(data)
        result += self._pack_uInt16(length)

        result += subtags
        result += data

        return result

    def _pack_name(self):

        tagname = codes.tag[self.name]

        if self.subtags :
            tagname = tagname * 2 + 1
        else:
            tagname = tagname * 2

        return self._pack_uInt16(tagname)

    def _pack_type(self):
        type = tagtype[self.type]
        assert type < 256
        return struct.pack("!B", type)

    def _pack_subtags(self):

        result = ""

        count = len(self.subtags)
        if count :
            result += self._pack_uInt16(count)
            for subtag in self.subtags:
                result += subtag.packup()

        return result

    def _pack_data(self):

        result = ""
        t = self.type
        data = self.data

        if  t in ('uint8','uint16', 'uint32', 'uint64'):
            result += self._pack_number(data)
        elif t == 'string':
            result += self._pack_string(data)
        elif t == 'hash16':
            result += self._pack_hash(data)
        else:
            raise TypeError('Invalid type:%s' % t)

        return result

    def _pack_string(self, data):
        data += u'\0'
        return unicode.encode(data,"utf-8")

    def _pack_hash(self, data):
        return data

    def _pack_number(self, num):

        if num < pow(2, 8):
            return self._pack_uInt8(num)
        elif num < pow(2, 16):
            return self._pack_uInt16(num)
        elif num < pow(2, 32):
            return self._pack_uInt16(num)
        elif num < pow(2, 64):
            return self._pack_uInt16(num)
        else:
            raise TypeError('value %d is too big' % num)


    def _pack_uInt8(self, num):
        return struct.pack("!B", num)

    def _pack_uInt16(self,num):
        return struct.pack("!H", num)

    def _pack_uInt32(self,num):
        return struct.pack("!L", num)

    def _pack_uInt64(self,num):
        return struct.pack("!Q", num)


    def unpack(self, binarydata):
        """create ECTag method #2, based upon binary data received from core """
        pass
        self._asssert()

