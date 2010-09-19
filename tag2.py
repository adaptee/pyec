#!/usr/bin/env python
# vim: set fileencoding=utf-8 :


import codes2

from tagtypes2 import tagtypes
#from pack import pack_number, pack_hash, pack_string, pack_double, pack_ipv4
from pack import *


class ECTag:

    def __init__ (self, tagname=None, tagtype=None, tagdata=None, subtags=None):
        self.tagname = tagname
        self.tagtype = tagtype
        self.tagdata = tagdata
        self.subtags = subtags

    def _assert(self):
        """ called befor packing, or after unpacking"""
        assert self.tagname in codes2.tags.keys()
        assert self.tagtype in tagtypes.keys()


    def debugrepr (self):
        result = ""
        result += "tagname: %s\n" % self.tagname
        result += "tagtype: %s\n" % self.tagtype

        if self.subtags:
            for tag in self.subtags:
                result += tag.debugrepr()

        result += "tagdata: %s\n" % str(self.tagdata)

        return result

    def setname(self, tagname):
        assert tagname in codes2.tags.keys()
        self.tagname = tagname

    def settype(self, tagtype):

        assert tagtype in tagtypes.keys()
        self.tagtype = tagtype

    def setdata(self, tagdata):
        """create ECTag method #1, based upon readable data from ourside """

        self.tagdata = tagdata

    def setsubtags(self, subtags):
        self.subtags = subtags

    def addsubtag(self, subtag):
        if not self.subtags:
            self.subtags = [ ]
        self.subtags.append(subtag)

    def packup(self):
        """create the binary representatio of this ECTag, which is used in
        communication"""
        self._assert()

        result = ""

        result += self._pack_name()
        result += self._pack_type()

        subtags = self._pack_subtags()
        tagdata = self._pack_data()

        length = len(subtags) + len(tagdata)
        result += pack_uint32(length)

        result += subtags
        result += tagdata

        return result

    def _pack_name(self):

        tagname = codes2.tags[self.tagname]

        if self.subtags :
            tagname = tagname * 2 + 1
        else:
            tagname = tagname * 2

        # FIXME : should we alwasy send utf-8-lized number, instead?
        return pack_uint16(tagname)

    def _pack_type(self):
        return pack_uint8(tagtypes[self.tagtype])

    def _pack_subtags(self):

        result = ""

        if self.subtags:
            count = len(self.subtags)
            result += pack_uint16(count)
            for subtag in self.subtags:
                result += subtag.packup()

        return result

    def _pack_data(self):

        result = ""
        tagtype = self.tagtype
        tagdata = self.tagdata

        if  tagtype in ('uint8', 'uint16', 'uint32', 'uint64'):
            result += pack_uint(tagdata, tagtype)
        elif tagtype == 'string':
            result += pack_string(tagdata)
        elif tagtype == 'hash16':
            result += pack_hash(tagdata)
        elif tagtype == 'ipv4':
            result += pack_ipv4(tagdata)
        elif tagtype == 'double':
            result += pack_double(tagdata)
        else:
            raise ValueError("[_pack_data] type %s is not supported yet"
                             % tagtype)

        return result

