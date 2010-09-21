#!/usr/bin/env python
# vim: set fileencoding=utf-8 :

import struct

import codes2
from pack import *
from unpack import *
from misc import indentext


class ECTag:

    def __init__ (self, tagname=None, tagtype=None, tagdata=None, subtags=None):
        self.tagname = tagname
        self.tagtype = tagtype
        self.tagdata = tagdata
        self.subtags = subtags

    def _assert(self):
        """ called befor packing, or after unpacking"""
        assert self.tagname in codes2.tags.keys()
        assert self.tagtype in codes2.tagtypes.keys()


    def debugrepr (self, indent_level=0 ):
        result = ""

        result += indentext( self._tagname_debugrepr(), indent_level)
        result += indentext( self._tagtype_debugrepr(), indent_level)

        if self.subtags:
            result += indentext( "subtags: %d\n" % len(self.subtags),
                    indent_level )
            for tag in self.subtags:
                result += tag.debugrepr(indent_level + 1)

        result += indentext (self._tagdata_debugrepr(), indent_level )
        result += "\n"

        return result

    def _tagname_debugrepr(self):
        tagnamecode = codes2.tags[self.tagname]

        return "tagname: %s | %s \n" % ( self.tagname, hex(tagnamecode) )

    def _tagtype_debugrepr(self):
        tagtypecode = codes2.tagtypes[self.tagtype]

        return "tagtype: %s | %s \n" % ( self.tagtype, hex(tagtypecode) )

    def _tagdata_debugrepr(self):

        # since strings are always stored as unicode string,
        # special treatment is need here.
        if self.tagtype == 'string':
            #return self.tagdata
            return unicode.encode(self.tagdata, "utf-8")
        else:
            return str(self.tagdata)

    def setname(self, tagname):
        assert tagname in codes2.tags.keys()
        self.tagname = tagname

    def settype(self, tagtype):

        assert tagtype in codes2.tagtypes.keys()
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

    def pack(self):
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
        return pack_uint8(codes2.tagtypes[self.tagtype])

    def _pack_subtags(self):

        result = ""

        if self.subtags:
            count = len(self.subtags)
            result += pack_uint16(count)
            for subtag in self.subtags:
                result += subtag.pack()

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


def unpack_ectag(data, utf8_num=True):

    tagname, data = unpack_ectag_tagname(data, utf8_num)
    tagname, has_subtags, subtags = analyze_ectag_tagname(tagname)

    tagtype, data = unpack_tagtype(data)

    taglen,  data = unpack_ectag_taglen(data, utf8_num)

    consumed_len = 0

    if has_subtags :

        tagcount, data = unpack_ectag_tagcount(data, utf8_num)

        # filed tagcount always consumes 2 bytes
        consumed_len += 2

        for i in range(tagcount):
            subtag, data, advance = unpack_ectag(data, utf8_num)
            subtags.append(subtag)
            consumed_len += advance

    tagdata_len = taglen - consumed_len

    tagdata, data = unpack_ectag_tagdata(data, tagtype, tagdata_len)

    tagname =  codes2.tags_rev[tagname]
    tagtype =  codes2.tagtypes_rev[tagtype]

    tag = ECTag(tagname, tagtype, tagdata, subtags)

    # tagname: 4 bytes, tagtype:1 bytes, taglen: 4 bytes
    return tag, data, taglen + 2 + 1 + 4


def analyze_ectag_tagname(tagname):
    # if the lowest bit set, then this tag contins subtags
    if (tagname % 2) == 1:
        has_subtags = True
        subtags = [ ]
    else:
        has_subtags = False
        subtags = None

    return tagname/2, has_subtags, subtags

# uint16 need to take care of utf-8-lized number
def unpack_ectag_tagname(data, utf8_num=True):

    value  = -1
    length = -1

    if utf8_num:
        return unpack_utf8_num(data)
    else:
        length = 2
        value, = unpack( '!H', data[:length] )
        return value, data[length:]

# FIXME; this could be optimized as simply ' return  data[0], 1'
def unpack_tagtype(data):
    value  = -1
    length = 1

    value, _ = unpack_uint8(data)

    return value, data[length:]

# uint32 need to take care of utf-8-lized number
def unpack_ectag_taglen(data, utf8_num=True ):
    value  = -1
    length = -1

    if utf8_num:
        return unpack_utf8_num(data)
    else:
        length = 4
        value, _ = unpack_uint32(data)
        return value, data[length:]


def unpack_ectag_tagcount(data, utf8_num=True ):

    if utf8_num:
        return unpack_utf8_num(data)
    else:
        length = 2
        value, _ = unpack_uint16( data )
        return value, data[length:]


def unpack_ectag_tagdata(data, tagtype, length):

    value  = -1

    if tagtype in [ codes2.tagtypes['uint8'] ,
                    codes2.tagtypes['uint16'],
                    codes2.tagtypes['uint32'],
                    codes2.tagtypes['uint64'] ]:

        #length = 1
        #if tagtype == codes2.tagtypes['uint16']:
            #length = 2
        #elif tagtype == codes2.tagtypes['uint32']:
            #length = 4
        #elif tagtype == codes2.tagtypes['uint64']:
            #length = 8

        value, data = unpack_uint(data, length)

    elif tagtype == codes2.tagtypes['string']  :
        value, data = unpack_string(data)

    elif tagtype == codes2.tagtypes['hash16']:
        value, data = unpack_hash16(data)

    elif tagtype == codes2.tagtypes['ipv4']:
        value, data = unpack_ipv4(data)

    elif tagtype == codes2.tagtypes['double']:
        value, data = unpack_double(data)

    elif tagtype == codes2.tagtypes['custom']:
        raise ValueError("[unpack_ectag_tagdata] type 'custom' is unsupported ")
        #value, data = unpack_custom(data, length)

    elif tagtype == codes2.tagtypes['unknown']:
        raise ValueError("[unpack_ectag_tagdata] type 'unkonwn' is unsupported ")

    return value, data


