#!/usr/bin/env python
# vim: set fileencoding=utf-8 :

import struct

import codes2
from pack import pack_uint8, pack_uint16, pack_uint32, pack_uint, \
                 pack_string, pack_double, pack_ipv4, pack_hash16
from unpack import unpack_uint8, unpack_uint16, unpack_uint32, unpack_uint, \
                   unpack_string, unpack_double, unpack_ipv4, unpack_hash16,\
                   unpack_custom, unpack_unknown, unpack_utf8_num

from misc import indentext


class ECTag:

    def __init__ (self, tagname=None, tagtype=None, tagdata=None, subtags=[ ] ):
        self.tagname = tagname
        self.tagtype = tagtype
        self.tagdata = tagdata
        self.subtags = subtags

    def assertself(self):
        """ called befor packing, or after unpacking"""
        assert self.tagname in codes2.tags.keys()
        assert self.tagtype in codes2.tagtypes.keys()
        for subtag in self.subtags:
            subtag.assertself()

    def addtag(self, subtag):
        self.subtags.append(subtag)

    def gettagsbyname(self, tagname):
        """get all tags matching specified tagname"""

        result = [ ]

        if self.subtags:
            for subtag in self.subtags:
                result.extend( subtag.gettagsbyname(tagname) )
        elif self.tagname == tagname :
            result.append(self)
        else:
            pass

        return result

    def pack(self):
        """create binary representatio of this ECTag, which is used in
        communication"""
        self.assertself()

        result = ""

        result += self._pack_name()
        result += self._pack_type()

        subtags_bin = self._pack_subtags()
        tagdata_bin = self._pack_data()

        taglen = len(subtags_bin) + len(tagdata_bin)
        result += pack_uint32(taglen)

        result += self._pack_count()
        result += subtags_bin
        result += tagdata_bin

        return result

    def _pack_name(self):

        tagname = codes2.tags[self.tagname]

        if self.subtags :
            tagname = tagname * 2 + 1
        else:
            tagname = tagname * 2

        # FIXME : should we alwasy send utf-8-lized number, instead?
        return pack_uint16(tagname)

    # tagtype should use 1 byte
    def _pack_type(self):
        return pack_uint8(codes2.tagtypes[self.tagtype])

    def _pack_count(self):
        result = ""

        if self.subtags :
            result +=  pack_uint16( len(self.subtags) )

        return result

    def _pack_subtags(self):

        result = ""

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
            result += pack_hash16(tagdata)
        elif tagtype == 'ipv4':
            result += pack_ipv4(tagdata)
        elif tagtype == 'double':
            result += pack_double(tagdata)
        else:
            raise ValueError("type %s is not supported yet" % tagtype)

        return result


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

        # strings are always stored as unicode string,
        # special treatment is need for them.
        if self.tagtype == 'string':
            #return self.tagdata
            return "tagdata: %s " % unicode.encode(self.tagdata, "utf-8")
        else:
            return "tagdata: %s " % str(self.tagdata)

def unpack_ectag(data, utf8_num=True):

    tagname, data = unpack_ectag_tagname(data, utf8_num)
    #tagname, has_subtags, subtags = analyze_ectag_tagname(tagname)
    tagname, has_subtags = analyze_ectag_tagname(tagname)

    tagtype, data = unpack_tagtype(data)

    taglen,  data = unpack_ectag_taglen(data, utf8_num)

    consumed_len = 0

    subtags = [ ]

    if has_subtags :

        tagcount, data = unpack_ectag_tagcount(data, utf8_num)

        # CATCH! the value of field taglen did not take optional field tagcount
        # into consideration
        # consumed_len += 2

        for i in range(tagcount):
            subtag, data, advance = unpack_ectag(data, utf8_num)
            subtags.append(subtag)
            consumed_len += advance

    tagdata_len = taglen - consumed_len

    tagdata, data = unpack_ectag_tagdata(data, tagtype, tagdata_len)

    tagname =  codes2.tags_rev[tagname]
    tagtype =  codes2.tagtypes_rev[tagtype]

    tag = ECTag(tagname, tagtype, tagdata, subtags)

    #print tag.debugrepr()
    tag.assertself()

    # tagname: 2 bytes
    # tagtype: 1 bytes
    # taglen:  4 bytes
    # tagcount : optional 2 bytes
    return tag, data, taglen + 2 + 1 + 4 + ( 2 if has_subtags else 0 )


def analyze_ectag_tagname(tagname):
    # if the lowest bit set, then this tag contins subtags
    if (tagname % 2) == 1:
        has_subtags = True
    else:
        has_subtags = False

    return tagname/2, has_subtags

# uint16 need to take care of utf-8-lized number
def unpack_ectag_tagname(data, utf8_num=True):

    value  = -1
    length = -1

    if utf8_num:
        return unpack_utf8_num(data)
    else:
        length = 2
        #value, = unpack( '!H', data[:length] )
        value, _ = unpack_uint16( data )
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

        value, data = unpack_uint(data, length)

    elif tagtype == codes2.tagtypes['string']  :
        value, data = unpack_string(data, length)

    elif tagtype == codes2.tagtypes['hash16']:
        value, data = unpack_hash16(data, length)

    elif tagtype == codes2.tagtypes['ipv4']:
        value, data = unpack_ipv4(data, length)

    elif tagtype == codes2.tagtypes['double']:
        value, data = unpack_double(data, length)

    elif tagtype == codes2.tagtypes['custom']:
        #raise ValueError("[unpack_ectag_tagdata] type 'custom' is unsupported ")
        value, data = unpack_custom(data, length)

    elif tagtype == codes2.tagtypes['unknown']:
        value, data = unpack_unknown(data, length)
    else:
        raise ValueError("invalid data type %d " % tagtype)

    return value, data


