#!/usr/bin/env python
# vim: set fileencoding=utf-8 :

from struct import unpack
from codes2 import tags_rev
from tagtypes2 import tagtypes, tagtypes_rev
from tag2 import ECTag
from packet2 import ECPacket



def unpack_packet(data, utf8_num=True ):

    op, data       = unpack_op(data)

    op = codes2.ops_rev[op]

    tagcount, data = unpack_tagcount(data, utf8_num)

    tags = [ ]

    for i in range(tagcount):
        tag, data = unpack_tag(data, utf8_num)
        tags.append(tag)

    assert len(data) == 0

    return ECPacket( op, tags)


def unpack_op(data):
    length =  1
    value, = unpack("!B",data[length:])

    return value, data[length:]

def unpack_tagcount(data, utf8_num=True ):

    value  = -1
    length = -1

    if utf8_num:
        #value, length = unpack_utf8_num(data)
        return unpack_utf8_num(data)
    else:
        length = 2
        value, = unpack( '!H', data[:length] )
        return value, data[length:]



def unpack_tag(data, utf8_num=True):

    tagname, data = unpack_tagname(data, utf8_num)

    tagname, has_subtags, subtags = analyze_tagname(tagname)

    tagtype, data = unpack_tagtype(data)

    taglen, data = unpack_taglength(data, utf8_num)

    if has_subtags :

        subtags_count, data = unpack_subtags_count(data, utf8_num)

        for i in range(subtags_count):
            subtag, data = unpack_tag(data, utf8_num)
            subtags.append(subtag)

    tagdata, data = unpack_tagdata(data, tagtype)

    tagname =  tags_rev[tagname]
    tagtype =  tagtypes_rev[tagtype]

    tag = ECTag(tagname, tagtype, tagdata, subtags)

    return tag, data


def analyze_tagname(tagname):
    # if the lowest bit set, then subtags exist
    if (tagname % 2) == 1:
        has_subtags = True
        subtags = [ ]
    else:
        has_subtags = False
        subtags = None

    return tagname / 2, has_subtags, subtags

# uint16 need to take care of utf-8-lized number
def unpack_tagname(data, utf8_num=True):

    value  = -1
    length = -1

    if utf8_num:
        #value, length = unpack_utf8_num(data)
        return unpack_utf8_num(data)
    else:
        length = 2
        value, = unpack( '!H', data[:length] )
        return value, data[length:]

# FIXME; this could be optimized as simply ' return  data[0], 1'
def unpack_tagtype(data):
    value  = -1
    length = 1

    value, = unpack('!B', data[:length])

    return value, data[length:]

# uint32 need to take care of utf-8-lized number
def unpack_taglength(data, utf8_num=True ):
    value  = -1
    length = -1

    if utf8_num:
        #value, length = unpack_utf8_num(data)
        return unpack_utf8_num(data)
    else:
        length = 4
        value, = unpack( '!L', data[:length] )
        return value, data[length:]


def unpack_subtags_count(data, utf8_num=True ):
    value  = -1
    length = -1

    if utf8_num:
        #value, length = unpack_utf8_num(data)
        return unpack_utf8_num(data)
    else:
        length = 2
        value, = unpack( '!H', data[:length] )
        return value, data[length:]

def unpack_tagdata(data, tagtype):

    value  = -1
    length = -1

    if tagtype in [ tagtypes['uint8'] ,
                    tagtypes['uint16'],
                    tagtypes['uint32'],
                    tagtypes['uint64'] ]:

        length = 1
        if tagtype == tagtypes['uint16']:
            length = 2
        elif tagtype == tagtypes['uint32']:
            length = 4
        elif tagtype == tagtypes['uint64']:
            length = 8

        value, data = unpack_uint(data, length)

    elif tagtype == tagtypes['string']  :
        value, data = unpack_string(data)

    elif tagtype == tagtypes['hash16']:
        value, data = unpack_hash16(data)

    elif tagtype == tagtypes['ipv4']:
        value, data = unpack_ipv4(data)

    elif tagtype == tagtypes['double']:
        value, data = unpack_double(data)

    elif tagtype == tagtypes['custom']:
        raise ValueError("[unpack_tagdata] type 'custom' is unsupported ")

    elif tagtype == tagtypes['unknown']:
        raise ValueError("[unpack_tagdata] type 'unkonwn' is unsupported ")

    return value, data


#def unpack_uint(data):
def unpack_uint(data, length):

    assert len(data) >= length

    value = -1

    fmtstrs = { 1:'!B',
                2:'!H',
                4:'!L',
                8:'!Q'
              }

    fmtstr = fmtstrs.get(length, "")

    if fmtstr :
        value, = unpack(fmtstr, data[:length])
    else:
        raise ValueError("[unpack_uint]: Wrong length for number: %d [%s]"
                %(len(data),repr(data)))

    return value, data[length:]


def unpack_string(data):
    value = ""
    length = -1

    length = data.find('\x00')
    value = unicode(data[:length],"utf8")

    return value, data[length:]

def unpack_hash16(data):

    length = 16

    if len(data) < length:
        raise ValueError("[unpack_hash16] Expected length 16, got length %d"
                        % (len(data)) )

    return data, data[length:]

def unpack_ipv4(data):

    length = 6
    assert len(data) >= length

    ipv4, port = unpack("!IH", data[:6])
    p1 = (ipv4 & 0xff000000) >> 24
    p2 = (ipv4 & 0xff0000) >> 16
    p3 = (ipv4 & 0xff00) >> 8
    p4 = ipv4 & 0xff

    value =  "%d.%d.%d.%d:%d"% (p1, p2, p3, p4, port)

    return value, data[length:]

def unpack_double(data):
    return unpack_string(data)

#def unpack_custom(data):
    #return data, len(data)

def unpack_utf8_num(data):

    value = -1
    utf8_len = -1

    if ord(data[0]) in range(0x7F):
        utf8_len = 1
    elif ord(data[0]) in range(0xc3, 0xdf):
        utf8_len = 2
    elif ord(data[0]) in range(0xe0, 0xef):
        utf8_len = 3
    else:
        raise ValueError("%s not a valid unicode range" % hex(ord(data[0])))

    value = ord( data[:utf8_len].decode("utf-8"))
    #return value, utf8_len
    return value, data[utf8_len:]


