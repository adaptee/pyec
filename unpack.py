#!/usr/bin/env python
# vim: set fileencoding=utf-8 :

from struct import unpack

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

def unpack_uint8(data):
    return unpack_uint(data, 1)

def unpack_uint16(data):
    return unpack_uint(data, 2)

def unpack_uint32(data):
    return unpack_uint(data, 4)

def unpack_uint64(data):
    return unpack_uint(data, 8)

# note, alwasy return unicode string
def unpack_string(data):

    value = ""
    length = -1

    # In EC protocol, string is alway terminated with \x00
    length = data.find('\x00')
    value = unicode(data[:length],"utf8")

    # skip that extra \x00
    return value, data[length + 1 :]

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

def unpack_custom(data, length):

    assert len(dat) >= length

    custom = data[:needed_len]

    return custom, data[length:]

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
    return value, data[utf8_len:]


