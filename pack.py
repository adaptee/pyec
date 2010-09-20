#!/usr/bin/env python
# vim: set fileencoding=utf-8 :

from struct import pack

def ipv4addr2num(addr):

    ip, port = addr.split(':')

    parts = ip.split('.')

    ip = 0
    for part in parts:
        ip = ip * 256 + int(part)

    port = int(port)

    return ip, port


def pack_string(data):
    data += u'\0'
    return unicode.encode(data,"utf-8")

def pack_hash(hash):

    if len(hash) != 16:
        raise ValueError('[pack_hash] length of hash is not 16 bytes')

    return hash

def pack_ipv4(ipv4addr):

    ipv4, port = ipv4addr2num(ipv4addr)

    return pack("!LH", ipv4, port)

def pack_double(double):
    return double

def pack_uint(number, tagtype):

    fmtstrs = { 'uint8' : '!B',
                'uint16': '!H',
                'uint32': '!L',
                'uint64': '!Q'
              }

    fmtstr = fmtstrs.get(tagtype, "")

    if fmtstr :
        value = pack(fmtstr, number)
    else:
        raise ValueError("[pack_uint]: %s is not supported " % number)

    return value

def pack_uint8(number):
    return pack_uint(number, 'uint8')

def pack_uint16(number):
    return pack_uint(number, 'uint16')

def pack_uint32(number):
    return pack_uint(number, 'uint32')

def pack_uint64(number):
    return pack_uint(number, 'uint64')

