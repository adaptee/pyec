#!/usr/bin/env python
# vim: set fileencoding=utf-8 :

from pack import *
from unpack import *
from tag2 import ECTag, unpack_ectag


def test_pack_string_success():
    print pack_string(u'test')
    assert pack_string(u'test') == 'test\x00'

def test_pack_hash_success():
    print pack_hash('0123456789abcdef')
    assert pack_hash('0123456789abcdef') == '0123456789abcdef'

def test_pack_hash_failure():
    try:
        pack_hash('too short')
    except ValueError:
        pass

def test_pack_uint8_success():
    print pack_uint8(127)
    assert pack_uint8(127) == '\x7F'

def test_pack_uint16_success():
    print pack_uint16(31000)
    assert pack_uint16(31000) == '\x79\x18'

##################################

def test_pack_uint32():
    print pack_uint32(4000000)
    assert pack_uint32(4000000) == '\x00\x3d\x09\x00'

def test_pack_uint64():
    print pack_uint64(80000000000000000L)
    assert pack_uint64(80000000000000000L) == '\x01\x1c\x37\x93\x7e\x08\x00\x00'

def test_unpack_uint8():
    test_in = 73
    test_bin = pack_uint8(test_in)
    test_out, _ = unpack_uint(test_bin, 1)
    assert test_out == test_in

def test_unpack_uint16():
    test_in = 14092
    test_bin = pack_uint16(test_in)
    test_out, _ = unpack_uint(test_bin, 2)
    assert test_out == test_in

def test_unpack_uint32():
    test_in = 312353512
    test_bin = pack_uint32(test_in)
    test_out,_ = unpack_uint(test_bin, 4)
    assert test_out == test_in

def test_unpack_uint64():
    test_in = 8414561238214513L
    test_bin = pack_uint64(test_in)
    test_out, _ = unpack_uint(test_bin, 8)
    assert test_out == test_in

def test_unpack_uint_invalid():
    test_data = "\xFF\xFF\xFF"
    try:
        unpack_uint(test_data, 3)
    except ValueError:
        pass


def test_unpack_string():
    test_in = u'Die Welt ist rund.'
    test_bin = pack_string(test_in)
    test_out, length = unpack_string(test_bin, len(test_bin) )
    assert test_out == test_in


def test_unpack_hash():
    test_in = 'abcdef0123456789'
    test_bin = pack_hash(test_in)
    test_out, length = unpack_hash(test_bin)
    assert test_out == test_in

def test_unpack_ipv4():
    test_in = '192.168.1.37:9527'
    test_bin = pack_ipv4(test_in)
    test_out, length = unpack_ipv4(test_bin, len(test_bin) )
    assert test_out == test_in
    print test_out


def test_pack_unpack_single_tag():
    # name --> 0x101 257
    # type --> 6
    # data --> SVN
    tag_in = ECTag('client_version', 'string', u'SVN')

    tag_bin = tag_in.pack()

    tag_out, len, _ = unpack_ectag(tag_bin, False)

    assert tag_in.tagname == tag_out.tagname
    print tag_out.tagname, tag_out.tagtype, tag_out.tagdata


def test_pack_unpack_complex_tag():

    subtag1 = ECTag('client_hash', 'hash16', '1234567890abcdef')
    subtag2 = ECTag('server_address', 'ipv4', "192.168.1.37:9527")
    subtag3 = ECTag('server_users', 'uint32', 0x5a5a)

    subtags = [ subtag1, subtag2, subtag3]
    maintag  = ECTag('server', 'string', "aMule Server No2", subtags)

    maintag_bin = maintag.pack()


    maintag_out ,length, _  = unpack_ectag(maintag_bin, False)


    print "tagname: %s" % maintag_out.tagname
    print "tagtype: %s" % maintag_out.tagtype
    print "tagdata: %s" % maintag_out.tagdata

    print "debug representation of maintag\n"
    print maintag_out.debugrepr()




test_pack_string_success()
test_pack_hash_success()
test_pack_hash_failure()
test_pack_uint8_success()
test_pack_uint16_success()
test_pack_uint32()
test_pack_uint64()

test_unpack_uint8()
test_unpack_uint16()
test_unpack_uint32()
test_unpack_uint64()
test_unpack_uint_invalid()
test_unpack_string()
test_unpack_ipv4()

test_pack_unpack_single_tag()
test_pack_unpack_complex_tag()
