#!/usr/bin/env python
# vim: set fileencoding=utf-8 :

from tag import ECTag

def test_ECTag_0():

    # name -> 0x101
    # type -> uint8(2)
    # data -> 123
    tag = ECTag("client_version","uint8",123 )

    result = tag.pack()
    assert result ==  '\x02\x02\x02\x00\x01{'

    print "#OK"
    return tag

def ECTags_generator ( ):

    metadata = [ ('version_id','uint16', 0x203) ,
                 ('client_id','uint32', 1231231) ,
                 ('ed2k_id', 'uint32', 1100471773),
                 #('id', 'string', 'HighID'),
                 #('kad','string', 'connected'),
                 #('kad_firewall', 'string', 'ok'),
                 #('server_address','ipv4', '212.63.206.35:4242'),
                 ('server_name', 'string', u'eDoneyServer No2')
               ]

    for item in metadata:
        tagname, tagtype, tagdata = item
        tag = ECTag_creator(tagname, tagtype, tagdata)


def ECTag_creator( tagname, tagtype, tagdata):

    tag = ECTag(tagname, tagtype, tagdata)

    result=tag.pack()
    print result
    print "#OK with [%s, %s, %s ]" % (tagname, tagtype, tagdata)
    return tag

ECTags_generator()

