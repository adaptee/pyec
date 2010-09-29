
# vim: set fileencoding=utf-8 :

import time

import socket
from hashlib import md5

import codes

from tag import ECTag
from packet import ECPacket, unpack_ecpacket
from rawpacket import ECRawPacket, unpack_rawpacket_header, unpack_rawpacket_data

class ConnectionFailedError(Exception):
    def __init__(self, error):
        self.error = error
    def __str__(self):
        return repr(self.error)

def create_salted_passwd_hash(passwd, salt):

    salt = "%lX" % (salt)

    passwd_hash = md5(passwd).hexdigest()
    salt_hash   = md5(salt).hexdigest()
    return md5( (passwd_hash.lower() + salt_hash ) ).digest()


def create_ecpacket_status_req():

    return ECPacket( 'stat_req',
                     [ ECTag('detail_level', 'uint8', codes.details['cmd']),  ]
                   )

def create_ecpacket_get_connstat_req():

    return ECPacket( 'get_connstate',
                     []
                    )

def create_ecpacket_get_server_list():
    return ECPacket( 'get_server_list',
                     []
                    )

def create_ecpacket_get_log():
    return ECPacket( 'get_log',
                     []
                    )

def create_ecpacket_get_debug_log():
    return ECPacket( 'get_debuglog',
                     []
                    )

def create_ecpacket_get_serverinfo():
    return ECPacket( 'get_serverinfo',
                     []
                    )

def create_ecpacket_get_dload_queue():
    return ECPacket( 'get_dload_queue',
                     []
                    )

def create_ecpacket_get_uload_queue():
    return ECPacket( 'get_uload_queue',
                     []
                    )

def create_ecpacket_get_shared_files():
    return ECPacket( 'get_shared_files',
                     []
                    )

def create_ecpacket_shutdown_req():
    return ECPacket( 'shutdown',
                     []
                    )

def create_ecpacket_kad_start_req():
    return ECPacket( 'kad_start',
                     []
                    )

def create_ecpacket_kad_stop_req():
    return ECPacket( 'kad_stop',
                     []
                    )

def create_ecpacket_sharedfiles_reloadi_req():
    return ECPacket( 'sharedfiles_reload',
                     []
                    )

def create_ecpacket_ipfilter_relaod_req():
    return ECPacket( 'ipfilter_reload',
                     []
                    )

def create_ecpacket_add_link_req(ed2k_link):

    test_link = u"ed2k://|file|#######立花里子.link|51233|737da5cf747d2f57e5e40191052d1fae|/"

    return ECPacket( 'add_link',
                     [ ECTag('string', 'string', test_link ),   ]
                    )

def create_ecpacket_reset_log_req():
    return ECPacket( 'reset_log',
                     []
                    )

def create_ecpacket_reset_debuglog_req():
    return ECPacket( 'reset_debuglog',
                     []
                    )

def create_ecpacket_get_preferences_req():
    return ECPacket( 'get_preferences',
                     []
                    )


def create_ecpacket_get_statsgraphs_req():
    return ECPacket( 'get_statsgraphs',
                     []
                    )

def create_ecpacket_get_statstree_req():
    return ECPacket( 'get_statstree',
                     []
                    )

def create_ecpacket_connect_req():
    return ECPacket( 'connect',
                     []
                    )

def create_ecpacket_disconnect_req():
    return ECPacket( 'disconnect',
                     []
                    )

def create_ecpacket_server_connect_req():
    return ECPacket( 'server_connect',
                     []
                    )

def create_ecpacket_server_disconnect_req():
    return ECPacket( 'server_disconnect',
                     []
                    )


# core function for searching
def create_ecpacket_search_start_req(search_type, search_name):

    return ECPacket( 'search_start',
                     [ECTag('search_type', 'uint8', search_type,
                             [ECTag('search_name', 'string', search_name), ] )
                     ]
                    )

# 3 helper functions

# only search current connected ed2k server
def create_ecpacket_search_local_req(search_name):

    return create_ecpacket_search_start_req( codes.searchs['local'],
                                             search_name
                                           )

# search all ed2k servers in the server list
def create_ecpacket_search_global_req(search_name):

    return create_ecpacket_search_start_req( codes.searchs['global'],
                                             search_name
                                           )

# search the kad network
def create_ecpacket_search_kad_req(search_name):

    return create_ecpacket_search_start_req( codes.searchs['kad'],
                                             search_name
                                           )

def create_ecpacket_search_progress_req():
    return ECPacket( 'search_progress',
                     []
                    )

def create_ecpacket_search_stop_req():
    return ECPacket( 'search_stop',
                     []
                    )

def create_ecpacket_search_results_req():
    return ECPacket( 'search_results',
                     [ECTag('detail_level','uint8', codes.details['full'] ) ]
                    )




def create_ecpacket_server_disconnect_req():
    return ECPacket( 'server_disconnect',
                     []
                    )



def hexlize_hash16():
    pass

def unhexlize_hash16( hex_str):

    assert len(hex_str) == 16*2
    char_list = [ chr(int(hex_str[i] + hex_str[i+1], 16) ) for i  in range ( len (hex_str) ) if i % 2 == 0  ]

    result = ""

    for char in char_list:
        result += char

    return result


def create_ecpacket_partfile_pause_req(partfile_hash16):

    hexlized_hash16 = "FAC5B940AAEF4F7430AC6F0F68082150"

    partfile_hash16 =  unhexlize_hash16(hexlized_hash16)

    return ECPacket( 'partfile_pause',
                     [ECTag('partfile', 'hash16', partfile_hash16)]
                    )

def create_ecpacket_partfile_stop_req(partfile_hash16):

    hexlized_hash16 = "FAC5B940AAEF4F7430AC6F0F68082150"

    partfile_hash16 =  unhexlize_hash16(hexlized_hash16)

    return ECPacket( 'partfile_stop',
                     [ECTag('partfile', 'hash16', partfile_hash16)]
                    )

def create_ecpacket_partfile_resume_req(partfile_hash16):

    hexlized_hash16 = "FAC5B940AAEF4F7430AC6F0F68082150"

    partfile_hash16 =  unhexlize_hash16(hexlized_hash16)

    return ECPacket( 'partfile_resume',
                     [ECTag('partfile', 'hash16', partfile_hash16)]
                    )



create_ecpacket_partfile_pause_req


class ECConnection:
    """Remote-control aMule(d) using "External connections."""
    def __init__(self, password, host="localhost", port=4712, app="pyEC",
                       version="0.5"):
        """Connect to a running aMule(d) core.

        Parameters:
        - password (required): Password for the connection
        - host (default: "localhost"): Host where core is running
        - port (default: 4712): Port where core is running
        - app (default "pyEC"): application name transmitted on login
        - ver (default: "0.5"): application version
        """

        self.password = password
        self.host     = host
        self.port     = port
        self.app      = app
        self.version  = version

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.sock.connect((host,port))
        except (socket.error):
            raise ConnectionFailedError("Couldn't connect to socket")

        self._connect_to_amule_core()




    def _connect_to_amule_core(self):

        auth_req = self._create_ecpacket_authreq()
        auth_reply = self.send_and_recv_ecpacket(auth_req)
        print auth_reply.debugrepr()

        salt = auth_reply.subtags[0].tagdata
        saltpasswd_req = self._create_ecpacket_saltpasswd(salt)
        saltpasswd_reply = self.send_and_recv_ecpacket(saltpasswd_req)
        print saltpasswd_reply.debugrepr()

        #status_req = create_ecpacket_status_req()
        #status_reply = self.send_and_recv_ecpacket(status_req)
        #print status_reply.debugrepr()

        #get_connstat_req = create_ecpacket_get_connstat_req()
        #get_connstat_reply = self.send_and_recv_ecpacket(get_connstat_req)
        #print get_connstat_reply.debugrepr()

        #request= create_ecpacket_get_server_list ()
        #reply = self.send_and_recv_ecpacket(request)
        #print reply.debugrepr()

        #request= create_ecpacket_get_log ()
        #reply = self.send_and_recv_ecpacket(request)
        #print reply.debugrepr()

        #request= create_ecpacket_get_debug_log ()
        #reply = self.send_and_recv_ecpacket(request)
        #print reply.debugrepr()

        #request= create_ecpacket_get_serverinfo ()
        #reply = self.send_and_recv_ecpacket(request)
        #print reply.debugrepr()

        #request= create_ecpacket_get_dload_queue ()
        #reply = self.send_and_recv_ecpacket(request)
        ##print reply.debugrepr()

        #request= create_ecpacket_get_uload_queue ()
        #reply = self.send_and_recv_ecpacket(request)
        #print reply.debugrepr()

        #request= create_ecpacket_get_shared_files ()
        #reply = self.send_and_recv_ecpacket(request)
        ##print reply.debugrepr()


        #request= create_ecpacket_kad_start_req ()
        #reply = self.send_and_recv_ecpacket(request)
        #print reply.debugrepr()

        #request= create_ecpacket_kad_stop_req ()
        #reply = self.send_and_recv_ecpacket(request)
        #print reply.debugrepr()

        #request= create_ecpacket_ipfilter_relaod_req ()
        #reply = self.send_and_recv_ecpacket(request)
        #print reply.debugrepr()

        #request= create_ecpacket_sharedfiles_reloadi_req ()
        #reply = self.send_and_recv_ecpacket(request)
        #print reply.debugrepr()

        #request= create_ecpacket_add_link_req ("")
        #reply = self.send_and_recv_ecpacket(request)
        #print reply.debugrepr()


        #request= create_ecpacket_reset_log_req ()
        #reply = self.send_and_recv_ecpacket(request)
        #print reply.debugrepr()

        #request= create_ecpacket_reset_debuglog_req ()
        #reply = self.send_and_recv_ecpacket(request)
        #print reply.debugrepr()

        # FIXME
        #request= create_ecpacket_get_preferences_req ()
        #reply = self.send_and_recv_ecpacket(request)
        #print reply.debugrepr()

        # FIXME
        #request= create_ecpacket_get_statsgraphs_req ()
        #reply = self.send_and_recv_ecpacket(request)
        #print reply.debugrepr()

        #request= create_ecpacket_get_statstree_req ()
        #reply = self.send_and_recv_ecpacket(request)
        #print reply.debugrepr()


        #request= create_ecpacket_partfile_pause_req ("")
        #reply = self.send_and_recv_ecpacket(request)
        #print reply.debugrepr()

        #request= create_ecpacket_partfile_stop_req ("")
        #reply = self.send_and_recv_ecpacket(request)
        #print reply.debugrepr()

        #request= create_ecpacket_partfile_resume_req ("")
        #reply = self.send_and_recv_ecpacket(request)
        #print reply.debugrepr()

        #request= create_ecpacket_connect_req ()
        #reply = self.send_and_recv_ecpacket(request)
        #print reply.debugrepr()

        # FIXME
        #request= create_ecpacket_disconnect_req ()
        #reply = self.send_and_recv_ecpacket(request)
        #print reply.debugrepr()

        # FIXME
        #request= create_ecpacket_server_disconnect_req ()
        #reply = self.send_and_recv_ecpacket(request)
        #print reply.debugrepr()

        #request= create_ecpacket_server_connect_req ()
        #reply = self.send_and_recv_ecpacket(request)
        #print reply.debugrepr()




        request= create_ecpacket_search_local_req (u"福音战士")
        reply = self.send_and_recv_ecpacket(request)
        print reply.debugrepr()

        #request= create_ecpacket_search_global_req (u"电磁炮")
        #reply = self.send_and_recv_ecpacket(request)
        #print reply.debugrepr()

        #request= create_ecpacket_search_kad_req (u"电磁炮")
        #reply = self.send_and_recv_ecpacket(request)
        #print reply.debugrepr()

        # give core some time to do searching
        time.sleep(60)

        request= create_ecpacket_search_progress_req ()
        reply = self.send_and_recv_ecpacket(request)
        print reply.debugrepr()


        #request= create_ecpacket_search_stop_req ()
        #reply = self.send_and_recv_ecpacket(request)
        #print reply.debugrepr()

        request= create_ecpacket_search_results_req ()
        reply = self.send_and_recv_ecpacket(request)
        print reply.debugrepr()


        #request= create_ecpacket_shutdown_req ()
        #reply = self.send_and_recv_ecpacket(request)
        #print reply.debugrepr()

    def _create_ecpacket_authreq(self):

        subtags = []

        subtags.append(ECTag('client_name', 'string', self.app  ) )
        subtags.append(ECTag('client_version', 'string', self.version  ) )
        subtags.append(ECTag('protocol_version', 'uint16', codes.protocol_version  ) )
        subtags.append(ECTag('passwd_hash', 'hash16', md5(self.password).digest()  ) )

        return ECPacket('auth_req', subtags)

    def _create_ecpacket_saltpasswd(self, salt):

        salted_passwd_hash = create_salted_passwd_hash(self.password, salt)

        return ECPacket('auth_passwd',
                        [ ECTag('passwd_hash', 'hash16', salted_passwd_hash), ]
                        )


    def __del__(self):
        self.sock.close()

    def _send_data(self, data):
        self.sock.send(data)

    def send_ecpacket(self, ecpacket):
        rawpacket = ECRawPacket(ecpacket)
        self._send_data( rawpacket.pack() )

    def _recv_data(self):

        # this 8 bytes is flag + length
        header = self.sock.recv(8)
        if (not header) or (len(header) != 8):
            raise ConnectionFailedError("Invalid packet header: received %d of 8 expected bytes" % len(header))

        flag, length = unpack_rawpacket_header(header)

        rawdata = self.sock.recv(length, socket.MSG_WAITALL)
        if (not rawdata) or (len(rawdata) != length):
            raise ConnectionFailedError("Invalid packet body: received %d of %d expected bytes" % (len(rawdata), length))

        return rawdata, flag

    def recv_ecpacket(self):

        rawdata, flag = self._recv_data()

        data = unpack_rawpacket_data(rawdata, flag)

        utf8_num = (flag & codes.flags['utf8_numbers'] != 0)

        return unpack_ecpacket(data, utf8_num)

    def send_and_recv_ecpacket(self, ecpacket):
        self.send_ecpacket(ecpacket)
        return self.recv_ecpacket()


    #def search_results(self):
        #"""Get results of last search.

        #Returns a list of search results. The data for a search result is
         #stored in a dictionary with the following keys:
        #- "name": file name
        #- "size": size in Bytes
        #- "hash": file hash stored in 16 Byte
        #- "sources": number of clients sharing the file
        #- "sources_complete": number of clients sharing all parts of the file
        #"""
        #data = ECPacket((codes.op['search_results'],[]))
        #response = self.send_and_receive_packet(data)
        #return packet.decode_search(response[1])

