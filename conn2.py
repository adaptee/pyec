#from .packet import ECLoginPacket, ECPacket, ReadPacketData
#from struct import unpack
import socket
from hashlib import md5

import codes2

from tag2 import ECTag
from packet2 import ECPacket, unpack_ecpacket
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
                     [ ECTag('detail_level', 'uint8', codes2.details['cmd']),  ]
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

def create_ecpacket_get_shared_files():
    return ECPacket( 'get_shared_files',
                     []
                    )


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
        pass

        auth_req = self._create_ecpacket_authreq()
        auth_reply = self.send_and_recv_ecpacket(auth_req)
        print auth_reply.debugrepr()

        salt = auth_reply.tags[0].tagdata
        #print "[debug] salt: %s" % salt
        saltpasswd_req = self._create_ecpacket_saltpasswd(salt)
        saltpasswd_reply = self.send_and_recv_ecpacket(saltpasswd_req)
        print saltpasswd_reply.debugrepr()

        status_req = create_ecpacket_status_req()
        status_reply = self.send_and_recv_ecpacket(status_req)
        print status_reply.debugrepr()

        get_connstat_req = create_ecpacket_get_connstat_req()
        get_connstat_reply = self.send_and_recv_ecpacket(get_connstat_req)
        print get_connstat_reply.debugrepr()

        request= create_ecpacket_get_server_list ()
        reply = self.send_and_recv_ecpacket(request)
        print reply.debugrepr()

        request= create_ecpacket_get_log ()
        reply = self.send_and_recv_ecpacket(request)
        print reply.debugrepr()

        request= create_ecpacket_get_debug_log ()
        reply = self.send_and_recv_ecpacket(request)
        print reply.debugrepr()

        request= create_ecpacket_get_serverinfo ()
        reply = self.send_and_recv_ecpacket(request)
        print reply.debugrepr()

        #FIXME
        #request= create_ecpacket_get_dload_queue ()
        #reply = self.send_and_recv_ecpacket(request)
        #print reply.debugrepr()

        # FIXME
        request= create_ecpacket_get_shared_files ()
        reply = self.send_and_recv_ecpacket(request)
        #print reply.debugrepr()


    def _create_ecpacket_authreq(self):
        pass

        tags = []

        tags.append(ECTag('client_name', 'string', self.app  ) )
        tags.append(ECTag('client_version', 'string', self.version  ) )
        tags.append(ECTag('protocol_version', 'uint16', codes2.protocol_version  ) )
        tags.append(ECTag('passwd_hash', 'hash16', md5(self.password).digest()  ) )

        return ECPacket('auth_req', tags)

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

        utf8_num = (flag & codes2.flags['utf8_numbers'] != 0)

        return unpack_ecpacket(data, utf8_num)

    def send_and_recv_ecpacket(self, ecpacket):
        self.send_ecpacket(ecpacket)
        return self.recv_ecpacket()



    #def get_status(self):
        #"""Get status information from remote core.

        #Returns a dictionary with the following keys:
        #- "ul_speed": upload speed in Bytes/s
        #- "dl_speed": download speed in Bytes/s
        #- "ul_limit": upload limit, 0 is unlimited
        #- "dl_limit": download limit, 0 is unlimited
        #- "queue_len": number of clients waiting in the upload queue
        #- "src_count": number of download sources
        #- "ed2k_users": users in the eD2k network
        #- "kad_users": users in the kademlia network
        #- "ed2k_files": files in the eD2k network
        #- "kad_files": files in the kademlia network
        #- "connstate": connection status, dictionary with the following keys:
            #- "ed2k": ed2k network status. possible values: "connected", "connecting", "Not connected"
            #- "kad": kademlia network status. possible values: "connected", "Not connected", "Not running"
            #- "server_addr": server address in ip:port format
            #- "ed2k_id": identification number for the ed2k network
            #- "client_id": identification number for the kademlia network
            #- "id": connection status. possible values: "LowID", "HighID", ""
            #- "kad_firewall": kademlia status. possible values: "ok", "firewalled", ""

        #"""
        #data = ECPacket((codes.op['stat_req'], [(codes.tag['detail_level'], codes.detail['cmd'])]))
        #response = self.send_and_receive_packet(data)
        ## structure: (op['stats'], [(tag['stats_ul_speed'], 0), (tag['stats_dl_speed'], 0), (tag['stats_ul_speed_limit'], 0), (tag['stats_dl_speed_limit'], 0), (tag['stats_ul_queue_len'], 0), (tag['stats_total_src_count'], 0), (tag['stats_ed2k_users'], 3270680), (tag['stats_kad_users'], 0), (tag['stats_ed2k_files'], 279482794), (tag['stats_kad_files'], 0), (tag['connstate'], ((connstate, [subtags])))])
        #return packet.decode_status(response[1])


    #def get_connstate(self):
        #"""Get connection status information from remore core.

        #Returns a dictionary with the following keys:
        #- "ed2k": ed2k network status. possible values: "connected", "connecting", "Not connected"
        #- "kad": kademlia network status. possible values: "connected", "Not connected", "Not running"
        #- "server_addr": server address in ip:port format
        #- "ed2k_id": identification number for the ed2k network
        #- "client_id": identification number for the kademlia network
        #- "id": connection status. possible values: "LowID", "HighID", ""
        #- "kad_firewall": kademlia status. possible values: "ok", "firewalled", ""
        #"""
        #data = ECPacket((codes.op['get_connstate'], [(codes.tag['detail_level'], codes.detail['cmd'])]))
        #response = self.send_and_receive_packet(data)
        ## structure: (op['misc_data'], [(tag['connstate'], (connstate, [subtags]))])
        #connstate = response[1][0][1][0]
        #subtags = response[1][0][1][1]
        #return packet.decode_connstate(connstate, subtags)

    #def shutdown(self):
        #"""Shutdown remote core"""
        #data = ECPacket((codes.op['shutdown'],[]))
        #self.send_packet(data)

    #def connect(self):
        #"""Connect remote core to activated networks.

        #Returns a tuple with a boolean indicating success and a list of strings
         #with status messages."""
        #data = ECPacket((codes.op['connect'],[]))
        #response = self.send_and_receive_packet(data)
        ## (op['failed'], [(tag['string'], u'All networks are disabled.')])
        ## (op['strings'], [(tag['string'], u'Connecting to eD2k...'), (tag['string'], u'Connecting to Kad...')])
        #return (response[0] != codes.op['failed'], map(lambda s:s[1],response[1]))

    #def connect_server(self):
        #"""Connect remote core to eD2k network.

        #Returns a boolean indicating success."""
        #data = ECPacket((codes.op['server_connect'],[]))
        #response = self.send_and_receive_packet(data)
        #return response[0] != codes.op['failed']

    #def connect_kad(self):
        #"""Connect remote core to kademlia network.

        #Returns a boolean indicating success."""
        #data = ECPacket((codes.op['kad_start'],[]))
        #response = self.send_and_receive_packet(data)
        #return response[0] != codes.op['failed']

    #def disconnect(self):
        #"""Disconnect remote core from networks.

        #Returns a tuple with a boolean indicating success and a list of strings
         #with status messages."""
        ## (op['noop'], [])
        ## (op['strings'], [(tag['string'], u'Disconnected from eD2k.'), (tag['string'], u'Disconnected from Kad.')])
        #data = ECPacket((codes.op['disconnect'],[]))
        #response = self.send_and_receive_packet(data)
        #return (response[0] == codes.op['strings'], map(lambda s:s[1],response[1]))

    #def disconnect_server(self):
        #"""Disconnect remote core from eD2k network."""
        #data = ECPacket((codes.op['server_disconnect'],[]))
        #response = self.send_and_receive_packet(data)

    #def disconnect_kad(self):
        #"""Disconnect remote core from kademlia network."""
        #data = ECPacket((codes.op['kad_stop'],[]))
        #response = self.send_and_receive_packet(data)

    #def reload_shared(self):
        #"""Reload shared files on remote core."""
        #data = ECPacket((codes.op['sharedfiles_reload'],[]))
        #response = self.send_and_receive_packet(data)

    #def reload_ipfilter(self):
        #"""Reload ipfilter on remote core."""
        #data = ECPacket((codes.op['ipfilter_reload'],[]))
        #response = self.send_and_receive_packet(data)

    #def get_shared(self):
        #"""Get list of shared files.

        #Returns a list of shared files. The data for a file is stored in a
         #dictionary with the following keys:
        #- "name": file name
        #- "size": size in Bytes
        #- "link": eD2k link to the file
        #- "hash": file hash stored in 16 Byte
        #- "prio": upload priority, Auto is prefixed by 1, e.g. 12 is Auto (High)
            #- 4: Very Low
            #- 0: Low
            #- 1: Normal
            #- 2: High
            #- 3: Very High
            #- 6: Release
        #- "aich": file's AICH hash (see: http://wiki.amule.org/index.php/AICH)
        #- "part_status": unknown
        #- "uploaded": Bytes uploaded during the current session
        #- "uploaded_total": total Bytes uploaded
        #- "requests": number of requests for this file during the current session
        #- "requests_total": total number of requests for this file
        #- "accepted": number of accepted requests for this file during the current session
        #- "accepted_total": total number of accepted requests for this file
        #"""
        #data = ECPacket((codes.op['get_shared_files'],[]))
        #response = self.send_and_receive_packet(data)
        #return packet.decode_shared(response[1])

    #def search_local(self, keywords):
        #"""Start a kad search.

        #See function "search" for further details."""
        #return self.search(codes.search['local'],keywords)

    #def search_global(self, keywords):
        #"""Start a kad search.

        #See function "search" for further details."""
        #return self.search(codes.search['global'],keywords)

    #def search_kad(self, keywords):
        #"""Start a kad search.

        #See function "search" for further details."""
        #return self.search(codes.search['kad'],keywords)


    #def search(self, type, keywords):
        #"""Start a search.

        #Returns a tuple consisting of a boolean value indicating success and
        #a string with aMule's answer.

        #Type is one of local (0x00), global (0x01) and kad (0x02), denoting the
         #scope of the search.
        #"local" queries only the connected server, "global" all servers in the
         #server list and "kad" starts a search in the kad network.
        #Usage of the helper functions "search_local", "search_global" and
         #"search_kad" is recommended.

        #Keywords is a string of words for which to search.
        #"""
        #packet = (codes.op['search_start'], \
            #[(codes.tag['search_type'],(type, \
                #[(codes.tag['search_name'],unicode(keywords))] \
            #))] \
        #)
        #data = ECPacket(packet)
        #response = self.send_and_receive_packet(data)
        #answer = response[1][0][1]
        #not_connected = (answer == u'Search in progress. Refetch results in a moment!')
        #return (not_connected, answer)

    #def search_progress(self):
        #"""Doesn't work correctly, don't use it.
        #"""
        #data = ECPacket((codes.op['search_progress'],[]))
        #response = self.send_and_receive_packet(data)
        #print repr(response)

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

    #def add_link(self, link):
        #"""Add link to aMule core.

        #Returns True when the link was added and False if the link is invalid.
        #"""
        #data = ECPacket((codes.op['add_link'],[(codes.tag['string'],unicode(link))]))
        #response = self.send_and_receive_packet(data)
        #print (response[0] != codes.op['failed'])
