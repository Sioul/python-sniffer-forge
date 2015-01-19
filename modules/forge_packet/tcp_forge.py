#!/usr/bin/python3

#from ..packet_info_container import PacketInfoContainer
import socket
from struct import *
from ..abstract_forge import Forge
from ..packet_info_container import ForgeInfo

class           TCPForge(Forge):
    """ Creating the tcp part of the encapsulation"""

    parser_name = 'TCP'

    def         ask_for_the_list(self):
        """ Return the list of nedeed parameter in order to check the xml validity """

        return ['source', 'dest', 'seq', 'seq', 'ack_seq', 'doff', 'fin',  'syn', 'rst', 'psh', 'ack', 'urg', 'check', 'urg_ptr']


    def         get_forged_encapsulation(self, forge_info, chk=None):
        """ Forge tcp packet from packet info container """
        
        tcp_hdr = forge_info.get_extracted_dict(self.parser_name)
        window = socket.htons(5840)
        tcp_offset_res = (int(tcp_hdr['doff']) << 4) + 0
        tcp_flags = int(tcp_hdr['fin']) + (int(tcp_hdr['syn']) << 1) + \
            (int(tcp_hdr['rst']) << 2) + (int(tcp_hdr['psh']) << 3) + \
            (int(tcp_hdr['ack']) << 4) + (int(tcp_hdr['urg']) << 5)

        if chk:
            tcp_header = pack('!HHLLBBH' , \
                                  int(tcp_hdr['source']), int(tcp_hdr['dest']), \
                                  int(tcp_hdr['seq']), int(tcp_hdr['ack_seq']), \
                                  tcp_offset_res, tcp_flags, window) + \
                                  pack('H' , chk) + \
                                  pack('!H', int(tcp_hdr['urg_ptr']))
            return tcp_header
        else:
            tcp_header = pack('!HHLLBBHHH' , \
                                  int(tcp_hdr['source']), int(tcp_hdr['dest']), \
                                  int(tcp_hdr['seq']), int(tcp_hdr['ack_seq']), \
                                  tcp_offset_res, tcp_flags, window, \
                                  int(tcp_hdr['check']), int(tcp_hdr['urg_ptr']))
            forge_info.set_forged_packet(self.parser_name, tcp_header)
