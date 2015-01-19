#!/usr/bin/python3

#from ..packet_info_container import PacketInfoContainer
import socket
from struct import *
from ..abstract_forge import Forge
from ..packet_info_container import ForgeInfo

class           ARPForge(Forge):
    """ Creating the arp part of the encapsulation"""

    parser_name = 'arp'

    def         ask_for_the_list(self):
        """ Return the list of nedeed parameter in order to check the xml validity """

        return ['hardware_type', 'proto_type', 'hardware_len', 'proto_len', 'opcode', 'src_hw_add', 'src_proto_add', 'dst_hw_add', 'dst_proto_add']
    

    def         get_forged_encapsulation(self, forge_info):
        """ Forge arp packet from packet info container """
        
        arp_hdr = forge_info.get_extracted_dict(self.parser_name)
        forge_info.dest_ip = arp_hdr['dst_proto_add']

        source_addr = socket.inet_aton(arp_hdr['src_proto_add'])
        dest_addr = socket.inet_aton(arp_hdr['dst_proto_add'])

        arp_header = pack(\
            '!2s2s1s1s2s6s4s6s4s', \
                arp_hdr['hardware_type'].encode(), \
                arp_hdr['proto_type'].encode(), arp_hdr['hardware_len'].encode(), \
                arp_hdr['proto_len'].encode(), arp_hdr['opcode'].encode(), \
                arp_hdr['src_hw_add'].encode(), source_addr, \
                arp_hdr['dst_hw_add'].encode(), dest_addr)
        forge_info.set_forged_packet(self.parser_name, arp_header)
