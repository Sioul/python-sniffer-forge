#!/usr/bin/python3

import struct
import binascii
from ..abstract_parser import Parser
from ..packet_info_container import PacketInfoContainer

class           EthernetParser(Parser):
    """Parsing the Ethernet encapsulation"""

    parser_name = 'ethernet'
    # Create a protocol list that can be parsed here
    next_parser_id = {}
    next_parser_id[b'0800'] = 'IPv4'
    next_parser_id[b'86dd'] = 'IPv6'
    next_parser_id[b'0806'] = 'ARP'

    def get_next_parser(self, pic): 
        eth = {}

        ############ ETHERNET HEADER ############        
        # the 14 first bytes represente the ethernet header
        ethernet_header = pic.get_packet()[0][0:14]
        # Extract filds with precise type
        eth_hdr = struct.unpack("!6s6s2s", ethernet_header)

        # Save and convert the filds in hexa 
        eth['destination_mac'] = binascii.hexlify(eth_hdr[0])
        eth['source_mac'] = binascii.hexlify(eth_hdr[1])
        eth['ethernet_type'] = binascii.hexlify(eth_hdr[2])

        ########### SAVING DATA ############
        # Find the next parser
        for key in self.next_parser_id:
            if key == eth['ethernet_type']:
                pic.set_pos_hdr(14)
                pic.append_ex_parser('ethernet', eth)
                return self.next_parser_id[eth['ethernet_type']]
        # if hasen't found any "next_parser" raise an error
        pic.over = True
        return 'ethernet'
        raise ValueError("Protocole '%s' not implemented error" % \
                             eth['eth_type'])
