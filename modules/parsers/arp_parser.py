#!/usr/bin/python3

import struct
import socket
import binascii
from ..abstract_parser import Parser

class           ARPParser(Parser):
    """Parsing the Arp encapsulation"""

    parser_name = 'ARP'

    def get_next_parser(self, pic):
        arp = {}

        arp_header = pic.get_packet()[0][pic.get_hdr_pos():pic.get_hdr_pos() + 28]
        arp_hdr = struct.unpack("2s2s1s1s2s6s4s6s4s", arp_header)

        # Byte 1 Hardware type
        arp['hardware_type'] = binascii.hexlify(arp_hdr[0])
        # Byte 2 Proto type
        arp['prototype'] = binascii.hexlify(arp_hdr[1])
        # Byte 3 Hardware size
        arp['hardware_size'] = binascii.hexlify(arp_hdr[2])
        # Byte 4 Proto size
        arp['prototype_size'] = binascii.hexlify(arp_hdr[3])
        # Byte 5 Op code
        arp['op_code'] = binascii.hexlify(arp_hdr[4])
        # Byte 6 Source mac
        arp['source_mac'] = binascii.hexlify(arp_hdr[5])
        # Byte 7 Source IP
        arp['source_ip'] = socket.inet_ntoa(arp_hdr[6])
        # Byte 8 Dest mac
        arp['destination_mac'] = binascii.hexlify(arp_hdr[7])
        # Byte 9 Dest IP
        arp['destination_ip'] = socket.inet_ntoa(arp_hdr[8])

        pic.append_ex_parser('arp', arp)
        pic.over=True
        return 'ethernet'
