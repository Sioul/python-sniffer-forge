#!/usr/bin/python3

import struct
from ..abstract_parser import Parser

class           UDPParser(Parser):
    """Parsing the UDP encapsulation"""

    parser_name = 'UDP'

    def get_next_parser(self, pic):
        udp = {}

        ############ UDP HEADER #############
        udp_header = pic.get_packet()[0][pic.get_hdr_pos():pic.get_hdr_pos() + 8]
        udp_hdr = struct.unpack('!HHHH' , udp_header)

        # Byte 1 & 2 (Source Port)
        udp['source_port'] = udp_hdr[0]
        # Byte 3 & 4 (Destination Port)
        udp['destination_port'] = udp_hdr[1]
        # Byte 5 & 6 (Lenght)
        udp['length'] = udp_hdr[2]
        # Byte 7 & 8 (Checksum)
        udp['checksum'] = udp_hdr[3]

        ########## DATA ###########
        data = pic.get_packet()[0][pic.get_hdr_pos() + 8:]
        pic.append_ex_parser('udp', udp)
        pic.save_data(data)
        pic.over = True
        return 'ethernet'
