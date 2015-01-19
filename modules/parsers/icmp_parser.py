#!/usr/bin/python3

import struct
from ..abstract_parser import Parser

class           ICMPParser(Parser):
    """Parsing the ICMP encapsulation"""

    parser_name = 'ICMP'

    def get_next_parser(self, pic):
        icmp = {}

        icmp_header = pic.get_packet()[0][pic.get_hdr_pos():pic.get_hdr_pos() + 4]
        icmph = struct.unpack('!BBH' , icmp_header)

        # Byte 1 & 2 (ICMP type)
        icmp['type'] = icmp_header[0]
        # Byte 3 & 4 (Code)
        icmp['code'] = icmp_header[1]
        # Byte 5 & 6 (Checksum)
        icmp['checksum'] = icmp_header[2]

        pic.append_ex_parser('icmp', icmp)
        pic.over = True
        return 'ethernet'
