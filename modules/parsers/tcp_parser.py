#!/usr/bin/python3

import struct
from ..abstract_parser import Parser

class           TCPParser(Parser):
    """Parsing the TCP encapsulation"""

    parser_name = 'TCP'

    def get_next_parser(self, pic):
        tcp = {}

        ###### TCP HEADER ######
        # Get the header ip with the old position in the packet
        tcp_header = pic.get_packet()[0][pic.get_hdr_pos():pic.get_hdr_pos() + 20]
        tcp_hdr = struct.unpack('!HHLLBBHHH' , tcp_header)        
        # Byte 1 & 2 (Source Port)
        tcp['source_port'] = tcp_header[0]
        # Byte 3 & 4 (Destination Port)
        tcp['destination_port'] = tcp_header[1]
        # Byte 5 & 6 (Sequence)
        tcp['seqence'] = tcp_header[2]
        # Byte 7 & 8 (Acknowledgement)
        tcp['acknowlegement'] = tcp_header[3]
        # Byte 9 & 10 (Reserved)
        tcp['reserved'] = tcp_header[4]
        # Bype 11 (Tcp Header Length)
        tcp['header_length'] = tcp_header[4] >> 4

        ###### DATA ######
        data = pic.get_packet()[0][pic.get_hdr_pos() + 20:]
        pic.append_ex_parser('tcp', tcp)
        pic.save_data(data)
        pic.over = True
        return "ethernet"
        

