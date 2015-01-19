#!/usr/bin/python3

import socket
import struct
from ..abstract_parser import Parser
from ..packet_info_container import PacketInfoContainer

class           IPv4Parser(Parser):
    """Parsing the IP encapsulation"""

    parser_name = 'IPv4'
    next_parser_id = {}
    next_parser_id[1] = 'ICMP'
    next_parser_id[6] = 'TCP'
    next_parser_id[17] = 'UDP'

    def get_next_parser(self, pic):
        ip = {}

        ########## IPV4 HEADER ############
        # Get the header ip with the old position in the packet
        ip_header = pic.get_packet()[0][pic.get_hdr_pos():pic.get_hdr_pos() + 20]
        # Create a tuple from the unpacked header
        ip_hdr = struct.unpack("!BBHHHBBH4s4s", ip_header)
        # Byte 1 (Version + Header Length)
        ip['version'] = (ip_hdr[0])>>4
        ip['header_len'] = (ip_hdr[0] & 0b00001111)
        # Byte 2 (Differentiated Services)
        ip['differenciated_services'] = ip_hdr[1]
        # Bytes 3 & 4 (Total Length)
        ip['total_length'] = ip_hdr[2]
        # Bytes 5 & 6 (Identification)
        ip['identification'] = ip_hdr[3]
        # Bytes 7 & 8 (Flags & Fragment offset)
        ip['rflag'] = (ip_hdr[4])>>15
        ip['dfflag'] = (ip_hdr[4] & 0b0100000000000000)>>14
        ip['mfflag'] = (ip_hdr[4] & 0b0010000000000000)>>13
        ip['fragment_offset'] = (ip_hdr[4] & 0b0001111111111111)
        # Byte 9 (Time To Live)
        ip['time_to_live'] = ip_hdr[5]
        # Byte 10 (Protocol)
        ip['protocol'] = ip_hdr[6]
        # Bytes 11 & 12 (Header Checksum)
        ip['header_checksum'] = ip_hdr[7]
        # Bytes 13 - 16 (Source IP)
        ip['source_ip'] = socket.inet_ntoa(ip_hdr[8])
        # Bytes 17 - 20 (Destination IP)
        ip['destination_ip'] = socket.inet_ntoa(ip_hdr[9])

        ########### SAVING DATA ############
        # Find the next parser
        for key in self.next_parser_id:
            if key == ip['protocol']:
                pic.set_pos_hdr(pic.get_hdr_pos() + 20)
                pic.append_ex_parser('ipv4', ip)
                return self.next_parser_id[ip['protocol']]
        # if hasen't found any "next_parser" raise an error
        pic.over = True
        return 'ethernet'
        raise ValueError("Protocole '%s' not implemented error" % \
                             ip['proto'])
