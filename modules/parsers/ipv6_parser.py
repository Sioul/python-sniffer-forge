#!/usr/bin/python3

import socket
import struct
from ..abstract_parser import Parser
from ..packet_info_container import PacketInfoContainer

class           IPv6Parser(Parser):
    """Parsing the IP encapsulation"""

    parser_name = 'IPv6'
    next_parser_id = {}
    next_parser_id[1] = 'ICMP'
    next_parser_id[6] = 'TCP'
    next_parser_id[17] = 'UDP'

    def get_next_parser(self, pic):
        ip = {}
        
        ########### IPV6 PARSER ##########
        # Get the header ip with the old position in the packet
        ip_header = pic.get_packet()[0][pic.get_hdr_pos():pic.get_hdr_pos() + 41]
        ip_hdr = struct.unpack("!BBBHHBB16s16s", ip_header)
        # Bits 1 to 4 (Version)
        ip['version'] = (ip_hdr[0]) >> 4
        # Bits 5 to 13 (Traffic class)
        ip['traffic_class'] = (ip_hdr[0] & 0b00001111) + (ip_hdr[1]) >> 4
        # Bits 14 to 34 (Flow label)
        ip['flow_label'] = (ip_hdr[2] & 0b00001111) + ip_hdr[3]
        # Bytes 5 & 6 (Playload length)
        ip['playload_length'] = ip_hdr[4]
        # Byte 7 (Next header)
        ip['next_header'] = ip_hdr[5]
        # Byte 8 (Hop limit)
        ip['hop_limit'] = ip_hdr[6]
        # Bytes 9 to 25 (ipsrc)
        ip['source_ip'] = socket.inet_ntop(socket.AF_INET6, ip_hdr[7])
        # Byte 26 to 42
        ip['destination_ip'] = socket.inet_ntop(socket.AF_INET6, ip_hdr[8])

        ########### SAVING DATA ############
        # Find the next parser
        for key in self.next_parser_id:
            if key == ip['next_header']:
                pic.set_pos_hdr(pic.get_hdr_pos() + 41)
                pic.append_ex_parser('ipv6', ip)
                return self.next_parser_id[ip['next_header']]
        
        pic.over = True
        return 'ethernet'
        raise ValueError("Protocole '%s' not implemented error" % \
                             ip['next_header'])
