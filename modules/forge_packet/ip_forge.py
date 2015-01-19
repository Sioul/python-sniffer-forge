#!/usr/bin/python3

#from ..packet_info_container import PacketInfoContainer
import socket
from struct import *
from ..abstract_forge import Forge
from ..packet_info_container import ForgeInfo


class           IPv4Forge(Forge):
    """ Creating the ipv4 part of the encapsulation"""

    parser_name = 'ipv4'

    def         ask_for_the_list(self):
        """ Return the list of nedeed parameter in order to check the xml validity """

        return ['ihl', 'ver', 'tos', 'tot_len', 'id', 'frag_off', 'ttl', 'proto', 'check', 'a_addr', 'd_addr']
    

    def         get_forged_encapsulation(self, forge_info):
        """ Forge ipv4 packet from packet info container """
        
        ip_hdr = forge_info.get_extracted_dict(self.parser_name)
        forge_info.dest_ip = ip_hdr['d_addr']

        source_addr = socket.inet_aton(str(ip_hdr['a_addr']))
        dest_addr = socket.inet_aton(str(ip_hdr['d_addr']))

        forge_info.saddr = source_addr
        forge_info.daddr = dest_addr
        ip_proto = socket.IPPROTO_TCP

        ip_ihl_ver = (int(ip_hdr['ver']) << 4) + int(ip_hdr['ihl'])

        ip_header = pack('!BBHHHBBH4s4s', \
                             ip_ihl_ver, int(ip_hdr['tos']), \
                             int(ip_hdr['tot_len']), int(ip_hdr['id']), \
                             int(ip_hdr['frag_off']), int(ip_hdr['ttl']), \
                             int(ip_proto), int(ip_hdr['check']), \
                             source_addr, dest_addr)
 
#        ip_header = pack('!BBHHHBBH4s4s' , ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl, ip_proto, ip_check, source_addr, dest_addr)

        forge_info.set_forged_packet(self.parser_name, ip_header)
