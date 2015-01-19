#!/usr/bin/python3

#from ..packet_info_container import PacketInfoContainer
from struct import *
from ..abstract_forge import Forge
from ..packet_info_container import ForgeInfo

class           ethernetForge(Forge):
    """ Creating the ethernet part of the encapsulation"""

    parser_name = 'ethernet'

    def         ask_for_the_list(self):
        """ Return the list of nedeed parameter in order to check the xml validity """

        return ['dest_mac', 'source_mac', 'type']
    

    def         get_forged_encapsulation(self, forge_info):
        """ Forge ethernet packet from packet info container """
        
        ethernet_hdr = forge_info.get_extracted_dict(self.parser_name)
        ethernet_header = pack('!6s6s2s', \
                                   ethernet_hdr['dest_mac'].encode(), \
                                   ethernet_hdr['source_mac'].encode(), \
                                   ethernet_hdr['type'].encode())
        forge_info.set_forged_packet(self.parser_name, ethernet_header)
