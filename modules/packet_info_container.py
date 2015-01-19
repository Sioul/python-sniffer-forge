#!/usr/bin/python3

class           ForgeInfo(object):
    """ Contain the forge relative informations """

    extracted_dict = {}
    forged_packet = {}
    dest_ip = None
    saddr = None
    daddr = None
    check = None
    user_data = b''

    def get_extracted_dict(self, name=None):
        if name:
            return self.extracted_dict[name]
        else:
            return self.extracted_dict

    def set_extracted_dict(self, name, dico):
        self.extracted_dict[name] = dico

    def get_forged_packet(self):
        return self.forged_packet

    def set_forged_packet(self, name, li):
        self.forged_packet[name] = li

    def clear_all(self):
        self.extracted_dict.clear()
        self.forged_packet.clear()
        self.dest_ip = None
        self.saddr = None
        self.daddr = None
        self.check = None
        self.user_data = b''

class           PacketInfoContainer(object):
    """ Container of the parsed data"""

    packet = []
    pos_hdr = 0
    over = False
    extracted_data = []
    extracted_parser = {}
    
    def set_packet(self, packet):
        self.packet = packet

    def get_packet(self):
        return self.packet

    def append_ex_parser(self, name, new_data):
        self.extracted_parser[name] = new_data

    def get_ex_parser(self):
        return self.extracted_parser

    def clear_info(self):
        self.extracted_data = []
        self.extracted_parser.clear()
        self.over = False
        
    def save_data(self, data):
        self.extracted_data = data

    def get_ex_data(self):
        return self.extracted_data

    def set_pos_hdr(self, pos):
        self.pos_hdr = pos

    def get_hdr_pos(self):
        return self.pos_hdr
