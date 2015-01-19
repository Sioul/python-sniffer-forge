#!/usr/bin/python3

import socket
from struct import *
from ..packet_info_container import ForgeInfo
 

def             checksum(data):
    """ Calculate the checksum"""

    s = 0
    data = str(data)
    n = len(data) % 2

    for i in range(0, len(data) - n, 2):
        s += ord(data[i]) + (ord(data[i + 1]) << 8)
    if n:
        s += ord(data[i + 1])
    while (s >> 16):
        s = (s & 0xFFFF) + (s >> 16)
    s = ~s & 0xffff

    return s


def             checksum_calc(fi, proto_type):
    """ Pseudo header field completer"""

    proto_dict = {'TCP': socket.IPPROTO_TCP}
    
    placeholder = 0
    protocol = proto_dict[proto_type]
    length = len(fi.get_forged_packet()[proto_type]) + len(fi.user_data)
 
    psh = pack('!4s4sBBH', fi.saddr, fi.daddr, placeholder, protocol, length)
    psh = psh + fi.get_forged_packet()[proto_type] + fi.user_data

    fi.check = checksum(psh)
