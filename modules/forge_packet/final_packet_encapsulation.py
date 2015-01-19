#!/usr/bin/python3

from ..forge_factory import newForge
from ..packet_info_container import ForgeInfo
from ..tools.checksum_calc import checksum_calc


def             final_packet_encapsulation(fi):
    """ Rebuilt the entire packet with a valide checksum """

    header_order = []
    proto_list = {0: ['ethernet'], \
                      1: ['ipv4'], \
                      2: ['TCP']}

    for i in range(len(proto_list)):
        for elem in proto_list[i]:
            if elem in fi.get_forged_packet():
                header_order.append(elem)
            # Doit contenire tout les header qu'on a parser
    checksum_calc(fi, header_order[1])
    # Reforge the packet with the correct checksum
    n_forge = newForge(header_order[1])
    final_hdr = n_forge.get_forged_encapsulation(fi, fi.check)
    packet = b''
    # Concat the packet in correct order
    for elem in header_order:
        packet = packet + fi.get_forged_packet()[elem]
    packet = packet + fi.get_extracted_dict('user_data')
    return packet


