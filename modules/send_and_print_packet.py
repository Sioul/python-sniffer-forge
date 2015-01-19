#!/usr/bin/python3

from .tools.hexdump import hexdump
from .yellow_socket import YellowSocket
from .packet_info_container import ForgeInfo
from .forge_packet.final_packet_encapsulation import final_packet_encapsulation


def             send_and_print_packet(fi, xtd, args):
    """ Send and print the packet """

    y_socket = YellowSocket(1)

    if "arp" not in fi.extracted_dict:
        if xtd.findall('user_data'):
            fi.set_extracted_dict('user_data', xtd.findtext('user_data').encode())
        else:
            fi.set_extracted_dict('user_data', b'')

        packet = final_packet_encapsulation(fi)
    else:
        packet = fi.get_forged_packet()['ethernet'] + fi.get_forged_packet()['arp']

    #send packet with socket
    for j in range(args.recursion_number):
        y_socket.send_packet(packet, fi.dest_ip)
        if args.print_packet:
            print("Packet number {} send\n".format(j + 1))
            print("{}".format(hexdump(packet)))
        else:
            print("Packet number {} successfully send".format(j + 1))

    fi.clear_all()
