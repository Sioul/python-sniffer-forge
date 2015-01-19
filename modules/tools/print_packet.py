#!/usr/bin/python3

from ..packet_info_container import PacketInfoContainer
from .hexdump import hexdump

def             print_it(p_info, ex_parser, dico, test_parser):
    """ Print one of our dico """

    print("\n############################### {0:10s} ################################\n".format(dico))
    for key in ex_parser[dico]:
        print('{0:25s} ==> '.format(key), ex_parser[dico][key])
                
        if test_parser != '' and dico == test_parser:
            input("\nPush ENTER to continue")
            print()


def             print_ex_parser(p_info, test_parser='', flag=None):
    """ Test function to print all the info and eventually wait after the parser you asked for"""

    ex_parser = p_info.get_ex_parser()

    if not hasattr(print_ex_parser, "static_counter"):
        print_ex_parser.static_counter = 1
    if flag in ex_parser or not flag:
        print("____________________________ PACKET number: {} _______________________________".format(print_ex_parser.static_counter))
        #hexdump(p_info.packet[0])

    value = 0
    for dico in ex_parser:
        if flag:
            if flag == dico:
                print_it(p_info, ex_parser, dico, test_parser)
                value = 1
        else:
            print_it(p_info, ex_parser, dico, test_parser)
            value = 1

    if value == 1:
        if p_info.get_ex_data():
            print("\n############################## UserData ###################################\n\n", p_info.get_ex_data(), end="\n\n\n")
        print_ex_parser.static_counter += 1

    return value
