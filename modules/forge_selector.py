#!/usr/bin/python3

import argparse
from .tools.xml_to_dict import XmlToDict
from .forge_factory import newForge
from .tools.check_dict import CheckDict
from .packet_info_container import ForgeInfo
from .send_and_print_packet import send_and_print_packet


def             shell_options(cmd):
    """ Options the shell can accept """

    parser = argparse.ArgumentParser(description='-------FORGE control shell.-------',)
    parser.add_argument('-f', '--file', help='select the path of an xml file', \
                            metavar="FILE", dest='filename', required=True)
    parser.add_argument('-r','--recursion_number', type=int, default=1, \
                            metavar="INT", help='Choose the number of packet you want to send')
    parser.add_argument('-p','--print_packet', action='store_true', \
                            help='Print the packet before sending it')

    try:
        args = parser.parse_args(cmd)
    except SystemExit:
        raise

    try:
        xtd = XmlToDict(args.filename).get_dict()
    except AttributeError:
        print("[ERROR] Can't access or unreadable .xml at {}".format(args.file))
        raise

    return (args, xtd)


def             createPacket(cmd):
    """ Read the xml and create the packet """

    dico = None
    fi = ForgeInfo()
    try:
        args, xtd = shell_options(cmd)
    except:
        return
    try:
        check_dict = CheckDict(xtd)
    except Exception as inst:
        print("Missing the {} parameter in the {} xml".format(inst.args))
        raise
    # List of the protocol we can handle
    proto_list = {0: ['ethernet'], \
                      1: ['ipv4', 'arp'],\
                      2: ['TCP']}

    for i in range(len(proto_list)):
        for elem in proto_list[i]:
            if xtd.findall(elem):
                # Instanciate the correct forge class
                n_forge = newForge(elem)
                try:
                    # Check the xml validity and extract a dict
                    dico = check_dict.parse_dico(elem, n_forge.ask_for_the_list())
                    if dico:
                        fi.set_extracted_dict(elem, dico)
                        # Forge the packet itself
                        n_forge.get_forged_encapsulation(fi)
                        if dico == "arp":
                            break
                    else:
                        print("Missing {} in the xml".format(proto_list[i]))
                        raise
                except Exception as e:
                    print(e.args)
                    raise
    send_and_print_packet(fi, xtd, args)
