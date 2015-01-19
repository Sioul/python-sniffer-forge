#!/usr/bin/python3

import argparse
import socket
from .parser_factory import newParser
from .yellow_socket import YellowSocket
from .tools.print_packet import print_ex_parser
from .packet_info_container import PacketInfoContainer


def             shell_options(cmd):
    """ Options the shell can accept """

    proto_list = ['ethernet', 'arp', 'ipv4', 'ipv6', 'icmp', 'tcp', 'udp']

    parser = argparse.ArgumentParser(description='------SNIFFER control shell-------')

    parser.add_argument('-f','--filter', metavar="PROTOCOL", help='Filter the protcoles abrove the list: {}'.format(proto_list), choices=proto_list)       
    parser.add_argument('-r','--recursion_number', metavar="NUMBER OF RECURSION", type=int, default=1, \
                            help='Choose the number of packet you want to read')
    parser.add_argument('-ip', '--ip_filter', help='Filter the incoming packet to print only the one from choosen ip (works only with ipv4)', metavar="IP")

    try:
        args = parser.parse_args(cmd)
    except SystemExit:
        raise
    
    if args.ip_filter:
        try:
            socket.inet_aton(args.ip_filter)
        except socket.error:
            print("[ERROR] Bad address ip as --ip_filter parameter: {}".format(args.ip_filter))
            raise

    return args


def             sniff(cmd, sock, p_info):
    """ The main sniffer function """

    i = 0

    try:
        args = shell_options(cmd)
    except:
        return
    my_parser = newParser("ethernet")
    packet = sock.get_packet()
    p_info.set_packet(packet)
    while i < args.recursion_number:
        
        if p_info.over:
            packet = sock.get_packet()
            p_info.set_packet(packet)
            if 'ethernet' in p_info.get_ex_parser() and not args.ip_filter \
                    or args.ip_filter and 'ipv4' in p_info.extracted_parser and \
                    args.ip_filter == p_info.extracted_parser['ipv4']['source_ip']:
                i = i + print_ex_parser(p_info, flag=args.filter)
            p_info.clear_info()

        my_parser = newParser(my_parser.get_next_parser(p_info))
