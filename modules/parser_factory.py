#!/usr/bin/python3

# Include your parsers here
from .abstract_parser import Parser
from .parsers.ethernet_parser import EthernetParser
from .parsers.icmp_parser import ICMPParser
from .parsers.ipv4_parser import IPv4Parser
from .parsers.ipv6_parser import IPv6Parser
from .parsers.tcp_parser import TCPParser
from .parsers.arp_parser import ARPParser
from .parsers.udp_parser import UDPParser

TypeType = type(type)

def newParser(parser_name):
    """Find the good parser to send back"""

    # Get a full list of all the included parsers
    parserClasses = [j for (i, j) in globals().items() \
                         if isinstance(j, TypeType) and issubclass(j, Parser)]
    for parserClass in parserClasses:
        parser = parserClass()
        if parser_name == parser.get_name():
            return parser
    raise ValueError("No parser containing '%s' tag." % parser_name)
