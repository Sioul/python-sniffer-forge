#!/usr/bin/python3

# include your forge func here
from .abstract_forge import Forge
from .forge_packet.ip_forge import IPv4Forge
from .forge_packet.tcp_forge import TCPForge
from .forge_packet.arp_forge import ARPForge
from .forge_packet.ethernet_forge import ethernetForge

TypeType = type(type)

def             newForge(forge_name):
    """Find the good forge to send back"""

    # Get a full list of all the included forges
    forgeClasses = [j for (i, j) in globals().items() \
                         if isinstance(j, TypeType) and issubclass(j, Forge)]
    for forgeClass in forgeClasses:
        forge = forgeClass()
        if forge_name == forge.get_name():
            return forge
    raise ValueError("No forge containing '%s' tag." % forge_name)




