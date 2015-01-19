#!/usr/bin/python2

# Initialize the raw socket

import socket, sys
from struct import *

#create a AF_PACKET type raw socket (thats basically packet level)
#define ETH_P_ALL    0x0003          /* Every packet (be careful!!!) */  

class           YellowSocket:
    """RAWSocket for python"""

    def         __init__(self, flag = None):
        try:
            if flag:
                self.socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
            else:
                self.socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        except socket.error as msg:
            if '[Errno 1]' in str(msg):
                print('This program need administrator right to create the RAW socket on your computer')
            else:
                print('Socket could not be created. Error Code: '+ str(msg) + ' Message')
            sys.exit()


    def         get_packet(self):
        return self.socket.recvfrom(65565)



    def         send_packet(self, packet, dest_ip):
        self.socket.sendto(packet, (dest_ip, 0))
