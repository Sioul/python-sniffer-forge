#!/usr/bin/python3

import os
import readline
from ..sniff import sniff
from ..yellow_socket import YellowSocket
from ..forge_selector import createPacket
from ..packet_info_container import PacketInfoContainer


class           UserTerminal:
    """ A terminal for the user """

    def         __init__(self, p_info, sock):

        self.p_info = p_info
        self.sock = sock

        # Dictionary of our shell macro commande
        self.terminal_func = {'forge': self.forge,
                              'sniff': self.sniff,
                              'help': self.help,
                              'cd': self.cd
                              }


    def         term(self, input_msg):
        """ Just a terminal with autocompletition """

        readline.parse_and_bind("tab: complete")
        return input(input_msg)


    def         forge(self, cmd):
        """ Call create packet in forge_selector"""

        createPacket(cmd)
        

    def         sniff(self, cmd):
        """ Call sniff in sniff"""

        sniff(cmd, self.sock, self.p_info)


    def         cd(self, cmd):
        """ A simple cd func """

        if os.access(cmd[1:], os.W_OK):
            os.chdir(cmd[1:])
        else:
            print("ERROR: Bad path %s" % cmd)


    def         help(self, cmd):
        """ Help """

        print("\nYou can use your usual shell commande\n'exit' to quit\n'forge' to create your own packet (-h for help)\n'sniff' to list the packet you read on your network interfaces (-h for help)\n")


    def         user_term(self):
        """ Permit the user to choose what he want to do """

        print("\n[Usage] Enter 'help' to get a commande list")
        self.old_path = os.getcwd()

        while 1:
            cmd = self.term('Yellow> ')
            l_cmd = cmd.split()
            
            if cmd == "exit":
                break
            elif l_cmd and l_cmd[0] in self.terminal_func:
                # Seem complicated but isn't just call the pointered func dict
                ret = self.terminal_func[l_cmd[0]](l_cmd[1:])
            else:
                os.system(cmd)
