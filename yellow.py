#!/usr/bin/python3

from modules.yellow_socket import YellowSocket
from modules.tools.user_terminal import UserTerminal
from modules.packet_info_container import PacketInfoContainer


def             main():
    """ Main func. Instanciate all the class we need"""

    sock = YellowSocket()
    p_info = PacketInfoContainer()

    ut = UserTerminal(p_info, sock)
    ut.user_term()



if __name__ == "__main__":
    main()
