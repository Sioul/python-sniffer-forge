#!/usr/bin/python3

###### We need packet info container to share our data between the forging modules

class           Forge(object):
    """Abstract class for all network constructer"""

    parser_name = None

    def         __contains__(self, nothing):
        return self.parser_name

    def         get_name(self):
        return self.parser_name

    def         ask_for_the_list(self):
        raise NotImplemented

    def         get_forged_encapsulation(self, dic):
        raise NotImplemented
