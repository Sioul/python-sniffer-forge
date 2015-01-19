#!/usr/bin/python3

class           Parser(object):
    """Abstract class for all parsers"""

    parser_name = None
    next_parser_id = {}
    exctracted_data = {}

    def __contains__(self, nothing):
        return self.parser_name

    def get_name(self):
        return self.parser_name

    def get_next_parser(self, packet = []):
        return self.next_module_id

