#!/usr/bin/python3

import xml.etree.ElementTree as ET

# incomplete for now
class           CheckDict:
    """ Check the xml integrity """

    def         __init__(self, dico):
        
        self.dico = dico

    
    def         parse_dico(self, f_type, parser_list):
        
        self.forge_dict = {}

        for element in self.dico.findall(f_type):
            for item in parser_list:
                if element.findtext(item):
                    r_word = element.findtext(item)
                    self.forge_dict[item] = r_word
                else:
                    raise Exception(item, f_type)
        return self.forge_dict
