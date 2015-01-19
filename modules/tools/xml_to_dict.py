#!/usr/bin/python3

import xml.etree.ElementTree as ET
import readline
import subprocess
import os


class           XmlToDict():
    """ Open the xml configuration file and 
    create a dict with all our forging information """


    # The init function need a xml file as parameter
    def         __init__(self, config_file):
        """ Python basic xml interpreter """

        try:
            tree = ET.parse(config_file)
            root = tree.getroot()
            self.parser_dict = root
        except:
            print("Bad or missformed XML please enter a correct one")
            self.parser_dict = None
            raise


    def         get_dict(self):

        return self.parser_dict
