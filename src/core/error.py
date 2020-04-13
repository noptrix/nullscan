#!/usr/bin/env python3
# -*- coding: utf-8 -*- ########################################################
#               ____                     _ __                                  #
#    ___  __ __/ / /__ ___ ______ ______(_) /___ __                            #
#   / _ \/ // / / (_-</ -_) __/ // / __/ / __/ // /                            #
#  /_//_/\_,_/_/_/___/\__/\__/\_,_/_/ /_/\__/\_, /                             #
#                                           /___/ team                         #
#                                                                              #
# nullscan                                                                     #
# A modular framework designed to chain and automate security tests            #
#                                                                              #
# FILE                                                                         #
# error.py                                                                     #
#                                                                              #
# AUTHOR                                                                       #
# noptrix@nullsecurity.net                                                     #
#                                                                              #
################################################################################


# sys imports
import sys
import os


# own imports
from core.constants import *


class Error:
  """ error handler class """


  def __init__(self):
    """ init """

    self.map_errors()
    self.map_warnings()

    return


  def map_warnings(self):
    """ maps warning keywords to corresponding warning messages """

    self.warns = {
      'default': 'Oops, something went wrong: ',
      'r00t': 'You are not r00t. Some tools will fail!',
      'workers': 'Are you kidding me, more than 255 workers? ...',
      'tool_timeout': 'Timeout expired for tool: ',
      'tool_interrupt': 'Interrupted by user: ',
      'tool_failed': 'Something went wrong with tool: ',
      'nmap_verbose': 'Use verbose mode to see the nmap scan progress.',
    }

    return


  def map_errors(self):
    """ maps error keywords to corresponding error messages """

    self.errors = {
      'default': 'Oops, something went wrong: ',
      'aborted': 'Program aborted. :(',
      'r00t': 'You need to be r00t, d00d!',
      'usage': 'Something wrong with your usage. Check syntax.',
      'rfile': 'Could not read from file: ',
      'wfile': 'Could not write to file: ',
      'mkdir': 'Could not create directory: ',
      'config': 'Could not read or parse config file: ',
      'nmap': 'Could not read or parse nmap logfile: ',
      'brain': 'WTF? mount /dev/brain!',
      'help': 'Use -H to print help and usage.',
      'cmdopt': 'Unknown option chosen: ',
      'report': 'Unknown report format: ',
      'workers': 'Workers must be a number.',
      'timeout': 'Timeout must be a number for seconds.',
      'protocol': 'Unknown protocol for host mode: ',
      'port': 'Invalid port specified: ',
      'wwwurl': 'Incorrect www URL specified: ',
      'nettype': 'Unknown network type: ',
      'social': 'Unknown social type: ',
      'mac': 'Invalid mac address specified: ',
      'mod_import': 'Could not import module: ',
      'mod_default': 'You cannot remove default modules.',
      'mod_opts': 'Option -i and -x are not allowed together',
      'tool_opts': 'Option -I and -X are not allowed together',
      'add_mod_tool': 'Could not add the module or tool. Check syntax.',
      'add_tool': 'Module file was not found. Create module first.',
      'nmap_scan': 'Nmap scan failed: ',
      'nmap_abort': 'Nmap scan aborted by user!',
      'mode': 'Unknown mode or format chosen: ',
      'file_copy': 'Could not copy or move the files',
      'inexmods': 'Wrong syntax for including/excluding modules',
      'pydeps': 'Missing Python modules detected!',
      'nmap_root': 'You are not r00t and requested -sU... dumb.',
      'file_del': 'Could not delete file: ',
      'hostrange': 'Wrong host or CIDR range defined: ',
    }

    return


# EOF
