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
# logger.py                                                                    #
#                                                                              #
# AUTHOR                                                                       #
# noptrix@nullsecurity.net                                                     #
#                                                                              #
################################################################################


# sys imports
import sys
import colorama


# own imports
from core.constants import *
from core.error import Error


class Logger(Error):
  """ Class to handle output (logging). """


  def __init__(self):
    """ Constructor. """

    Error.__init__(self)

    colorama.init()
    self.init_colors()
    self.msg_types()

    return


  def __del__(self):
    """ Destructor. """

    colorama.deinit()

    return


  def msg_types(self):
    """ Init message types. """

    self.types = {
      'norm': '',
      'msg': f"[+] {self.colors['bold']}",
      'vmsg': '    > ',
      'warn': f"[!] {self.colors['byellow']}",
      'err': f"[-] {self.colors['bred']}",
    }

    return


  def init_colors(self):
    """ Init colors. """

    self.colors = {
      '': '',
      'norm': colorama.Style.RESET_ALL,
      'bold': colorama.Style.BRIGHT,
      'red': colorama.Fore.RED,
      'bred': colorama.Style.BRIGHT + colorama.Fore.RED,
      'green': colorama.Fore.GREEN,
      'bgreen': colorama.Style.BRIGHT + colorama.Fore.GREEN,
      'yellow': colorama.Fore.YELLOW,
      'byellow': colorama.Style.BRIGHT + colorama.Fore.YELLOW,
      'blue': colorama.Fore.BLUE,
      'bblue': colorama.Style.BRIGHT + colorama.Fore.BLUE,
    }

    return


  def log(self, msg, _type='norm', stream='stdout', end='', flush=False,
    color='', eargs='', exit=True):
    """ Print a (verbose) (error|warning) message line """

    # output message to <stream>
    if _type == 'err':
      print(self.types[_type] + self.colors[color] + self.errors[msg] + eargs +
        self.colors['norm'], end=end, file=getattr(sys, stream), flush=flush)
    elif _type == 'warn':
      print(self.types[_type] + self.colors[color] + self.warns[msg] + eargs +
        self.colors['norm'], end=end, file=getattr(sys, stream), flush=flush)
    else:
      print(self.types[_type] + self.colors[color] + msg + self.colors['norm'],
        end=end, file=getattr(sys, stream), flush=flush)

    # exit if error type was chosen
    if _type == 'err' and exit:
      os._exit(FAILURE)

    return


# EOF
