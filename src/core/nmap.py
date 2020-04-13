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
# nmap.py                                                                      #
#                                                                              #
# AUTHOR                                                                       #
# noptrix@nullsecurity.net                                                     #
#                                                                              #
################################################################################


# sys imports
import sys
import os
import subprocess


# own imports
from core.logger import Logger
from core.checks import Check


class Nmap:
  """ nmap class """


  def __init__(self, opts):
    """ constructor """

    self.opts = opts            # nmap options
    self.cmd = []               # nmap command line
    self.logfile = 'results'    # default nmap logfile

    self.logger = Logger()
    self.log = self.logger.log

    self.check = Check()        # we need to check UID

    return


  def set_logfile(self, logfile):
    """ set nmap logfile """

    self.logfile = logfile

    return


  def get_protocol(self):
    """ get the protocol out of selected scan type """

    protocol = 'tcp'    # default if nothing or -A was selected
    scan_forms = {
      'tcp': ['-sS', '-sT', '-sA', '-sW', '-sM', '-sN', '-sF', '-sX'],
      'udp': ['-sU'],
      'sctp': ['-sY', '-sZ'],
      'ip': ['-sO'],
      }

    for prot, forms in scan_forms.items():
      for form in forms:
        if form in self.opts['opts']:
          protocol = prot
          break

    return protocol


  def build_cmd(self):
    """ check and build nmap command args line for subprocess """

    # collect nmap options and build nmap command line
    self.cmd.insert(0, 'nmap')
    if type(self.opts['opts']) == list:   # nmap options from config file
      for o in self.opts['opts']:
        self.cmd.append(o)
    else:
      self.cmd.append(self.opts['opts'])  # nmap options given on cmdline
    [self.cmd.append(o) for o in ['-oA', self.logfile]]
    [self.cmd.append(o) for o in self.opts['hosts']]

    return


  def scan(self, output=None, debug=False):
    """ start a scan """

    try:
      if output:
        f = output
      elif debug:
        f = '/dev/stdout'
      else:
        f = os.devnull
      with open(f, 'w') as fd:
        subprocess.run(self.cmd, stdout=fd, stderr=subprocess.STDOUT)
    except KeyboardInterrupt:
      self.log('nmap_abort', _type='err', end='\n')
    except Exception as err:
      self.log('nmap_scan', eargs=err, _type='err', end='\n')

    return


# EOF
