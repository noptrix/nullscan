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
# portscan.py                                                                  #
#                                                                              #
# AUTHOR                                                                       #
# noptrix@nullsecurity.net                                                     #
#                                                                              #
################################################################################


# sys imports
import os


# own imports
from modules.libs.base import Base, tool, timeout


class PortScan(Base):
  """ portscan module (lan) """


  def __init__(self, target, opts):
    """ init """

    Base.__init__(self, target, opts)

    return


  @tool
  def tcp_portscan(self):
    """
    DESCR: Perform TCP portscan of all active hosts in a LAN. (ext)
    TOOLS: nmap
    """

    self.opts['nmap'].append('--open')
    opts = {'hosts': self._get_arpsweep_hosts(), 'opts': self.opts['nmap']}

    self._portscan(opts, 'tcp_portscan')

    msg = f'TCP portscan results saved in: {os.getcwd()}'
    self._log('tcp_portscan', msg)

    return


  @tool
  def udp_portscan(self):
    """
    DESCR: Perform UDP portscan of all active hosts in a LAN. (ext)
    TOOLS: nmap
    """

    nmap_opts = ['-sU']
    opts = {'hosts': self._get_arpsweep_hosts(), 'opts': nmap_opts}

    self._portscan(opts, 'udp_portscan')

    msg = f'UDP portscan results saved in: {os.getcwd()}'
    self._log('udp_portscan', msg)

    return


# EOF
