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
# iax.py                                                                       #
#                                                                              #
# AUTHOR                                                                       #
# noptrix@nullsecurity.net                                                     #
#                                                                              #
################################################################################


# sys imports


# own imports
from modules.libs.base import Base, tool, timeout


class IAX(Base):
  """ IAX module (udp/4569)"""


  def __init__(self, target, opts):
    """ init """

    Base.__init__(self, target, opts)

    return


  @tool
  def iax_scan_users(self):
    """
    DESCR: Detect live IAX/2 hosts and then enumerate (bruteforce) users. (ext)
    TOOLS: iax-scan-users
    """

    opts = f"-i {self.target['host']} -p {self.target['port']}"
    opts += ' -s 1 -e 1000 -v 1'
    self._run_tool('iax-scan-users', opts, nullscan_tool='iax_scan_users')

    return


  @tool
  def nmap_iax_udp(self):
    """
    DESCR: Scan iax service with corresponding NSE scripts. (ext)
    TOOLS: nmap
    """

    opts = '-n -sU -Pn --nsock-engine epoll --script iax2-version'
    opts += f" -p {self.target['port']} {self.target['host']}"

    self._run_tool('nmap', opts, 'nmap_iax_udp')

    return


# EOF
