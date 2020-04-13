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
# epmap.py                                                                     #
#                                                                              #
# AUTHOR                                                                       #
# noptrix@nullsecurity.net                                                     #
#                                                                              #
################################################################################


# sys imports


# own imports
from modules.libs.base import Base, tool, timeout


class Epmap(Base):
  """ EPmap module (udp/135) """


  def __init__(self, target, opts):
    """ init """

    Base.__init__(self, target, opts)

    return


  @tool
  def rpcdump_udp(self):
    """
    DESCR: Get infos over MSRPC endpoint mapper service. (ext)
    TOOLS: rpcdump.py
    """

    opts = f"{self.target['host']}"
    self._run_tool('rpcdump.py', opts, nullscan_tool='rpcdump_udp')

    return


  @tool
  def nmap_msrpc_udp(self):
    """
    DESCR: Scan msrpc service with corresponding NSE scripts. (ext)
    TOOLS: nmap
    """

    opts = '-n -sU -Pn --nsock-engine epoll --script msrpc-enum'
    opts += f" -p {self.target['port']} {self.target['host']}"

    self._run_tool('nmap', opts, nullscan_tool='nmap_msrpc_udp')

    return


# EOF
