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
# rpcbind.py                                                                   #
#                                                                              #
# AUTHOR                                                                       #
# noptrix@nullsecurity.net                                                     #
#                                                                              #
################################################################################


# sys imports


# own imports
from modules.libs.base import Base, tool, timeout


class RPCbind(Base):
  """ rpcbind module (tcp/111) """


  def __init__(self, target, opts):
    """ init """

    Base.__init__(self, target, opts)

    return


  @tool
  def rpcinfo(self):
    """
    DESCR: Get remote RPC services. (ext)
    TOOLS: rpcinfo
    """

    opts = f"-p {self.target['host']}"
    self._run_tool('rpcinfo', opts)

    return


  @tool
  def nmap_rpcbind(self):
    """
    DESCR: Scan rpcbind/portmapper service with corresponding NSE scripts. (ext)
    TOOLS: nmap
    """

    opts = '-n -sS -Pn --open --nsock-engine epoll'
    opts += ' --script nfs-ls,nfs-showmount,nfs-statfs,rpc-grind,rpcinfo'
    opts += f" -p {self.target['port']} {self.target['host']}"

    self._run_tool('nmap', opts, nullscan_tool='nmap_rpcbind')

    return


# EOF
