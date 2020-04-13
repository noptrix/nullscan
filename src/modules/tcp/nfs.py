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
# nfs.py                                                                       #
#                                                                              #
# AUTHOR                                                                       #
# noptrix@nullsecurity.net                                                     #
#                                                                              #
################################################################################


# sys imports
import concurrent.futures as cf


# own imports
from modules.libs.base import Base, tool, timeout


class NFS(Base):
  """ NFS module (tcp/2049) """


  def __init__(self, target, opts):
    """ init """

    Base.__init__(self, target, opts)

    return


  @tool
  def showmount(self):
    """
    DESCR: Get infos on exported shares and connected clients. (ext)
    TOOLS: showmount
    """

    sopts = ('-e', '-a')
    threads = len(sopts)

    with cf.ThreadPoolExecutor(threads) as exe:
      for o in sopts:
        opts = f"{o} {self.target['host']}"
        exe.submit(self._run_tool, 'showmount', opts)

    return


  @tool
  def nmap_nfs(self):
    """
    DESCR: Scan nfs service with corresponding NSE scripts. (ext)
    TOOLS: nmap
    """

    opts = '-n -sS -Pn --open --nsock-engine epoll'
    opts += ' --script nfs-ls,nfs-showmount,nfs-statfs,'
    opts += f" -p {self.target['port']} {self.target['host']}"

    self._run_tool('nmap', opts, nullscan_tool='nmap_nfs')

    return


# EOF
