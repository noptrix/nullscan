#!/usr/bin/env python3
# -*- coding: utf-8 -*- ########################################################
#               ____                     _ __                                  #
#    ___  __ __/ / /__ ___ ______ ______(_) /___ __                            #
#   / _ \/ // / / (_-</ -_) __/ // / __/ / __/ // /                            #
#  /_//_/\_,_/_/_/___/\__/\__/\_,_/_/ /_/\__/\_, /                             #
#                                           /___/ team                         #
#                                                                              #
# nullscan                                                                     #
# modular framework designed to chain and automate security tests              #
#                                                                              #
# FILE                                                                         #
# ncube-lm.py                                                                  #
#                                                                              #
# AUTHOR                                                                       #
# noptrix@nullsecurity.net                                                     #
#                                                                              #
################################################################################


# sys imports
import concurrent.futures as cf


# own imports
from modules.libs.base import Base, tool, timeout


class NcubeLM(Base):
  """ Ncube-lm and Oracle TNS module (tcp/1521) """


  def __init__(self, target, opts):
    """ init """

    Base.__init__(self, target, opts)

    return


  @tool
  def tnscmd(self):
    """
    DESCR: Get infos from Oracle TNS listener. (ext)
    TOOLS: tnscmd
    """

    tns_cmds = ('ping', 'version', 'status')
    threads = len(tns_cmds)

    with cf.ThreadPoolExecutor(threads) as exe:
      for tc in tns_cmds:
        opts = f"{tc} -p {self.targt['port']} -h {self.target['host']}"
        exe.submit(self._run_tool, 'tnscmd', opts)

    return


  @tool
  def nmap_oracle(self):
    """
    DESCR: Scan oracle (tns) service with corresponding NSE scripts. (ext)
    TOOLS: nmap
    """

    opts = '-n -sS -Pn --open --nsock-engine epoll'
    opts += ' --script oracle-enum-users,oracle-sid-brute,oracle-tns-version'
    opts += f" -p {self.target['port']} {self.target['host']}"

    self._run_tool('nmap', opts, nullscan_tool='nmap_oracle')

    return


# EOF
