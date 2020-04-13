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
# finger.py                                                                    #
#                                                                              #
# AUTHOR                                                                       #
# noptrix@nullsecurity.net                                                     #
#                                                                              #
################################################################################


# sys imports
import concurrent.futures as cf


# own imports
from modules.libs.base import Base, tool, timeout


class Finger(Base):
  """ Finger module (tcp/79, tcp/2003) """


  def __init__(self, target, opts):
    """ init """

    Base.__init__(self, target, opts)

    return


  @tool
  def finger(self):
    """
    DESCR: Finger all system users. (ext)
    TOOLS: finger
    """

    cmds = (
      f"finger -l @{self.target['host']}",
      f"finger 0@{self.target['host']}",
      f"finger -l root@{self.target['host']}",
    )
    threads = len(cmds)

    with cf.ThreadPoolExecutor(threads) as exe:
      for cmd in cmds:
        exe.submit(self._run_cmd, cmd, 'finger', timeout=2)

    return


  @tool
  def nmap_finger(self):
    """
    DESCR: Scan finger service with corresponding NSE scripts. (ext)
    TOOLS: nmap
    """

    opts = '-n -sS -Pn --open --nsock-engine epoll --script finger'
    opts += f" -p {self.target['port']} {self.target['host']}"

    self._run_tool('nmap', opts, nullscan_tool='nmap_finger')

    return


# EOF
