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
# ntp.py                                                                       #
#                                                                              #
# AUTHOR                                                                       #
# noptrix@nullsecurity.net                                                     #
#                                                                              #
################################################################################


# sys imports
import concurrent.futures as cf


# own imports
from modules.libs.base import Base, tool, timeout


class NTP(Base):
  """ NTP module (tcp/123) """


  def __init__(self, target, opts):
    """ init """

    Base.__init__(self, target, opts)

    return


  @tool
  def ntp_infos(self):
    """
    DESCR: Query ntpd to gather infos about system, states, peers etc. (ext)
    TOOLS: ntpdc
    """

    opts = '-c'
    ntp_cmds = ('peers', 'kerninfo', 'sysinfo', 'sysstats', 'memstats',
      'iostats', 'monlist')
    threads = len(ntp_cmds)

    with cf.ThreadPoolExecutor(threads) as exe:
      for c in ntp_cmds:
        cmd = f"ntpdc {opts} {c} {self.target['host']}"
        exe.submit(self._run_cmd, cmd, 'ntp_infos')

    return


  @tool
  def nmap_ntp(self):
    """
    DESCR: Scan ntp service with corresponding NSE scripts. (ext)
    TOOLS: nmap
    """

    opts = '-n -sS -Pn --open --nsock-engine epoll'
    opts += ' --script ntp-info,ntp-monlist,'
    opts += f" -p {self.target['port']} {self.target['host']}"

    self._run_tool('nmap', opts, nullscan_tool='nmap_ntp')

    return


# EOF
