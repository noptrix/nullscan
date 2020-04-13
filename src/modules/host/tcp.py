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
# tcp.py                                                                       #
#                                                                              #
# AUTHOR                                                                       #
# noptrix@nullsecurity.net                                                     #
#                                                                              #
################################################################################


# sys imports
import concurrent.futures as cf


# own imports
from modules.libs.base import Base, tool, timeout


class TCP(Base):
  """ TCP module (host) """


  def __init__(self, target, opts):
    """ init """

    Base.__init__(self, target, opts)

    return


  @tool
  def tcp_timestamp(self):
    """
    DESCR: Gather TCP timestamp from remote host. (ext)
    TOOLS: hping hping3
    """

    threads = 10
    opts = '-S --tcp-timestamp -c 3'

    if not self.target['privip']:
      with cf.ThreadPoolExecutor(threads) as exe:
        for p in self.def_tcp_ports:
          _opts = f" {opts} -p {p} {self.target['host']}"
          exe.submit(self._run_tool, 'hping3', _opts, 'tcp_timestamp')

    return


# EOF
