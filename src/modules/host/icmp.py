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
# icmp.py                                                                      #
#                                                                              #
# AUTHOR                                                                       #
# noptrix@nullsecurity.net                                                     #
#                                                                              #
################################################################################


# sys imports
import concurrent.futures as cf


# own imports
from modules.libs.base import Base, tool, timeout


class ICMP(Base):
  """ ICMP module (host) """


  def __init__(self, target, opts):
    """ init """

    Base.__init__(self, target, opts)

    return


  @tool
  def icmp_fuzz(self):
    """
    DESCR: Send all ICMP types and codes. (ext)
    TOOLS: nping
    """

    threads = 15

    if not self.target['privip']:
      with cf.ThreadPoolExecutor(threads) as exe:
        for name, v in self.icmp_types.items():
          for _type, codes in v.items():
            for code in codes:
              exe.submit(self._icmp_req, name, _type, code, 2)

    return


# EOF
