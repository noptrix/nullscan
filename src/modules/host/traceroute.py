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
# traceroute.py                                                                #
#                                                                              #
# AUTHOR                                                                       #
# noptrix@nullsecurity.net                                                     #
#                                                                              #
################################################################################


# sys imports


# own imports
from modules.libs.base import Base, tool, timeout


class Traceroute(Base):
  """ Traceroute module (host) """

  timeout = 60  # default global timeout


  def __init__(self, target, opts):
    """ init """

    Base.__init__(self, target, opts)

    return


  @tool
  def traceroute(self):
    """
    DESCR: Trace the net route to target. (ext)
    TOOLS: traceroute
    """

    opts = f"-q 2 -w 3 -4 {self.target['host']}"

    if not self.target['privip']:
      self._run_tool('traceroute', opts, timeout=Traceroute.timeout)

    return


  @tool
  def tcptraceroute(self):
    """
    DESCR: Trace the net route to target via TCP. (ext)
    TOOLS: tcptraceroute
    """

    opts = f"-q 2 -w 2 {self.target['host']}"

    if not self.target['privip']:
      self._run_tool('tcptraceroute', opts, timeout=Traceroute.timeout)

    return


# EOF
