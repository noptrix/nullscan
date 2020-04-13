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
# ids.py                                                                       #
#                                                                              #
# AUTHOR                                                                       #
# noptrix@nullsecurity.net                                                     #
#                                                                              #
################################################################################


# sys imports


# own imports
from modules.libs.base import Base, tool, timeout


class Ids(Base):
  """ IDS WiFi module """


  def __init__(self, target, opts):
    """ init """

    Base.__init__(self, target, opts)

    return


  @tool
  def pidense(self):
    """
    DESCR: Monitor illegal wireless network activities. (ext)
    TOOLS: pidense
    """

    # Note: The wifi interface is hardcoded in the tool to wlan0mon
    #       and no arguments supporte, just start the tool.
    tool_name = "pidense"
    force_flush = 'stdbuf -i 0 -o 0 -e 0 '

    self._run_tool(tool_name, "",
      timeout=self.opts['wifi_timeout'],
      precmd=force_flush,
      escape_codes=True
      )

    return


# EOF
