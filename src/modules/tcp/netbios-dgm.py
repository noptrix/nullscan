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
# netbios-dgm.py                                                               #
#                                                                              #
# AUTHOR                                                                       #
# noptrix@nullsecurity.net                                                     #
#                                                                              #
################################################################################


# sys imports


# own imports
from modules.libs.base import Base, tool, timeout


class NetBiosDgm(Base):
  """ NetBIOS-DGM module (tcp/138) """


  def __init__(self, target, opts):
    """ init """

    Base.__init__(self, target, opts)

    return


  @tool
  def rpcdump_dgm(self):
    """
    DESCR: Gather infos over NetBIOS-DGM endpoint. (ext)
    TOOLS: rpcdump.py
    """

    opts = f"-port {self.target['port']} {self.target['host']}"
    self._run_tool('rpcdump.py', opts, 'rpcdump_dgm')

    return


# EOF
