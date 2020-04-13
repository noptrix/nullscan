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
# ident.py                                                                     #
#                                                                              #
# AUTHOR                                                                       #
# noptrix@nullsecurity.net                                                     #
#                                                                              #
################################################################################


# sys imports


# own imports
from modules.libs.base import Base, tool, timeout


class Ident(Base):
  """ Ident module (tcp/113) """


  def __init__(self, target, opts):
    """ init """

    Base.__init__(self, target, opts)

    return


  @tool
  def ident_version(self):
    """
    DESCR: Try to get ident version and other system information. (ext)
    TOOLS: ncat
    """

    opts = f"-w 3 -i 1 {self.target['host']} {self.target['port']}"
    pre_cmd = "echo -e 'version\\r\\n' |"

    self._run_tool('ncat', opts, nullscan_tool='ident_version', precmd=pre_cmd)

    return


  @tool
  def nmap_ident(self):
    """
    DESCR: Scan ident service with corresponding NSE scripts. (ext)
    TOOLS: nmap
    """

    opts = '-n -sS -Pn --open --nsock-engine epoll'
    opts += f" --script auth-owners,auth-spoof -p {self.target['port']}"
    opts += f" {self.target['host']}"

    self._run_tool('nmap', opts, nullscan_tool='nmap_ident')

    return


# EOF
