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
# ldap.py                                                                      #
#                                                                              #
# AUTHOR                                                                       #
# noptrix@nullsecurity.net                                                     #
#                                                                              #
################################################################################


# sys imports


# own imports
from modules.libs.base import Base, tool, timeout


class LDAP(Base):
  """ LDAP module (tcp/389) """


  def __init__(self, target, opts):
    """ init """

    Base.__init__(self, target, opts)

    return


  @tool
  def ldapenum(self):
    """
    DESCR: Gather LDAP / AD information. (ext)
    TOOLS: ldapenum
    """

    opts = f"-U -G -E -v -i {self.target['host']}"
    self._run_tool('ldapenum', opts)

    return


  @tool
  def nmap_ldap(self):
    """
    DESCR: Scan ldap service with corresponding NSE scripts. (ext)
    TOOLS: nmap
    """

    opts = '-n -sS -Pn --open --nsock-engine epoll'
    opts += f" --script ldap-rootdse,ldap-search -p {self.target['port']}"
    opts += f" {self.target['host']}"

    self._run_tool('nmap', opts, nullscan_tool='nmap_ldap')

    return


# EOF
