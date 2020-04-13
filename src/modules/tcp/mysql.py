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
# mysql.py                                                                     #
#                                                                              #
# AUTHOR                                                                       #
# noptrix@nullsecurity.net                                                     #
#                                                                              #
################################################################################


# sys imports


# own imports
from modules.libs.base import Base, tool, timeout


class MySQL(Base):
  """ MySQL module (tcp/3306) """


  def __init__(self, target, opts):
    """ init """

    Base.__init__(self, target, opts)

    return


  @tool
  def hydra_mysql(self):
    """
    DESCR: Bruteforce MySQL logins. (ext)
    TOOLS: hydra
    """

    opts = '-e nsr -f'
    self._hydra('mysql', opts)

    return


  @tool
  def nmap_mysql(self):
    """
    DESCR: Scan mysql service with corresponding NSE scripts. (ext)
    TOOLS: nmap
    """

    opts = '-n -sS -Pn --open --nsock-engine epoll'
    opts += ' --script mysql-empty-password,mysql-enum,mysql-info,'
    opts += f"mysql-vuln-cve2012-2122 -p {self.target['port']}"
    opts += f" {self.target['host']}"

    self._run_tool('nmap', opts, nullscan_tool='nmap_mysql')

    return


# EOF
