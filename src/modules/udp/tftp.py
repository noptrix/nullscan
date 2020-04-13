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
# tftp.py                                                                      #
#                                                                              #
# AUTHOR                                                                       #
# noptrix@nullsecurity.net                                                     #
#                                                                              #
################################################################################


# sys imports


# own imports
from modules.libs.base import Base, tool, timeout


class TFTP(Base):
  """ TFTP module (udp/69) """


  def __init__(self, target, opts):
    """ init """

    Base.__init__(self, target, opts)

    return


  @tool
  def atftp_passwd(self):
    """
    DESCR: Connect and get /etc/passwd. (ext)
    TOOLS: atftp
    """

    opts = f"--verbose -g -r /etc/passwd -l passwd {self.target['host']}"
    opts += f" {self.target['port']}"

    self._run_tool('atftp', opts, nullscan_tool='atftp_passwd', timeout=300)

    return


  @tool
  def tftp_fuzz(self):
    """
    DESCR: Fuzz TFTP service. (ext)
    TOOLS: tftp-fuzz
    """

    opts = f"-t {self.target['host']}"
    self._run_tool('tftp-fuzz', opts, nullscan_tool='tftp_fuzz', timeout=300)

    return


  @tool
  def nmap_tftp(self):
    """
    DESCR: Scan tftp service with corresponding NSE scripts. (ext)
    TOOLS: nmap
    """

    opts = '-n -sU -Pn --nsock-engine epoll --script tftp-enum'
    opts += f" -p {self.target['port']} {self.target['host']}"

    self._run_tool('nmap', opts, nullscan_tool='nmap_tftp')

    return


# EOF
