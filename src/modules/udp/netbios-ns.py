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
# netbios-ns.py                                                                #
#                                                                              #
# AUTHOR                                                                       #
# noptrix@nullsecurity.net                                                     #
#                                                                              #
################################################################################


# sys imports


# own imports
from modules.libs.base import Base, tool, timeout


class NetBiosNs(Base):
  """ NetBIOS-NS module (udp/137) """


  def __init__(self, target, opts):
    """ init """

    Base.__init__(self, target, opts)

    return


  @tool
  def nbtscan_udp(self):
    """
    DESCR: Scan for NetBIOS name infos. (ext)
    TOOLS: nbtscan
    """

    opts = f"-v -r {self.target['host']}"
    self._run_tool('nbtscan', opts, nullscan_tool='nbtscan_udp')

    return


  @tool
  def nmbscan_udp(self):
    """
    DESCR: Scan for NetBIOS shares. (ext)
    TOOLS: nmbscan
    """

    opts = f"-h {self.target['host']}"
    self._run_tool('nmbscan', opts, nullscan_tool='nmbscan_udp')

    return


  @tool
  def enum4linux_udp(self):
    """
    DESCR: Enumerate NetBIOS/SMB infos. (ext)
    TOOLS: enum4linux
    """

    opts = f"-a {self.target['host']}"
    self._run_tool('enum4linux', opts, nullscan_tool='enum4linux_udp')

    return


  @tool
  def nmap_netbios_ns_udp(self):
    """
    DESCR: Scan netbios-ns service with corresponding NSE scripts. (ext)
    TOOLS: nmap
    """

    opts = '-n -sU -Pn --nsock-engine epoll'
    opts += ' --script msrpc-enum,smb2-capabilities,smb2-security-mode,smb-ls,'
    opts += 'smb2-time,smb2-vuln-*,smb-double-pulsar-backdoor,smb-mbenum,'
    opts += 'smb-enum-domains,smb-enum-groups,smb-enum-processes,smb-vuln-*,'
    opts += 'smb-enum-services,smb-enum-sessions,smb-enum-shares,'
    opts += 'smb-os-discovery,smb-protocols,smb-security-mode,smb-server-stats'
    opts += f" -p {self.target['port']} {self.target['host']}"

    self._run_tool('nmap', opts, nullscan_tool='nmap_netbios_ns_udp')

    return


# EOF
