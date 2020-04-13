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
# netbios-ssn.py                                                               #
#                                                                              #
# AUTHOR                                                                       #
# noptrix@nullsecurity.net                                                     #
#                                                                              #
################################################################################


# sys imports


# own imports
from modules.libs.base import Base, tool, timeout


class NetBiosSsn(Base):
  """ NetBIOS-SSN module (tcp/139) """


  def __init__(self, target, opts):
    """ init """

    Base.__init__(self, target, opts)

    return


  @tool
  def rpcdump_ssn(self):
    """
    DESCR: Get infos over NetBIOS-SSN service. (ext)
    TOOLS: rpcdump.py
    """

    opts = f"-port {self.target['port']} {self.target['host']}"
    self._run_tool('rpcdump.py', opts, 'rpcdump_ssn')

    return


  @tool
  def smbdumpusers(self):
    """
    DESCR: Dump users from SMB endpoint. (ext)
    TOOLS: smbdumpusers
    """

    opts = f"-i {self.target['host']} -m 1"
    self._run_tool('smbdumpusers', opts, timeout=15)

    return


  @tool
  def netbios_share_scanner(self):
    """
    DESCR: Scan for open NetBIOS/SMB shares. (ext)
    TOOLS: netbios-share-scanner
    """

    opts = f"{self.target['host']}"
    self._run_tool('netbios-share-scanner', opts, 'netbios_share_scanner')

    return


  @tool
  def nmap_netbios_ssn(self):
    """
    DESCR: Scan NetBIOS-SSN service with corresponding NSE scripts. (ext)
    TOOLS: nmap
    """

    opts = '-n -sS -Pn --open --nsock-engine epoll'
    opts += ' --script msrpc-enum,smb2-capabilities,smb2-security-mode,smb-ls,'
    opts += 'smb2-time,smb2-vuln-*,smb-double-pulsar-backdoor,smb-mbenum,'
    opts += 'smb-enum-domains,smb-enum-groups,smb-enum-processes,smb-vuln-*,'
    opts += 'smb-enum-services,smb-enum-sessions,smb-enum-shares,'
    opts += 'smb-os-discovery,smb-protocols,smb-security-mode,smb-server-stats'
    opts += f" -p {self.target['port']} {self.target['host']}"

    self._run_tool('nmap', opts, nullscan_tool='nmap_netbios_ssn')

    return


# EOF
