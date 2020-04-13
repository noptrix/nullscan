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
# smtp.py                                                                      #
#                                                                              #
# AUTHOR                                                                       #
# noptrix@nullsecurity.net                                                     #
#                                                                              #
################################################################################


# sys imports


# own imports
from modules.libs.base import Base, tool, timeout


class SMTP(Base):
  """ SMTP module (tcp/25) """


  def __init__(self, target, opts):
    """ init """

    Base.__init__(self, target, opts)

    return


  @tool
  def smtptx(self):
    """
    DESCR: Check for open relay. (ext)
    TOOLS: smtptx
    """

    opts = '-f root@nsa.gov -t billy@microsoft.com -m t3st -s t3st -e '
    opts += f"-p {self.target['port']} -S {self.target['host']}"

    self._run_tool('smtptx', opts, timeout=10)

    return


  @tool
  def smtpscan(self):
    """
    DESCR: Fingerprint SMTP server. (ext)
    TOOLS: smtpscan
    """

    fprints = '/usr/share/smtpscan/fingerprints'
    tests = '/usr/share/smtpscan/tests'

    opts = f"-f {fprints} -t {tests} -p {self.target['port']}"
    opts += f" {self.target['host']}"

    self._run_tool('smtpscan', opts)

    return


  @tool
  def smtp_fuzz(self):
    """
    DESCR: Fuzz SMTP service. (ext)
    TOOLS: smtp-fuzz
    """

    opts = f"{self.target['host']} {self.target['port']}"
    self._run_tool('smtp-fuzz', opts, 'smtp_fuzz')

    return


  @tool
  def hydra_smtp(self):
    """
    DESCR: Bruteforce SMTP logins. (ext)
    TOOLS: hydra
    """

    opts = '-e nsr -f'
    self._hydra('smtp', opts)

    return


  @tool
  def nmap_smtp(self):
    """
    DESCR: Scan SMTP service with corresponding NSE scripts. (ext)
    TOOLS: nmap
    """

    opts = '-n -sS -Pn --open --nsock-engine epoll'
    opts += ' --script smtp-commands,smtp-enum-users,smtp-ntlm-info,'
    opts += 'smtp-open-relay,smtp-vuln-cve2010-4344,smtp-vuln-cve2011-1720,'
    opts += 'smtp-vuln-cve2011-1764'
    opts += f" -p {self.target['port']} {self.target['host']}"

    self._run_tool('nmap', opts, nullscan_tool='nmap_smtp')

    return


# EOF
