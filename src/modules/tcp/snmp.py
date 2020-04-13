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
# snmp.py                                                                      #
#                                                                              #
# AUTHOR                                                                       #
# noptrix@nullsecurity.net                                                     #
#                                                                              #
################################################################################


# sys imports
import concurrent.futures as cf


# own imports
from modules.libs.base import Base, tool, timeout


class SNMP(Base):
  """ SNMP module (tcp/161) """


  def __init__(self, target, opts):
    """ init """

    Base.__init__(self, target, opts)

    return


  @tool
  def snmpwalk(self):
    """
    DESCR: Do SNMP walk using public community string. (ext)
    TOOLS: snmpwalk
    """

    opts = '-c public -v '
    versions = ('1', '2c', '3')
    threads = len(versions)

    with cf.ThreadPoolExecutor(threads) as exe:
      for v in versions:
        cmd = f"snmpwalk {opts} {v} {self.target['host']}"
        exe.submit(self._run_cmd, cmd, 'snmpwalk')

    return


  @tool
  def onesixtyone(self):
    """
    DESCR: Enumerate SNMP service. (ext)
    TOOLS: onesixtyone
    """

    opts = f"{self.target['host']} public"
    self._run_tool('onesixtyone', opts)

    return


  @tool
  def snmpattack(self):
    """
    DESCR: Enumerate and attack SNMP service. (ext)
    TOOLS: snmpattack
    """

    opts = f"-c public,private {self.target['host']}"
    self._run_tool('snmpattack', opts)

    return


  @tool
  def hydra_snmp(self):
    """
    DESCR: Bruteforce SNMP community strings. (ext)
    TOOLS: hydra
    """

    opts = '-e nsr -f'
    threads = len(self.opts['plists'])

    with cf.ThreadPoolExecutor(threads) as exe:
      for p in self.opts['plists']:
        if self._check_file(p):
          cmd = f"hydra {opts} -P {p} snmp://{self.target['host']}"
          exe.submit(self._run_cmd, cmd, 'hydra_snmp')

    return


  @tool
  def nmap_smtp(self):
    """
    DESCR: Scan SNMP service with corresponding NSE scripts. (ext)
    TOOLS: nmap
    """

    opts = '-n -sS -Pn --open --nsock-engine epoll'
    opts += ' --script snmp-hh3c-logins,snmp-info,snmp-interfaces,'
    opts += 'snmp-ios-config,snmp-netstat,snmp-processes,snmp-sysdescr,'
    opts += 'snmp-win32-*'
    opts += f" -p {self.target['port']} {self.target['host']}"

    self._run_tool('nmap', opts, nullscan_tool='nmap_snmp')

    return


# EOF
