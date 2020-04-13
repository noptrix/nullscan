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
  """ SNMP module (udp/161) """


  def __init__(self, target, opts):
    """ init """

    Base.__init__(self, target, opts)

    return


  @tool
  def snmpwalk_udp(self):
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
        exe.submit(self._run_cmd, cmd, 'snmpwalk_udp')

    return


  @tool
  def onesixtyone_udp(self):
    """
    DESCR: Enumerate SNMP service. (ext)
    TOOLS: onesixtyone
    """

    opts = f"{self.target['host']} public"
    self._run_tool('onesixtyone', opts, nullscan_tool='onesixtyone_udp')

    return


  @tool
  def snmpattack_udp(self):
    """
    DESCR: Enumerate and attack SNMP service. (ext)
    TOOLS: snmpattack
    """

    opts = f"-c public,private {self.target['host']}"
    self._run_tool('snmpattack', opts, nullscan_tool='snmpattack_udp')

    return


  @tool
  def hydra_snmp_udp(self):
    """
    DESCR: Bruteforce SNMP community strings. (ext)
    TOOLS: hydra
    """

    opts = '-e nsr -f'
    threads = len(self.opts['plists'])

    with cf.ThreadPoolExecutor(threads) as exe:
      for p in self.opts['plists']:
        if self._check_file(p):
          opts = f"{opts} -P {p} snmp://{self.target['host']}"
          exe.submit(self._run_tool, 'hydra', opts, 'hydra_snmp_udp')

    return


  @tool
  def nmap_smtp_udp(self):
    """
    DESCR: Scan SNMP service with corresponding NSE scripts. (ext)
    TOOLS: nmap
    """

    opts = '-n -sU -Pn --nsock-engine epoll '
    opts += '--script snmp-hh3c-logins,snmp-info,snmp-interfaces,'
    opts += 'snmp-ios-config,snmp-netstat,snmp-processes,snmp-sysdescr,'
    opts += 'snmp-win32-*'
    opts += f" -p {self.target['port']} {self.target['host']}"

    self._run_tool('nmap', opts, nullscan_tool='nmap_snmp_udp')

    return


# EOF
