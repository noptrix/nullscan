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
# default.py                                                                   #
#                                                                              #
# AUTHOR                                                                       #
# noptrix@nullsecurity.net                                                     #
#                                                                              #
################################################################################


# sys imports
import netifaces
import getmac
import netaddr


# own imports
from modules.libs.base import Base, tool, timeout


class Default(Base):
  """ Default module (lan) """


  def __init__(self, target, opts):
    """ init """

    Base.__init__(self, target, opts)

    self._check_iputils()
    self.uname = self._get_uname()[0]

    return


  @tool
  def src_ip(self):
    """
    DESCR: Get source IP address of local device. (int)
    TOOLS: python3
    """

    with timeout(self.opts['timeout']):
      if not self.opts['shost']:
        ip = netifaces.ifaddresses(self.target)[netifaces.AF_INET][0]['addr']
        self._log('src_ip', ip)
      else:
        self._log('src_ip', self.opts['shost'])

    return


  @tool
  def src_mac(self):
    """
    DESCR: Get source MAC address of local device. (int)
    TOOLS: python3
    """

    with timeout(self.opts['timeout']):
      if not self.opts['smac']:
        mac = netifaces.ifaddresses(self.target)[netifaces.AF_LINK][0]['addr']
        self._log('src_mac', mac)
      else:
        self._log('src_mac', self.opts['smac'])

    return


  @tool
  def netmask(self):
    """
    DESCR: Get sub netmask address of local device. (int)
    TOOLS: python3
    """

    with timeout(self.opts['timeout']):
      mask = netifaces.ifaddresses(self.target)[netifaces.AF_INET][0]['netmask']
      self._log('netmask', mask)

    return


  @tool
  def broadcast(self):
    """
    DESCR: Get broadcast address of local device. (int)
    TOOLS: python3
    """

    with timeout(self.opts['timeout']):
      brd = netifaces.ifaddresses(self.target)[netifaces.AF_INET][0]['broadcast']
      self._log('broadcast', brd)

    return


  @tool
  def router_ip(self):
    """
    DESCR: Get IP address of default gateway. (int)
    TOOLS: python3
    """

    with timeout(self.opts['timeout']):
      if not self.opts['rhost']:
        ip = list(netifaces.gateways()['default'].values())[0][0]
        self._log('router_ip', ip)
      else:
        self._log('router_ip', self.opts['rhost'])

    return


  @tool
  def router_mac(self):
    """
    DESCR: Get MAC address of default gateway. (int)
    TOOLS: python3
    """

    with timeout(self.opts['timeout']):
      if not self.opts['rmac']:
        router_ip = self._read_log('router_ip')
        addr = getmac.get_mac_address(ip=router_ip[0])
        self._log('router_mac', addr)
      else:
        self._log('router_mac', self.opts['rmac'])

    return


  @tool
  def cidr_range(self):
    """
    DESCR: Get IPv4 network in CIDR range format. (int)
    TOOLS: python3
    """

    with timeout(self.opts['timeout']):
      if self.opts['shost']:
        ip = self.opts['shost']
      else:
        ip = self._read_log('src_ip')[0]

      netmask = self._read_log('netmask')[0]
      cidr = str(netaddr.IPNetwork(f'{ip}/{netmask}'))
      self._log('cidr_range', cidr)

    return


  @tool
  def host_range(self):
    """
    DESCR: Get IPv4 network in host range format. (int)
    TOOLS: python3
    """

    with timeout(self.opts['timeout']):
      cidr = self._read_log('cidr_range')[0]
      net = netaddr.IPNetwork(cidr)

      if not cidr.endswith('32'):
        start = str(net[1])
        end = str(net[-2])
        self._log('host_range', f'{start}-{end}')
      else:
        start = cidr.rstrip('/32')
        end = start
        self._log('host_range', f'{start}-{end}')

    return


# EOF
