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
import socket
import os
import time
import ipwhois


# own imports
from modules.libs.base import Base, tool, timeout


class Default(Base):
  """ Default module (host) """


  def __init__(self, target, opts):
    """ init """

    Base.__init__(self, target, opts)

    return


  @tool
  def ipv4addr(self):
    """
    DESCR: Get IPv4 address. (int)
    TOOLS: python3
    """

    with timeout(self.opts['timeout']):
      if self._is_ipaddr(self.target['host']) == 'ipv4':
        self._log('ipv4addr', self.target['host'])
      else:
        try:
          self._log('ipv4addr', socket.gethostbyname(self.target['host']))
        except:
          pass

    return


  @tool
  def ipv6addr(self):
    """
    DESCR: Get IPv6 address. (int)
    TOOLS: python3
    """

    with timeout(self.opts['timeout']):
      if self._is_ipaddr(self.target['host']) == 'ipv6':
        self._log('ipv6addr', self.target['host'])
      else:
        try:
          alladdr = socket.getaddrinfo(self.target['host'], None)
          if alladdr:
            ip6 = filter(lambda x: x[0] == socket.AF_INET6, alladdr)
          if ip6:
            ip6list = list(ip6)[0][4][0]
          if ip6list:
            self._log('ipv6addr', ip6list)
        except:
          pass

    return


  @tool
  def hostname(self):
    """
    DESCR: Get hostname. (int)
    TOOLS: python3
    """

    with timeout(self.opts['timeout']):
      if self._is_ipaddr(self.target['host']):
        try:
          self._log('hostname', socket.gethostbyaddr(self.target['host'])[0])
        except:
          pass
      else:
        self._log('hostname', self.target['host'])

    return


  @tool
  def domainname(self):
    """
    DESCR: Get domain names. (int)
    TOOLS: python3
    """

    with timeout(self.opts['timeout']):
      if not self.target['privip']:
        if self._is_ipaddr(self.target['host']):
          try:
            domain = socket.gethostbyaddr(self.target['host'])[0].split('.')[-2:]
            domain = '.'.join(domain)
            self._log('domainname', domain)
          except:
            pass
        else:
          # just in case that we have a subdomain we need to get domain only
          domain = '.'.join(self.target['host'].split('.')[-2:])
          self._log('domainname', domain)

    return


  @tool
  def nameserver(self):
    """
    DESCR: Get nameserver hosts. (int)
    TOOLS: python3
    """

    with timeout(self.opts['timeout']):
      if not self.target['privip']:
        self._dns_query('ns', 'nameserver', 'domainname')

    return


  @tool
  def mailserver(self):
    """
    DESCR: Get mailserver hosts. (int)
    TOOLS: python3
    """

    with timeout(self.opts['timeout']):
      if not self.target['privip']:
        self._dns_query('mx', 'mailserver', 'domainname')

    return


  @tool
  def ipv4range(self):
    """
    DESCR: Get IPv4 address range in host range and cidr format. (int)
    TOOLS: python3
    """

    with timeout(self.opts['timeout']):
      if not self.target['privip']:
        try:
          ipaddr = self._read_log('ipv4addr')[0]
          if ipaddr:
            res = ipwhois.IPWhois(ipaddr).lookup_whois()
            iprange = res['nets'][0]['range'].replace(' ', '')
            cidr = res['nets'][0]['cidr'].replace(' ', '')
            self._log('ipv4range', iprange)
            self._log('ipv4cidr', cidr)
        except:
          pass

    return


# EOF
