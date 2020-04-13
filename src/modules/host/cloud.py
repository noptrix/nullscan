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
# cloud.py                                                                     #
#                                                                              #
# AUTHOR                                                                       #
# noptrix@nullsecurity.net                                                     #
#                                                                              #
################################################################################


# sys imports


# own imports
from modules.libs.base import Base, tool, timeout


class Cloud(Base):
  """ Cloud module (host) """


  def __init__(self, target, opts):
    """ init """

    Base.__init__(self, target, opts)

    return


  @tool
  def cloud_buster(self):
    """
    DESCR: Checks for CloudFlare enabled sites for origin IP-addr leaks. (ext)
    TOOLS: cloud-buster
    """

    opts = '--scan mx crimeflare dnsdumpster'

    # this tool makes only sense with domain name.
    if self._is_ipaddr(self.target['host']):
      host = None
      domain = self._read_log('domainname')[0]
      hostname = self._read_log('hostname')[0]
      if domain:
        host = domain
        if hostname and hostname in domain:
          # avoid using r ptr records
          host = hostname
    else:
      # must be hostname and/or domainname
      host = self.target['host']

    opts = f'{host} {opts}'
    self._run_tool('cloud-buster', opts, escape_codes=True)

    return


  @tool
  def cloudmare(self):
    """
    DESCR: Find origin servers of websites protected by CloudFlare with
           misconfigured DNS. (ext)
    TOOLS: cloudmare
    """

    opts = '--subdomain'

    # this tool makes only sense with domain name.
    if self._is_ipaddr(self.target['host']):
      host = None
      domain = self._read_log('domainname')[0]
      hostname = self._read_log('hostname')[0]
      if domain:
        host = domain
        if hostname and hostname in domain:
          # avoid using r ptr records
          host = hostname
    else:
      # target must be hostname and/or domainname
      host = self.target['host']

    opts = f'{opts} {host}'
    precmd = "yes 'y' |"
    self._run_tool('cloudmare', opts, escape_codes=True, precmd=precmd,
      timeout=180)

    return


# EOF
