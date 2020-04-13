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
# search.py                                                                    #
#                                                                              #
# AUTHOR                                                                       #
# noptrix@nullsecurity.net                                                     #
#                                                                              #
################################################################################


# sys imports
import requests
import json


# own imports
from modules.libs.base import Base, tool, timeout


class Search(Base):
  """ Search-Engines module (host) """


  def __init__(self, target, opts):
    """ init """

    Base.__init__(self, target, opts)

    self.host = self._get_ipv4addr(self.target['host'])

    return


  @tool
  def shodan(self):
    """
    DESCR: Perform shodan host search to gather information. (int)
    TOOLS: python3
    """

    url = f"https://api.shodan.io/shodan/host/{self.host}?key="
    url += f"{self.opts['shodan_key']}"
    headers = {'User-Agent': self.useragent}

    with timeout(self.opts['timeout']):
      if not self.target['privip']:
        r = requests.get(url, verify=False, headers=headers, timeout=300)
        if r.content:
          parsed = json.loads(r.content.decode('utf-8'))
          self._log('shodan', json.dumps(parsed, indent=2, sort_keys=True))

    return


  @tool
  def domain_urls(self):
    """
    DESCR: Play google: Find URLs (max 100) on target domains. (int)
    TOOLS: python3
    """

    with timeout(self.opts['timeout']):
      def dosearch(domain):
        for url in self._googlesearch(domain):
          host, port, scheme, path = self._parse_url(url)
          if self.target['host'] in host or domain in host:
            self._log('domain_urls', url)
        return

    with timeout(self.opts['timeout']):
      if not self.target['privip']:
        dosearch(self._read_log('domainname')[0])

    return


#  @tool
#  def censys(self):
#    """
#    DESCR: Perform censys host search to gather information. (int)
#    TOOLS: python3
#    """
#
#    url = "https://censys.io/api/v1/search/ipv4"
#
#    return


# EOF
