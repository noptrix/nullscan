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
# whois.py                                                                     #
#                                                                              #
# AUTHOR                                                                       #
# noptrix@nullsecurity.net                                                     #
#                                                                              #
################################################################################


# sys imports
import json
import concurrent.futures as cf


# own imports
from modules.libs.base import Base, tool, timeout


class Whois(Base):
  """ WHOIS module (host) """


  def __init__(self, target, opts):
    """ init """

    Base.__init__(self, target, opts)

    return


  @tool
  def whois_domain(self):
    """
    DESCR: Perform whois on domain. (int)
    TOOLS: python3
    """

    with timeout(self.opts['timeout']):
      if not self.target['privip']:
        res = self._whois('domain')
        with open('whois_domain.log', 'w') as log:
          for line in res:
            print(line, file=log)

    return


  @tool
  def whois_ipaddr(self):
    """
    DESCR: Perform whois on IP address. (int)
    TOOLS: python3
    """

    with timeout(self.opts['timeout']):
      if not self.target['privip']:
        res = self._whois('ipv4addr')
        for line in res:
          self._log('whois_ipaddr', json.dumps(line, indent=2, sort_keys=True))

    return


  @tool
  def whois_cidr(self):
    """
    DESCR: Get CIDR ranges and ASN descriptions belonging and related to target
           by doing whois lookup on all found subdomains' IPv4 addresses. (int)
    TOOLS: python3
    """

    tmp = '127.0.0.1'

    with timeout(self.opts['timeout']):
      if not self.target['privip']:
        futures = []
        results = []
        with cf.ThreadPoolExecutor(30) as exe:
          for line in self._read_log('all_subdomains_ips'):
            splitted = line.split()
            if len(splitted) < 2:
              continue
            sub = splitted[0]
            ips = splitted[1].split(',') # list of ips
            if tmp != ips[0]: # skip duplicates
              futures.append({exe.submit(self._whois, 'ipv4addr', ips[0]): sub})
            tmp = ips[0]
          for i in futures:
            for f in cf.as_completed(i.keys()):
              sub = i[f]
              for r in f.result():
                results.append(f"{sub} | {r['query']} | " +
                  f"{r['network']['cidr']} | {r['asn_description']}")

        results = list(sorted(set(results)))
        self._log('whois_cidr', results, data_end='\n')

    return


# EOF
