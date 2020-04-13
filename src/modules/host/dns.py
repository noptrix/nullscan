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
# dns.py                                                                       #
#                                                                              #
# AUTHOR                                                                       #
# noptrix@nullsecurity.net                                                     #
#                                                                              #
################################################################################


# sys imports
import concurrent.futures as cf
import dns.query
import dns.zone
import socket
import os


# own imports
from modules.libs.base import Base, tool, timeout


class DNS(Base):
  """ DNS module (host) """


  def __init__(self, target, opts):
    """ init """

    Base.__init__(self, target, opts)

    return


  @tool
  def dnsrecords(self):
    """
    DESCR: Find available DNS records. (int)
    TOOLS: python3
    """

    with timeout(self.opts['timeout']):
      threads = 5
      if not self.target['privip']:
        with cf.ThreadPoolExecutor(threads) as exe:
          for rt in self.dns_record_types:
            if rt != 'a' and rt != 'aaaa' and rt != 'ptr' and rt != 'mx':
              exe.submit(self._dns_query, rt, 'dnsrecords')

    return


  @tool
  def zonetransfer(self):
    """
    DESCR: Perform DNS zonetransfer. (int)
    TOOLS: python3
    """

    with timeout(self.opts['timeout']):
      threads = 5

      def runcmd(dom, nmsrv):
        z = dns.zone.from_xfr(dns.query.xfr(nmsrv, dom, lifetime=5, timeout=5))
        if z:
          names = z.nodes.keys()
          for name in names:
            self._log(f'zonetransfer', z[name].to_text(name))
        return

      if not self.target['privip']:
        dom = self._read_log('domainname')[0]
        with cf.ThreadPoolExecutor(threads) as exe:
          for n in self._read_log('nameserver'):
            if dom and n:
              exe.submit(runcmd, dom, n)

    return


  @tool
  def dnsenum(self):
    """
    DESCR: Collect DNS infos and perform zonetransfer. (ext)
    TOOLS: dnsenum
    """

    opts = f"--nocolor --threads 10 -s 50 {self.target['host']}"

    if not self.target['privip']:
      self._run_tool('dnsenum', opts)

    return


  @tool
  def dnsspider(self):
    """
    DESCR: Scan for subdomains. (ext)
    TOOLS: dnsspider
    """

    opts = '-t 0 -x 50 '

    if not self.target['privip']:
      domain = self._read_log('domainname')[0]
      if domain:
        opts += f' -r dnsspider.log -a {domain}'
        self._run_tool('dnsspider', opts, create_log=False)

    return


  @tool
  def ripdc(self):
    """
    DESCR: Scan for neighbour domains. (ext)
    TOOLS: ripdc
    """

    res = []
    data = []

    if not self.target['privip']:
      res = self._run_cmd(f"ripdc -t {self.target['host']}")

      # also do for domain if present
      domain = self._read_log('domainname')[0]
      if domain:
        if domain != self.target['host']:
          res += self._run_cmd(f"ripdc -t {domain.strip()}")

    for line in res:
      if '> ' in line:
        data.append(line.split()[1])

    self._log('ripdc', data, data_end='\n')

    return


  @tool
  def findomain(self):
    """
    DESCR: Scan for subdomains via certificate transparency logs and APIs. (ext)
    TOOLS: findomain
    """

    opts = f'-o'

    if not self.target['privip']:
      domain = self._read_log('domainname')[0]
      if domain:
        opts += f' -t {domain}'
        self._run_tool('findomain', opts, create_log=False)
        self._run_cmd(f'cat {domain}.txt', nullscan_tool='findomain')

    return


  @tool
  def all_subdomains(self):
    """
    DESCR: Merge all found subdomains from various tools into a single list.
           (int)
    TOOLS: python3
    """

    with timeout(self.opts['timeout']):
      if not self.target['privip']:
        res_dnsspider = self._read_log('dnsspider')
        res_findomain = self._read_log('findomain')
        subdomains = list(sorted(set(res_dnsspider + res_findomain)))
        subdomains = [sd for sd in subdomains if len(sd) > 0]
        self._log('all_subdomains', subdomains, data_end='\n')

      return


  @tool
  def all_subdomains_ips(self):
    """
    DESCR: Make a 'subdomain + ipv4addr' list out of all subdomains. (int)
    TOOLS: python3
    """

    with timeout(self.opts['timeout']):
      def get_ipaddr(host):
        try:
          return (host, socket.gethostbyname_ex(host)[-1])
        except Exception as e:
          self._log('error', f"host {host} not found --> {e}")
          return None
        return

      if not self.target['privip']:
        futures = []
        pairs = []
        res = self._read_log('all_subdomains')
        with cf.ThreadPoolExecutor(30) as exe:
          for host in res:
            futures.append(exe.submit(get_ipaddr, host))
          for x in cf.as_completed(futures):
            if x.result():
              pairs.append(x.result())
        with open('all_subdomains_ips.log', 'a', encoding='latin-1') as log:
          for p in pairs:
            if p[0] != '0.0.0.0' and '0.0.0.0' not in p[1]:
              print(p[0], ",".join(p[1]), file=log)

    return


# EOF
