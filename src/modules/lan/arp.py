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
# arp.py                                                                       #
#                                                                              #
# AUTHOR                                                                       #
# noptrix@nullsecurity.net                                                     #
#                                                                              #
################################################################################


# sys imports


# own imports
from modules.libs.base import Base, tool, timeout


class ARP(Base):
  """ ARP module (lan) """


  def __init__(self, target, opts):
    """ init """

    Base.__init__(self, target, opts)

    return


  @tool
  def arpsweep(self):
    """
    DESCR: Discover alive hosts in current active network. (ext)
    TOOLS: nmap
    """

    opts = '-sn -n --host-timeout 3s --max-retries 2 --min-rate 1000'
    opts += ' --nsock-engine epoll'

    networks = self._read_log('cidr_range')

    if networks:
      for net in networks:
        if self._is_ipaddr(net.split('/')[0]) == 'ipv4':
          cmd = f'nmap {opts} {net}'
          res = self._run_cmd(cmd)
    else:
      cmd = 'nmap --iflist'
      res = self._run_cmd(cmd)
      for line in res:
        if self.target in line:
          if 'up' in line:
            net = line.split()[2]
      cmd = f'nmap {opts} {net}'
      res = self._run_cmd(cmd)

    # remove nmap lines containing these words including our own ipaddr
    if self.opts['shost']:
      srcip = self.opts['shost']
    else:
      srcip = self._read_log('src_ip')[0]
    del_words = ('Starting', 'Host is up', 'Nmap done', 'Stats', srcip)
    for word in del_words:
      for idx, line in enumerate(res):
        if word in line:
          res.pop(idx)

    # now just filter ipaddr, macaddr and hw info
    del_words = ('Nmap scan report for ', 'MAC Address: ')
    for word in del_words:
      res = [i.replace(word, '') for i in res]
    res = {res[i]: res[i + 1] for i in range(0, len(res), 2)}

    # log found active hosts
    resl = []
    for k, v in res.items():
      resl.append(f'{k} {v}\n')
    self._log('arpsweep', resl)

    return


# EOF
