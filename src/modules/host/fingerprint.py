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
# fingerprint.py                                                               #
#                                                                              #
# AUTHOR                                                                       #
# noptrix@nullsecurity.net                                                     #
#                                                                              #
################################################################################


# sys imports
import concurrent.futures as cf


# own imports
from modules.libs.base import Base, tool, timeout


class Fingerprint(Base):
  """ Fingerprint module (host) """


  def __init__(self, target, opts):
    """ init """

    Base.__init__(self, target, opts)

    self.ports = self._make_portlist(self.def_tcp_ports)

    return


  @tool
  def nmap_os(self):
    """
    DESCR: Fingerprint the remote OS via TCP/IP stack. (ext)
    TOOLS: nmap
    """

    opts = ' '.join(self.opts['nmap']) + ' -n -O --osscan-guess --open -p'
    opts += f" {self.ports} {self.target['host']}"

    self._run_tool('nmap', opts, 'nmap_os')

    return


  @tool
  def sinfp(self):
    """
    DESCR: Fingerprint remote OS via TCP/IP stack. (ext)
    TOOLS: sinfp
    """

    opts = f"-target {self.target['host']} -db-file /usr/share/sinfp/sinfp3.db"
    opts += ' -synscan-fingerprint -pps 500 -retry 1 -input-ipport -timeout 2'
    opts += f' -jobs 15 -best-score -port {self.ports}'

    self._run_tool('sinfp', opts, timeout=300)

    return


  @tool
  def http_os(self):
    """
    DESCR: Fingerprint remote OS via HTTP(S) banner. (ext)
    TOOLS: curl
    """

    opts = '-s --http1.1 --head --connect-timeout 3 -k'
    threads = 2

    def cb(opts, prot):
      cmd = f"curl {opts} {prot}://{self.target['host']}/"
      res = self._run_cmd(cmd)
      for line in res:
        if 'Server:' in line:
          banner = f"{prot}: {line.split(': ')[1]}"
          self._log('http_os', banner)
      return

    with cf.ThreadPoolExecutor(threads) as exe:
      for h in ('http', 'https'):
        exe.submit(cb, opts, h)

    return


# EOF
