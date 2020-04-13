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


# own imports
from modules.libs.base import Base, tool, timeout


class Default(Base):
  """ Default module (udp/*) """


  def __init__(self, target, opts):
    """ init """

    Base.__init__(self, target, opts)

    # default ncat options + proxy options
    self.ncat_opts = '-w 3 -i 1 -u'
    if self.opts['proxy']:
      host, port, scheme, path = self._parse_url(self.opts['proxy'])
      proxy = f'{host}:{port}'
      if self.opts['proxy_user'] and self.opts['proxy_pass']:
        proxy_user = self.opts['proxy_user']
        proxy_pass = self.opts['proxy_pass']
      self.ncat_opts += f' --proxy {proxy} --proxy-type {scheme}'
      if proxy_user and proxy_pass:
        self.ncat_opts += f' --proxy-auth {proxy_user}:{proxy_pass}'

    return


  @tool
  def udp_read(self):
    """
    DESCR: UDP-connect and try to receive data. (ext)
    TOOLS: ncat
    """

    opts = self.ncat_opts
    opts += f" {self.target['host']} {self.target['port']} 2>/dev/null"

    self._run_tool('ncat', opts, nullscan_tool='udp_read')

    return


  @tool
  def udp_write(self):
    """
    DESCR: UDP-connect and write few bytes to get a response. (ext)
    TOOLS: ncat
    """

    opts = self.ncat_opts
    opts += f" {self.target['host']} {self.target['port']} 2>/dev/null"
    pre_cmd = "echo -e 'HEAD / HTTP/1.0\\r\\n' |"

    self._run_tool('ncat', opts, nullscan_tool='udp_write', precmd=pre_cmd)

    return


  @tool
  def udp_read_ssl(self):
    """
    DESCR: SSL-UDP-connect and try to receive data. (ext)
    TOOLS: ncat
    """

    opts = self.ncat_opts
    opts += f" --ssl {self.target['host']} {self.target['port']} 2>/dev/null"

    self._run_tool('ncat', opts, nullscan_tool='udp_read_ssl')

    return


  @tool
  def udp_write_ssl(self):
    """
    DESCR: SSL-UDP-connect and write few bytes to receive response data. (ext)
    TOOLS: ncat
    """

    opts = self.ncat_opts
    opts += f" --ssl {self.target['host']} {self.target['port']}"
    pre_cmd = "echo -e 'HEAD / HTTP/1.0\\r\\n' |"

    self._run_tool('ncat', opts, nullscan_tool='udp_write_ssl', precmd=pre_cmd)

    return


  @tool
  def amap_udp(self):
    """
    DESCR: Read banner and fingerprint service. (ext)
    TOOLS: amap
    """

    opts = f"-bqv -u -c 64 -C 2 -T 3 -t 3"
    opts += f" {self.target['host']} {self.target['port']}"

    self._run_tool('amap', opts, nullscan_tool='amap_udp')

    return


  @tool
  def nmap_default_udp(self):
    """
    DESCR: Version scan service and run default+vulscan NSE scripts. (ext)
    TOOLS: nmap vulscan
    """

    opts = '-n -sUV -Pn --version-all --nsock-engine epoll'
    opts += ' --script default,vulscan'
    opts += f" -p {self.target['port']} {self.target['host']}"

    self._run_tool('nmap', opts, nullscan_tool='nmap_default_udp')

    return


# EOF
