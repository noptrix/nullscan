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
  """ Default module (tcp/*) """


  def __init__(self, target, opts):
    """ init """

    Base.__init__(self, target, opts)

    # default ncat options + proxy options
    self.ncat_opts = '-w 3 -i 1'
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
  def tcp_read(self):
    """
    DESCR: TCP-connect and try to receive data. (ext)
    TOOLS: ncat
    """

    opts = self.ncat_opts
    opts += f" {self.target['host']} {self.target['port']} 2>/dev/null"

    self._run_tool('ncat', opts, nullscan_tool='tcp_read')

    return


  @tool
  def tcp_write(self):
    """
    DESCR: TCP-write few bytes and try to receive response data. (ext)
    TOOLS: ncat
    """

    opts = self.ncat_opts
    opts += f" {self.target['host']} {self.target['port']} 2>/dev/null"
    pre_cmd = "echo -e 'HEAD / HTTP/1.0\\r\\n' |"

    self._run_tool('ncat', opts, nullscan_tool='tcp_write', precmd=pre_cmd)

    return


  @tool
  def tcp_read_ssl(self):
    """
    DESCR: SSL-TCP-read from socket and try to receive response data. (ext)
    TOOLS: ncat
    """

    opts = self.ncat_opts
    opts += f" --ssl {self.target['host']} {self.target['port']} 2>/dev/null"

    self._run_tool('ncat', opts, nullscan_tool='tcp_read_ssl')

    return


  @tool
  def tcp_write_ssl(self):
    """
    DESCR: SSL-TCP-write few bytes and try to receive response data. (ext)
    TOOLS: ncat
    """

    opts = self.ncat_opts
    opts += f" --ssl {self.target['host']} {self.target['port']}"
    pre_cmd = "echo -e 'HEAD / HTTP/1.0\\r\\n' |"

    self._run_tool('ncat', opts, nullscan_tool='tcp_write_ssl', precmd=pre_cmd)

    return


  @tool
  def amap(self):
    """
    DESCR: Read banner and fingerprint service. (ext)
    TOOLS: amap
    """

    opts = f"-bqv -c 64 -C 2 -T 3 -t 3 {self.target['host']}"
    opts += f" {self.target['port']}"

    self._run_tool('amap', opts)

    return


  @tool
  def nmap_default(self):
    """
    DESCR: Version scan service and run default+vulscan NSE scripts. (ext)
    TOOLS: nmap vulscan
    """

    opts = '-n -sSV -Pn --version-all --open --nsock-engine epoll'
    opts += ' --script default,vulscan'
    opts += f" -p {self.target['port']} {self.target['host']}"

    self._run_tool('nmap', opts, nullscan_tool='nmap_default')

    return


# EOF
