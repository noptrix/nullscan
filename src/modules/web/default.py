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
import concurrent.futures as cf
import json
import random


# own imports
from modules.libs.base import Base, tool, timeout


class Default(Base):
  """ Default module (web) """


  def __init__(self, target, opts):
    """ init """

    Base.__init__(self, target, opts)

    self.host, self.port, self.scheme, self.path = self._parse_url(self.target)

    return


  @tool
  def http_headers_web(self):
    """
    DESCR: Dump HTTP headers via a single HTTP HEAD request. (ext)
    TOOLS: curl
    """

    opts = f"--connect-timeout 3 -m 30 -s -X HEAD -I -A '{self.useragent}'"
    opts += f" --url '{self.target}'"

    self._run_tool('curl', opts, nullscan_tool='http_headers_web', timeout=30)

    return


  @tool
  def http_reqs_web(self):
    """
    DESCR: Send HTTP (head,get,post,options) requests with different HTTP
           versions (0.9,1.0,1.1,2). (ext)
    TOOLS: curl
    """

    threads = 3

    with cf.ThreadPoolExecutor(threads) as exe:
      for t in self.http_req_types:
        for v in self.http_versions:
          opts = f"-v -k --connect-timeout 3 -m 30 -s -A '{self.useragent}'"
          opts += f" -X {t.upper()} --http{v} --url '{self.target}'"
          exe.submit(self._run_tool, 'curl', opts,
            nullscan_tool=f'http_reqs_web_{t}')

    return


  @tool
  def http_put_web(self):
    """
    DESCR: Try to send HTTP PUT request with example data to
           <given URL>+/nullscan.html. (int)
    TOOLS: curl
    """

    opts = f"-k -s --connect-timeout 3 -m 30 -X PUT -A '{self.useragent}'"
    opts += ' -D /dev/stdout --data pwned'
    opts += f" --url '{self.target}nullscan.html'"

    self._run_tool('curl', opts, nullscan_tool='http_put_web')

    return


  @tool
  def proxy_check_web(self):
    """
    DESCR: Check for open HTTP proxy. (ext)
    TOOLS: curl
    """

    opts = f"-I -s -x {self.scheme}://{self.host}:{self.port}/"
    opts += f" -L https://www.blackarch.org/"

    self._run_tool('curl', opts, nullscan_tool='proxy_check_web')

    return


  @tool
  def davscan_web(self):
    """
    DESCR: Scan webserver and test if WebDAV is enabled. (ext)
    TOOLS: davscan
    """

    opts = f'-d -m -D 1 -o /tmp/{random.randint(1,9999999)}'

    if self.opts['user'] and self.opts['pass']:
      opts += f" -a basic -u {self.opts['user']} -p {self.opts['pass']}"
    if self.opts['proxy']:
      opts += f" -P {self.opts['proxy']}"

    opts += f" '{self.target}'"

    self._run_tool('davscan', opts, nullscan_tool='davscan_web', escape_codes=True)

    return


  @tool
  def metoscan_web(self):
    """
    DESCR: Scan for available HTTP methods. (ext)
    TOOLS: metoscan
    """

    self._metoscan(self.host, self.port, scheme=self.scheme)

    return


  @tool
  def httping_web(self):
    """
    DESCR: Ping and measure delay to HTTP server. (ext)
    TOOLS: httping
    """

    self._httping(self.host, self.port, self.scheme)

    return


  @tool
  def halberd_web(self):
    """
    DESCR: Discover http load balancer. (ext)
    TOOLS: halberd
    """

    self._halberd(self.host, self.port, scheme=self.scheme)

    return


  @tool
  def waybackpack(self):
    """
    DESCR: Download a URL-list of snapshots for Wayback Machine archive. (ext)
    TOOLS: waybackpack
    """

    opts = f"--quiet --ignore-errors --user-agent '{self.useragent}' --list"
    opts += f' {self.target}'

    self._run_tool('waybackpack', opts, timeout=180)

    return


  @tool
  def whichcdn(self):
    """
    DESCR: Detect if given website is protected by a Content Delivery Network.
           (ext)
    TOOLS: whichcdn
    """

    opts = f'{self.host}'
    self._run_tool('whichcdn', opts, escape_codes=True)

    return


  @tool
  def nmap_http_web(self):
    """
    DESCR: Scan http service with corresponding NSE scripts. (ext)
    TOOLS: nmap
    """

    nse = 'http-adobe*,http-aff*,http-apache*,http-asp*,http-avaya*,http-awst*,'
    nse += 'http-axis*,http-barra*,http-bigip*,http-cakephp*,http-chrono*,'
    nse += 'http-cisco-*,http-coldfus*,http-date,http-dlink*,http-drupal*,'
    nse += 'http-favicon,http-frontpage*,http-generator,http-git*,http-google*,'
    nse += 'http-headers,http-huawei*,http-iis*,http-internal-ip*,http-litesp*,'
    nse += 'http-majordomo2*,http-malware*,http-mcmp,http-methods,http-ntlm-*,'
    nse += 'http-open-proxy,http-phpmyadm*,http-qnap*,http-robots*,http-robte*,'
    nse += 'http-server-head*,http-shellsh*,http-svn*,http-title,http-tplink*,'
    nse += 'http-trace*,http-trane*,http-vhosts,http-vlc*,http-vmware*,'
    nse += 'http-vuln-*,http-waf*,http-webdav*'

    opts = f'-n -sS -Pn --open --nsock-engine epoll --script {nse}'
    opts += f" --script-args http-methods.url-path={self.path.split('.')[0]}"
    opts += f' -p {self.port} {self.host}'

    self._run_tool('nmap', opts, 'nmap_http_web')

    return


# EOF
