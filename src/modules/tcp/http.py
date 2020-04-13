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
# http.py                                                                      #
#                                                                              #
# AUTHOR                                                                       #
# noptrix@nullsecurity.net                                                     #
#                                                                              #
################################################################################


# sys imports
import concurrent.futures as cf
from collections import deque
import json


# own imports
from modules.libs.base import Base, tool, timeout


class HTTP(Base):
  """ HTTP module (tcp/80,8000,8080,8888) """


  def __init__(self, target, opts):
    """ init """

    Base.__init__(self, target, opts)

    return


  @tool
  def http_headers(self):
    """
    DESCR: Dump HTTP headers via a single HTTP HEAD request. (ext)
    TOOLS: curl
    """

    opts = f"--connect-timeout 3 -m 30 -s -X HEAD -I -A '{self.useragent}'"
    opts += f" --url http://{self.target['host']}:{self.target['port']}/"

    self._run_tool('curl', opts, nullscan_tool='http_headers', timeout=30)

    return


  @tool
  def http_reqs(self):
    """
    DESCR: Send HTTP (head,get,post,options) requests with different HTTP
           versions (0.9,1.0,1.1,2). (ext)
    TOOLS: curl
    """

    threads = 3

    with cf.ThreadPoolExecutor(threads) as exe:
      for t in self.http_req_types:
        for v in self.http_versions:
          opts = f"-v --connect-timeout 3 -m 30 -s -A '{self.useragent}'"
          opts += f" -X {t.upper()} --http{v}"
          opts += f" --url http://{self.target['host']}:{self.target['port']}/"
          exe.submit(self._run_tool, 'curl', opts, nullscan_tool=f'http_reqs_{t}')

    return


  @tool
  def http_put(self):
    """
    DESCR: Try to send HTTP PUT request with example data to /nullscan.html. (int)
    TOOLS: curl
    """

    opts = f"-s --connect-timeout 3 -m 30 -X PUT -A '{self.useragent}'"
    opts += ' -D /dev/stdout --data pwned'
    opts += f" --url http://{self.target['host']}:"
    opts += f"{self.target['port']}/nullscan.html"

    self._run_tool('curl', opts, nullscan_tool='http_put')

    return


  @tool
  def proxy_check(self):
    """
    DESCR: Check for open HTTP proxy. (int)
    TOOLS: curl
    """

    opts = f"-I -s -x 'http://{self.target['host']}:{self.target['port']}/'"
    opts += f" -L https://www.blackarch.org/"

    self._run_tool('curl', opts, nullscan_tool='proxy_check')

    return


  @tool
  def davscan(self):
    """
    DESCR: Scan webserver and test if WebDAV is enabled. (ext)
    TOOLS: davscan
    """

    opts = f"-d -m -D 1 -o /tmp/{self.target['host']}"

    if self.opts['user'] and self.opts['pass']:
      opts += f" -a basic -u {self.opts['user']} -p {self.opts['pass']}"
    if self.opts['proxy']:
      opts += f" -P {self.opts['proxy']}"

    opts += f" http://{self.target['host']}:{self.target['port']}/"

    self._run_tool('davscan', opts, escape_codes=True)

    return


  @tool
  def lulzbuster_http(self):
    """
    DESCR: Enumerate directories and files on webserver. (ext)
    TOOLS: lulzbuster
    """

    host = self.target['host']
    port = self.target['port']

    # better try with hostname
    domain = self._read_log('domainname')[0]
    hostname = self._read_log('hostname')[0]
    if domain:
      host = domain
      if hostname and hostname in domain:
        host = hostname

    for f in self.opts['flists']:
      self._lulzbuster(host, port, flist=f)

    return


  @tool
  def dirsearch_http(self):
    """
    DESCR: Enumerate directories and files on webserver. (ext)
    TOOLS: dirsearch
    """

    host = self.target['host']
    port = self.target['port']

    # better try with hostname
    domain = self._read_log('domainname')[0]
    hostname = self._read_log('hostname')[0]
    if domain:
      host = domain
      if hostname and hostname in domain:
        host = hostname

    for f in self.opts['flists']:
      self._dirsearch(host, port, flist=f)

    return


  @tool
  def gobuster_http(self):
    """
    DESCR: Enumerate directories and files on webserver. (ext)
    TOOLS: gobuster
    """

    host = self.target['host']
    port = self.target['port']

    # better try with hostname
    domain = self._read_log('domainname')[0]
    hostname = self._read_log('hostname')[0]
    if domain:
      host = domain
      if hostname and hostname in domain:
        host = hostname

    for f in self.opts['flists']:
      self._gobuster(host, port, flist=f)

    return


  @tool
  def halberd_http(self):
    """
    DESCR: Discover http load balancer. (ext)
    TOOLS: halberd
    """

    self._halberd(self.target['host'], self.target['port'])

    return


  @tool
  def lbmap_http(self):
    """
    DESCR: Fingerprint HTTP server. (ext)
    TOOLS: lbmap
    """

    self._lbmap(self.target['host'], self.target['port'])

    return


  @tool
  def metoscan_http(self):
    """
    DESCR: Scan available HTTP methods. (ext)
    TOOLS: metoscan
    """

    self._metoscan(self.target['host'], self.target['port'])

    return


  @tool
  def httping_http(self):
    """
    DESCR: Ping HTTP server. (ext)
    TOOLS: httping
    """

    self._httping(self.target['host'], self.target['port'])

    return


  @tool
  def httprint_http(self):
    """
    DESCR: Fingerprint the web-server. (ext)
    TOOLS: httprint
    """

    self._httprint(self.target['host'], self.target['port'])

    return


  @tool
  def nikto_http(self):
    """
    DESCR: Crawl the web-server for directories, files and vulnerabilities.
           (ext)
    TOOLS: nikto
    """

    self._nikto(self.target['host'], self.target['port'])

    return


  @tool
  def crack_http_auth(self):
    """
    DESCR: Check HTTP auth type (basic, realm, etc.) and crack login. (int)
    TOOLS: python3
    """

    with timeout(self.opts['timeout']):
      url = f"http://{self.target['host']}:{self.target['port']}/"
      self._crack_http_auth(url, 'crack_http_auth')

    return


  @tool
  def crack_tomcat_http(self):
    """
    DESCR: Check for tomcat and crack logins using tomcat's default creds. (int)
    TOOLS: python3
    """


    with timeout(self.opts['timeout']):
      # default tomcat creds
      users = deque(('tomcat', 'both', 'role1', 'admin', 'manager', 'root'))
      pws = deque(('tomcat', 'both', 'role1', 'admin', 'manager', 'root', ''))

      threads = len(users)

      url = self._is_tomcat(self.target['host'], self.target['port'])

      if url:
        with cf.ThreadPoolExecutor(threads) as exe:
          for us in users:
            for pw in pws:
              exe.submit(self._crack_tomcat, url, us, pw, 'crack_tomcat_http')

    return


  @tool
  def jexboss_http(self):
    """
    DESCR: Check for known java deserialization vulns against JBoss, Jenkins,
           and Apache Struts2. (ext)
    TOOLS: jexboss
    """

    self._jexboss(self.target['host'], self.target['port'], log='jexboss_http')

    return


  @tool
  def snallygaster_http(self):
    """
    DESCR: Scan for secret files on web-server. (ext)
    TOOLS: snallygaster
    """

    target = f"{self.target['host']}:{self.target['port']}"

    self._snallygaster(target, 'snallygaster_http')

    return


  @tool
  def tomcatwardeployer_http(self):
    """
    DESCR: Apache Tomcat auto WAR deployment & pwning. (ext)
    TOOLS: tomcatwardeployer
    """

    opts = '-t 5'

    if self.opts['user'] and self.opts['pass']:
      opts += f" -U {self.opts['user']} -P {self.opts['pass']}"

    opts += f" http://{self.target['host']}:{self.target['port']}/"

    self._run_tool('tomcatwardeployer', opts, 'tomcatwardeployer_http',
      timeout=8)

    return


  @tool
  def findstr_http(self):
    """
    DESCR: Find given string in HTTP responses. (int)
    TOOLS: curl
    """

    url = f"http://{self.target['host']}:{self.target['port']}/"
    opts = f"--connect-timeout 2 -m 30 -s -L -A '{self.useragent}' {url}"
    cmd = f'curl {opts}'

    res = ' '.join(self._run_cmd(cmd))
    if self.opts['searchstr'] in res:
      idx = res.index(self.opts['searchstr'])
      data = f"{url} ==> '{res[idx:idx+int(self.opts['resp_size'])]}'"
      self._log('findstr_http', data)

    return


  @tool
  def nmap_http(self):
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
    opts += f" -p {self.target['port']} {self.target['host']}"

    self._run_tool('nmap', opts, nullscan_tool='nmap_http')

    return


# EOF
