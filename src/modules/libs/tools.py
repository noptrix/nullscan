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
# tools.py                                                                     #
#                                                                              #
# AUTHOR                                                                       #
# noptrix@nullsecurity.net                                                     #
#                                                                              #
################################################################################


# sys imports
import ipaddress
import dns.resolver
import whois
import requests
import concurrent.futures as cf
from ipwhois import IPWhois
from googlesearch import search as gsearch
from requests.auth import HTTPBasicAuth, HTTPDigestAuth
from collections import deque


# own imports
from modules.libs.toolsattr import ToolsAttr
import core.nmap


class Tools(ToolsAttr):
  """ tools (wrapper) class: implement shared tools or wrap existing tools. """


  def __init__(self, target, opts):
    """ init """

    ToolsAttr.__init__(self, target, opts)

    return


  def _crack_http_auth(self, url, logfile, threads=20, exit_on_success=True):
    """ check for http auth type and crack login """

    futures = deque()
    headers={'User-Agent': f"'{self.useragent}'"}
    s = requests.session()
    h = s.head(url, verify=False, headers=headers).headers
    auth_header = ''
    if 'WWW-Authenticate' in h:
      auth_header = h['WWW-Authenticate']

    def crack(s, url, h, a, u, p):
      code = s.head(url, verify=False, headers=h,
        auth=a(f'{u}', f'{p}')).status_code
      if code == 200:
        return f'Login found: {u}:{p}'
      return

    if 'Basic realm' in auth_header:
      auth_type = HTTPBasicAuth
    elif 'Digest realm' in auth_header:
      auth_type = HTTPDigestAuth
    else:
      # todo: proxy auth etc.
      return

    # single username + single password
    if self.opts['user'] and self.opts['pass']:
      us = self.opts['user']
      pw = self.opts['pass']
      r = s.head(url, headers=headers, verify=False,
        auth=auth_type(f'{us}', f'{pw}'))
      if r.status_code == 200:
        self._log(logfile, f'Login found: {us}:{pw}')
        if exit_on_success:
          return

    # single username + password list
    if self.opts['user'] and self.opts['plists']:
      us = self.opts['user']
      for pwlist in self.opts['plists']:
        pws = self._read_file(pwlist)
        with cf.ThreadPoolExecutor(threads) as exe:
          for pw in pws:
            futures.append(exe.submit(crack, s, url, headers, auth_type, us,
              pw))
          for r in cf.as_completed(futures):
            if r.result():
              self._log(logfile, f'{r.result()}')
              if exit_on_success:
                return
    futures = []

    # username list + password list
    if self.opts['ulists'] and self.opts['plists']:
      for uslist in self.opts['ulists']:
        for pwlist in self.opts['plists']:
          usrs = self._read_file(uslist)
          pws = self._read_file(pwlist)
          with cf.ThreadPoolExecutor(threads) as exe:
            for us in usrs:
              for pw in pws:
                futures.append(exe.submit(crack, s, url, headers, auth_type, us,
                  pw))
              for r in cf.as_completed(futures):
                if r.result():
                  self._log(logfile, f'{r.result()}')
                  if exit_on_success:
                    return

    return


  def _crack_tomcat(self, url, user, password, logfile, timeout=5):
    """ crack tomcat login using default tomcat creds """

    headers = {'User-Agent': self.useragent}
    session = requests.session()

    try:
      res = session.get(url, timeout=timeout, auth=(user, password),
        verify=False, headers=headers)
      if res.status_code == 200:
        data = f'Login found: {url} ({user}:{password})'
        self._log(f'{logfile}', data)
    except:
      pass

    return


  def _sparty(self, url, log, mode='frontpage', opts=''):
    """ wrapper for sparty """

    if not opts:
      if mode == 'frontpage':
        for i in ('pvt', 'bin'):
          for j in ('rpc_version_check', 'rpc_service_listing',
            'rpc_file_upload', 'author_config_check', 'author_remove_folder'):
            opts = f'-u {url} -f {i} -v ms_frontpage -d extract -l list -e {j}'
            self._run_tool('sparty', opts, nullscan_tool=log, newlines=True)
      elif mode == 'sharepoint':
        for i in ('forms', 'layouts', 'catalog'):
          for j in ('rpc_version_check', 'rpc_service_listing',
            'rpc_file_upload', 'author_config_check', 'author_remove_folder'):
            opts = f'-u {url} -s {i} -v ms_sharepoint -d extract -l list -e {j}'
            self._run_tool('sparty', opts, nullscan_tool=log, newlines=True)
      else:
        opts += ' -u {url}'
        self._run_tool('sparty', opts, nullscan_tool=log)
        return

    return


  def _snallygaster(self, target, log, opts='', timeout=300):
    """ wrapper for snallygaster """

    if not opts:
      opts = f"-i -n --nowww --useragent '{self.useragent}'"

    opts = f'{opts} {target}'

    self._run_tool('snallygaster', opts, logfile=log, timeout=timeout)

    return


  def _jexboss(self, host, port, log, scheme='http', opts=''):
    """ wrapper for jexboss """

    if not opts:
      opts = ' -D'
      if self.opts['post_data']:
        opts += f" -H {self.opts['post_data']}"
      if self.opts['cookies']:
        opts += f" --cookies '{self.cookies}'"
      if self.opts['proxy']:
        opts += f" --proxy {self.opts['proxy']}"

    opts = f'{opts} -u {scheme}://{host}:{port}/'

    self._run_tool('jexboss', opts, logfile=log, precmd='yes "NO" |',
      escape_codes=True)

    return


  def _gobuster(self, host, port, flist, scheme='http', log=None, opts=''):
    """ wrapper for gobuster """

    if not log:
      log = f'gobuster_{scheme}'

    if not opts:
      opts = f"dir -a '{self.useragent}' -e -f -k -l -q -r --timeout 5s -t 20"
      opts += f' -w {flist} -u {scheme}://{host}:{port}/'
      if self.opts['cookies']:
        opts += f" -c '{self.cookies}'"
      if self.opts['web_user'] and self.opts['web_pass']:
        opts += f" -U {self.opts['web_user']} -P {self.opts['web_pass']}"
      if self.opts['proxy']:
        opts += f" --proxy {self.opts['proxy']}"

    opts = f'{opts} -u {scheme}://{host}:{port}/'

    self._run_tool('gobuster', opts, logfile=log)

    return


  def _droopescan(self, cms='drupal', opts=''):
    """ wrapper for droopescan """

    if not opts:
      opts = '--enumerate a -t 10 -o standard --timeout 5 --hide-progressbar'
      opts += ' --threads-enumerate 10'

    opts = f'{cms} -u {self.target} {opts}'

    self._run_tool('droopescan scan', opts, logfile=f'droopescan_{cms}')

    return


  def _domi_owned(self, target, log, mode='', newlines=False, opts=''):
    """ wrapper for domi-owned """

    if not opts:
      modes = ('fingerprint', 'enumerate', 'hashdump')

      for m in modes:
        # fingerprint, enumerate, hashdump without creds
        opts = f'{m} {target}'
        self._run_tool('domi-owned', opts, logfile=log, newlines=newlines,
          escape_codes=True)

        # fingerprint, enumerate, hashdump with creds
        if self.opts['user'] and self.opts['pass']:
          opts = f"{m} {target} --username {self.opts['user']}"
          opts += f" --password {self.opts['pass']}"
          self._run_tool('domi-owned', opts, logfile=log, newlines=newlines,
            escape_codes=True)

      # bruteforce accounts
      if self.opts['ulists']:
        for ulist in self.opts['ulists']:
          opts = f'bruteforce {target} {ulist} '
          self._run_tool('domi-owned', opts, logfile=log, newlines=newlines,
            escape_codes=True)
    else:
      self._run_tool('domi-owned', f'{mode} {target} {opts}', logfile=log,
        escape_codes=True)

    return


  def _commix(self, url, opts='', timeout=3600):
    """ wrapper for commix """

    if not opts:
      opts = '--batch --sys-info --level 3 --crawl 1 --disable-coloring'
      opts += f" --user-agent '{self.useragent}' --output-dir /tmp/"
      opts += ' --sys-info --retries 2 --flush-session --os-cmd dir'

      if self.opts['post_data']:
        opts += f" -d {self.opts['post_data']}"
      if self.opts['referer']:
        opts += f" --referer {self.opts['referer']}"
      if self.opts['login_url']:
        opts += f" --auth-url {self.opts['auth_url']}"
      if self.opts['cookies']:
        opts += f' --cookie {self.cookies}'
      if self.opts['web_user'] and self.opts['web_pass']:
        opts += f" --auth-type Basic" # we need to add auth type opt later
        opts += f" --auth-cred {self.opts['web_user']}:{self.opts['web_pass']}"

    opts = f'-u {url} {opts}'

    self._run_tool('commix', opts, escape_codes=True, timeout=timeout)

    return


  def _brutemap(self, target, opts='', logfile='brutemap'):
    """ crack website logins using dictionary attack. """

    if not opts:
      _opts = '--retries 2 -oD /tmp/brutemap'

      # single user + pass
      if self.opts['user'] and self.opts['pass']:
        opts = f"-t {target} -u {self.opts['user']} -p {self.opts['pass']}"
        opts += f' {_opts}'
        self._run_tool('brutemap', opts, logfile=logfile, newlines=True)

      # single user + passlist
      if self.opts['user'] and self.opts['plists']:
        for plist in self.opts['plists']:
          if self._check_file(plist, block=False):
            opts = f" -t {target} -u {self.opts['user']} -p {plist} {_opts}"
            self._run_tool('brutemap', opts, logfile=logfile, newlines=True)

      # userlist + passlist
      if self.opts['ulists'] and self.opts['plists']:
        for ulist in self.opts['ulists']:
          if self._check_file(ulist, block=False):
            for plist in self.opts['plists']:
              if self._check_file(plist, block=False):
                opts = f'-t {target} -u {ulist} -p {plist} {_opts}'
                self._run_tool('brutemap', opts, logfile=logfile)
    else:
      self._run_tool('brutemap', opts, logfile=logfile)

    return


  def _httprint(self, host, port, scheme='http', opts=''):
    """ wrapper to fingerprint http server using httprint """

    if not opts:
      opts = f'-h {scheme}://{host}:{port}/'
      opts += ' -s /usr/share/httprint/signatures.txt'
      opts += ' -r 2 -P0'

    opts = f'-h {scheme}://{host}:{port}/ {opts}'

    self._run_tool('httprint', opts, f'httprint_{scheme}')

    return


  def _httping(self, host, port, scheme='http', opts=''):
    """ wrapper to ping http server using httping """

    if not opts:
      opts = f"-a -t 3 -c 3 -I '{self.useragent}' -R {scheme}://nullscan.net/"
      if scheme == 'https':
        opts += ' -l'
      else:
        opts += ' -F'
      if self.opts['web_user'] and self.opts['web_pass']:
        opts += f" -A -U {self.opts['web_user']} -P {self.opts['web_pass']}"
      if self.opts['proxy']:
        h, p, s, pa = self._parse_url(self.opts['proxy'])
        opts += f' --proxy {h}:{p}'
        if self.opts['proxy_user'] and self.opts['proxy_pass']:
          opts += f" --proxy-user {self.opts['proxy_user']}"
          opts += f" --proxy-password {self.opts['proxy_pass']}"
      opts += f' -p {port} -g {host}'

    opts = f'{opts} -p {port} -g {host}'

    self._run_tool('httping', opts, f'httping_{scheme}')

    return


  def _metoscan(self, host, port, scheme='http', opts=''):
    """ wrapper to scan for available HTTP methods using metoscan """

    if not opts:
      opts = f'{scheme}://{host}:{port}/'

    self._run_tool('metoscan', opts, f'metoscan_{scheme}')

    return


  def _lbmap(self, host, port, scheme='http', opts=''):
    """ wrapper to fingerprint web-server using lbmap """

    if not opts:
      opts = f'{scheme}://{host}:{port} --timeout 10 --batch'

    opts = f'{scheme}://{host}:{port} {opts}'

    self._run_tool('lbmap', opts, nullscan_tool=f'lbmap_{scheme}')

    return


  def _halberd(self, host, port, scheme='http', opts=''):
    """ wrapper to discover http load balancers using halberd """

    if not opts:
      opts = f'-t 10 -p 15 -q {scheme}://{host}:{port}'

    opts = f'{opts} {scheme}://{host}:{port}/'

    self._run_tool('halberd', opts, nullscan_tool=f'halberd_{scheme}')

    return


  def _nikto(self, host, port, scheme='http', opts=''):
    """ wrapper to crawl the web-server for dirs,files and vulns using nikto """

    if not opts:
      opts = f'-C all -no404 -nointeractive -useragent "{self.useragent}"'
      opts += f' -p {port} -h {host}'
      if self.opts['proxy']:
        opts += f" -useproxy self.opts['proxy']"

    opts = f'{opts} -p {port} -h {host}'

    if scheme == 'https':
      opts += ' -ssl'

    self._run_tool('nikto', opts, nullscan_tool=f'nikto_{scheme}', timeout=3600)

    return


  def _fpdns(self, prot='udp', opts=''):
    """ wrapper to fingerprint remote DNS server using fpdns. """

    if not opts:
      if prot == 'tcp':
        opts = '-f -F 16 -T'
      else:
        opts = '-f -F 16'
      if self.opts['shost']:
        opts = f"{opts} -Q self.opts['shost']"

    opts = f"{opts} -p {self.target['port']} {self.target['host']}"
    self._run_tool('fpdns', opts, f'fpdns_{prot}')

    return


  def _snoop_cache(self, prot='udp', opts=''):
    """ test for DNS cache snoop leak using dig. """

    if not opts:
      if prot == 'tcp':
        opts = 'A +norecurse +tcp +timeout=5'
      else:
        opts = 'A +norecurse +timeout=5'

    site = 'gmail.com'

    cmd1 = f"dig @{self.target['host']} {site} {opts}"
    cmd2 = f"dig @{self.target['host']} {site} {opts} | grep -i 'answer'"

    # make first request
    self._run_cmd(cmd1, f'snoop_cache_{prot}', newlines=True)

    # make second request (grep for ANSWER flag)
    self._run_cmd(cmd2, f'snoop_cache_{prot}')

    return


  def _dig_dns_version(self, prot='udp', opts=''):
    """ determine remote DNS server version using 'dig' cmd. """

    if not opts:
      if prot == 'tcp':
        opts = '+short +tcp +timeout=5 chaos txt version.bind'
        opts += f" @{self.target['host']}"
      else:
        opts = "+short +timeout=5 chaos txt version.bind self.target['host']"

    self._run_tool('dig', opts, 'dig_dns_version',
      logfile=f'dig_dns_version_{prot}')

    return


  def _host_dns_version(self, prot='udp', opts=''):
    """ determine remote DNS server version using 'host' cmd. """

    if not opts:
      if prot == 'tcp':
        opts = f"-T -W 5 -c chaos -t txt version.bind {self.target['host']}"
      else:
        opts = f"-W 5 -c chaos -t txt version.bind {self.target['host']}"

    self._run_tool('host', opts, logfile=f'host_dns_version_{prot}')

    return


  def _googlesearch(self, query, **kwargs):
    """ simple google search """

    # defaults
    defaults = {'stop': 100, 'user_agent': self.useragent}

    # merge
    kwargs = {**defaults, **kwargs}

    for url in gsearch(query, **kwargs):
      yield url

    return


  def _testssl(self, host, port, opts=''):
    """ wrapper for testssl """

    if not opts:
      opts = f'--color 0 --vulnerable {host}:{port}'
    else:
      opts = f'{opts} {host}:{port}'

    self._run_tool('testssl', opts)

    return


  def _lulzbuster(self, host, port, scheme='http', flist=None, log=None,
    opts=''):
    """ wrapper for lulzbuster """

    if not log:
      log = f'lulzbuster_{scheme}.log'
    else:
      if not '.log' in log:
        log = f'{log}.log'

    if not opts:
      opts = f'-S -f -i -U -l {log}'
      if self.opts['proxy']:
        h, p, s, pa = self._parse_url(self.opts['proxy'])
        opts += f' -p {s}://{h}:{p}'
        if self.opts['proxy_user'] and self.opts['proxy_pass']:
          opts += f" -P {self.opts['proxy_user']}:{self.opts['proxy_pass']}"
      if self.opts['web_user'] and self.opts['web_pass']:
        opts += f" -a {self.opts['web_user']}:{self.opts['web_pass']}"

    if flist:
      opts += f' -w {flist}'

    opts = f'-s {scheme}://{host}:{port}/ {opts}'

    self._run_tool('lulzbuster', opts, create_log=False)

    return


  def _dirsearch(self, host, port, scheme='http', flist=None, log=None,
    opts=''):
    """ wrapper for dirsearch """

    if not log:
      log = f'dirsearch_{scheme}.log'
    else:
      if not '.log' in log:
        log = f'{log}.log'

    if not opts:
      opts = "-b -e ' ' -t 25 -x 300,301,302,303,400,401,402,404,430,500,501,"
      opts += f"502,503 --plain-text-report={log} --ua='{self.useragent}'"
      if self.opts['cookies']:
        opts += f" --cookie='{self.cookies}'"
      if self.opts['proxy']:
        h, p, s, pa = self._parse_url(self.opts['proxy'])
        opts += f' --proxy={h}:{p}'

    if flist:
      opts += f' -w {flist}'

    opts = f'-u {scheme}://{host}:{port}/ {opts}'

    self._run_tool('dirsearch', opts, create_log=False)

    return


  def _ikescan(self, opts, log):
    """ wrapper for all ikescan methods """

    # RFC compliant auth types
    for types in self.ike_auth_types.values():
      for t in types:
        _opts = f"{opts} --auth={t} {self.target['host']}"
        self._run_tool('ike-scan', _opts, logfile=log, newlines=True)

    return


  def _whois(self, _type, target=None):
    """ perform whois on domain or ipv4 addr """

    res = []
    try:
      if target:
        if _type == 'domain':
          res.append(whois.whois(target))
        else:
          obj = IPWhois(target)
          res.append(obj.lookup_rdap(depth=1))
      else:
        if _type == 'domain':
          log = self._read_log('domainname')
        else:
          log = self._read_log('ipv4addr')
        for target in log:
          if target:
            if _type == 'domain':
              res.append(whois.whois(target))
            else:
              obj = IPWhois(target)
              res.append(obj.lookup_rdap(depth=1))
    except:
      pass

    return res


  def _portscan(self, nmap_opts, logfile, output=None):
    """ wrapper to perform nmap portscan """

    nmap = core.nmap.Nmap(nmap_opts)
    nmap.set_logfile(logfile)
    nmap.build_cmd()
    nmap.scan(output=output)

    return


  def _icmp_req(self, name, icmp_type, icmp_code, count):
    """ wrapper for all icmp requests """

    opts = f'--icmp --icmp-type {icmp_type} --icmp-code {icmp_code}'
    opts += f" --delay 0.2s -c {count} {self.target['host']}"

    self._run_tool('nping', opts, name)

    return


  def _hydra(self, protocol, _opts):
    """ wrapper for hydra to crack logins """

    log = f'hydra_{protocol}.log'
    _opts += f' -o {log}'

    # single username + single password mode
    opts = f"{_opts} -l {self.opts['user']} -p {self.opts['pass']}"
    opts += f" {protocol}://{self.target['host']}:{self.target['port']}"
    self._run_tool('hydra', opts, create_log=False)

    # single username + password list mode
    for pwlist in self.opts['plists']:
      if self._check_file(pwlist):
        opts = f"{_opts} -l {self.opts['user']} -P {pwlist}"
        opts += f" {protocol}://{self.target['host']}:{self.target['port']}"
        self._run_tool('hydra', opts, create_log=False)

    # username list and password list mode
    for userlist in self.opts['ulists']:
      if self._check_file(userlist, block=False):
        for passlist in self.opts['plists']:
          if self._check_file(passlist, block=False):
            opts = f"{_opts} -L {userlist} -P {passlist}"
            opts += f" {protocol}://{self.target['host']}:{self.target['port']}"
            self._run_tool('hydra', opts, create_log=False)

    return


  def _dns_query(self, qtype, tool, logfile=None):
    """ perform dns query and log results """

    res = []

    if logfile:
      for host in self._read_log(logfile):
        try:
          res.append(dns.resolver.query(host, qtype))
        except:
          pass

    # try with target['host'] directly
    if not res:
      try:
        res.append(dns.resolver.query(self.target['host'], qtype))
      except:
        pass

    if res:
      for answers in res:
        for a in answers:
          if qtype != 'mx' and qtype != 'MX' and qtype != 'Mx' and qtype != 'mX':
            if not logfile:
              # output for dnsrecords()
              self._log(tool, f"{qtype.upper()}: {a.to_text().rstrip('.')}")
            else:
              # normal output
              self._log(tool, a.to_text().rstrip('.'))
          else:
            self._log(tool, a.exchange.to_text().rstrip('.'))

    return


# EOF
