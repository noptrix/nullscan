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
# fullscan.py                                                                  #
#                                                                              #
# AUTHOR                                                                       #
# noptrix@nullsecurity.net                                                     #
#                                                                              #
################################################################################


# sys imports


# own imports
from modules.libs.base import Base, tool, timeout


class Fullscan(Base):
  """ Fullscan module """

  timeout = 3600    # 1 hour default timeout


  def __init__(self, target, opts):
    """ init """

    Base.__init__(self, target, opts)

    self.host, self.port, self.scheme, self.path = self._parse_url(self.target)

    return


  @tool
  def striker(self):
    """
    DESCR: Performs quick offensive information and vulnerability scans. (ext)
    TOOLS: striker
    """

    opts = f'{self.host}'
    self._run_tool('striker', opts, escape_codes=True, timeout=Fullscan.timeout)

    return


  @tool
  def golismero(self):
    """
    DESCR: Map whole web-application and perform quick security scans. (ext)
    TOOLS: golismero
    """

    opts = f'scan {self.target} --full --no-color --follow-first'
    opts += ' --forbid-subdomains -q -o - -e dns,dns_malware,fingerprint_web,'
    opts += 'robots,shodan,spider,xsser,sqlmap,heartbleed'

    if self.opts['cookies']:
      opts += f" --cookie '{self.cookies}'"
    if self.opts['proxy']:
      opts += f" --proxy-addr {self.opts['proxy']}"
    if self.opts['proxy_user'] and self.opts['proxy_pass']:
      opts += f" -pu {self.opts['proxy_user']} -pp {self.opts['proxy_pass']}"

    self._run_tool('golismero', opts, timeout=Fullscan.timeout)

    return


  @tool
  def vanguard(self):
    """
    DESCR: Scan website for vulnerabilities. (ext)
    TOOLS: vanguard
    """

    opts = f'-v -o /dev/stdout -h {self.host}'
    self._run_tool('vanguard', opts, timeout=Fullscan.timeout)

    return


  @tool
  def wapiti(self):
    """
    DESCR: Crawl and scan website. (ext)
    TOOLS: wapiti
    """

    target = self.target
    if self.opts['attack_url']:
      target = self.opts['attack_url']

    opts = f'-u {target} --verify-ssl 0 -t 3 -d 2 -f txt --flush-session'
    opts += " --module 'xss,crlf,sql,file,htaccess,blindsql,permanentxss,"
    opts += "backup,exec,methods,shellshock,ssrf' -o /dev/stdout --no-bugreport"
    opts += f" --max-parameters 10 --max-scan-time {Fullscan.timeout}"

    if self.opts['proxy']:
      opts += f" -p {self.opts['proxy']}"

    self._run_tool('wapiti', opts, timeout=Fullscan.timeout)

    return


  @tool
  def uniscan(self):
    """
    DESCR: Crawl and scan website. (ext)
    TOOLS: uniscan
    """

    opts = f'-q -w -e -d -s -g -j -u {self.target}'
    self._run_tool('uniscan', opts, timeout=Fullscan.timeout)

    return


  @tool
  def skipfish(self):
    """
    DESCR: Crawl and scan website. (ext)
    TOOLS: skipfish
    """

    report = f'skipfish-{self.host}'
    opts = f'-u -i 5 -t 5 -d 3 -o {report} {self.target}'

    if self.opts['cookies']:
      for c in self.opts['cookies'].split(';'):
        opts += f" -C '{c}'"

    self._run_tool('skipfish', opts, precmd='echo |', escape_codes=True)

    return


  @tool
  def arachni(self):
    """
    DESCR: Crawl and scan website. (ext)
    TOOLS: arachni
    """

    report = f'/tmp/arachni-{self.host}'

    opts = f"--http-user-agent '{self.useragent}'"
    opts += f' --scope-directory-depth-limit 1 --report-save-path {report}'
    opts += ' --audit-links --audit-forms --audit-cookies --audit-headers'
    opts += f' --audit-xmls --audit-jsons --timeout 0:0:{Fullscan.timeout}'

    if self.opts['cookies']:
      opts += f" --http-cookie-string '{self.cookies}'"
    if self.opts['proxy']:
      host, port, scheme, path = self._parse_url(self.opts['proxy'])
      opts += f" --http-proxy self.opts['proxy'] --http-proxy-type {scheme}"
    if self.opts['proxy_user'] and self.opts['proxy_pass']:
      opts += f" --http-proxy-authentication {self.opts['proxy_user']}:"
      opts += f"{self.opts['proxy_pass']}"

    opts += f' {self.target}'

    self._run_tool('arachni', opts, create_log=False, timeout=Fullscan.timeout)

    # report
    cmd = f'arachni-reporter {report} --report txt:outfile=/tmp/{self.host}.txt'
    self._run_cmd(cmd)
    cmd = f'cat /tmp/{self.host}.txt'
    self._run_cmd(cmd, 'arachni')
    self._run_cmd(f'rm -rf {report} /tmp/arachni-{self.host}.txt')

    return


  @tool
  def wascan(self):
    """
    DESCR: Crawl and scan website. (ext)
    TOOLS: wascan
    """

    opts = f"-u {self.target} -s 5 -t 5 -A '{self.useragent}'"

    if self.opts['post_data']:
      opts += f" -d {self.opts['post_data']}"
    if self.opts['cookies']:
      opts += f" -c '{self.cookies}'"
    if self.opts['proxy']:
      opts += f" -p {self.opts['proxy']}"
    if self.opts['proxy_user'] and self.opts['proxy_pass']:
      opts += f" -P {self.opts['proxy_user']}:{self.opts['proxy_pass']}"
    if self.opts['web_user'] and self.opts['web_pass']:
      opts += f" -a {self.opts['web_user']}:{self.opts['web_pass']}"

    self._run_tool('wascan', opts, timeout=Fullscan.timeout, escape_codes=True)

    return


  @tool
  def sitadel(self):
    """
    DESCR: Crawl and scan website. (ext)
    TOOLS: sitadel
    """

    opts = f"{self.target} -r 1 --no-redirect -t 5 -ua '{self.useragent}'"

    if self.opts['cookies']:
      opts += f" -c '{self.cookies}'"
    if self.opts['proxy']:
      opts += f" -p {self.opts['proxy']}"

    opts += ' -f cms system framework frontend header lang server waf'
    opts += ' -a injection vulns other'

    self._run_tool('sitadel', opts, timeout=Fullscan.timeout, escape_codes=True)

    return


  @tool
  def taipan(self):
    """
    DESCR: Crawl and scan website. (ext)
    TOOLS: taipan
    """

    opts = f'{self.target}'
    self._run_tool('taipan', opts)

    return


  @tool
  def vulnx(self):
    """
    DESCR: Enumerate CMS and scan for vulnerabilities on website. (ext)
    TOOLS: vulnx
    """

    target = self.target
    if self.opts['attack_url']:
      target = self.opts['attack_url']

    opts = f"-u {self.target} -t {Fullscan.timeout} -c all -e -w"
    self._run_tool('vulnx', opts, escape_codes=True, timeout=Fullscan.timeout)


    return


  @tool
  def wig(self):
    """
    DESCR: Simple enumeration, scans and information gathering from website.
           (ext)
    TOOLS: wig
    """

    opts = '-q -N -v -a -d -t 10'

    if self.opts['proxy']:
      opts += f" --proxy '{self.opts['proxy']}'"

    opts += f' {self.target}'

    self._run_tool('wig', opts, escape_codes=True, timeout=Fullscan.timeout)

    return


  @tool
  def yawast(self):
    """
    DESCR: Enumerate, scan and gather information from web-application. (ext)
    TOOLS: yawast
    """

    opts = 'scan {self.target}'

    self._run_tool('yawast', opts, escape_codes=True, timeout=Fullscan.timeout)

    return


# EOF
