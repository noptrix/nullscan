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
# xss.py                                                                       #
#                                                                              #
# AUTHOR                                                                       #
# noptrix@nullsecurity.net                                                     #
#                                                                              #
################################################################################


# sys imports


# own imports
from modules.libs.base import Base, tool, timeout


class XSS(Base):
  """ Cross-Site Scripting module """

  timeout = 1800  # 30min default timeout


  def __init__(self, target, opts):
    """ init """

    Base.__init__(self, target, opts)

    return


  @tool
  def xsssniper(self):
    """
    DESCR: Crawl and scan website for XSS vulnerabilities. (ext)
    TOOLS: xsssniper
    """

    opts = f"--threads 16 --crawl --forms --user-agent '{self.useragent}' --dom"

    if self.opts['cookies']:
      opts += f" --cookie '{self.cookies}'"
    if self.opts['proxy']:
      opts += f" --http-proxy {self.opts['proxy']}"
    if self.opts['post_data']:
      opts += f" --data {self.opts['post_data']}"

    target = self.target
    if self.opts['attack_url']:
      target = self.opts['attack_url']

    opts += f" -u {target.rstrip('/')} 2> /dev/null"

    self._run_tool('xsssniper', opts, timeout=XSS.timeout)

    return


  @tool
  def xsss(self):
    """
    DESCR: Crawl and scan website for XSS vulnerabilities. (ext)
    TOOLS: xsss
    """

    opts = '--forms --queries --depth 2'

    target = self.target
    if self.opts['attack_url']:
      target = self.opts['attack_url'].rstrip('/')

    opts += f" '{target.rstrip('/')}'"

    self._run_tool('xsss', opts, timeout=XSS.timeout)

    return


  @tool
  def xsser(self):
    """
    DESCR: Crawl and scan website for XSS vulnerabilities. (ext)
    TOOLS: xsser
    """

    opts = '--Cw=5 --Onm --Ifr --B64 --Coo --Xsa --Xsr --Dcp --Dom --Ind'
    opts += ' --Anchor --Phpids0.6.5 --Phpids0.7 --Imperva --auto'
    opts += ' --follow-redirects --Webknight --F5bigip --Barracuda --Modsec'
    opts += ' --Quickdefense --timeout=10 --threads=10 --tcp-nodelay'
    opts += f" --user-agent '{self.useragent}'"

    if self.opts['cookies']:
      opts += f" --cookie='{self.cookies}'"
    if self.opts['web_user'] and self.opts['web_pass']:
      opts += f" --auth-type Basic --auth-cred {self.opts['web_user']}:"
      opts += f"{self.opts['web_pass']}"
    if self.opts['proxy']:
      opts += f" --proxy {self.opts['proxy']}"
    if self.opts['post_data']:
      opts += f" -p {self.opts['post_data']}"
    if self.opts['referer']:
      opts += f" --referer {self.opts['referer']}"

    target = self.target
    if self.opts['attack_url']:
      target = self.opts['attack_url']

    opts += f" -u '{target.rstrip('/')}'"

    self._run_tool('xsser', opts, timeout=XSS.timeout)

    return


  @tool
  def dsxs(self):
    """
    DESCR: Scan for XSS vulnerabilities on given URL with parameters included.
           (ext)
    TOOLS: dsxs
    """

    opts = f"--user-agent '{self.useragent}'"

    if self.opts['cookies']:
      opts += f" --cookie '{self.cookies}'"
    if self.opts['proxy']:
      opts += f" --proxy {self.opts['proxy']}"
    if self.opts['referer']:
      opts += f" --referer {self.opts['referer']}"
    if self.opts['post_data']:
      opts += f" --data {self.opts['post_data']}"

    target = self.target
    if self.opts['attack_url']:
      target = self.opts['attack_url'].rstrip('/')

    opts += f" -u '{target}'"

    self._run_tool('dsxs', opts, timeout=XSS.timeout)

    return


  @tool
  def xsscon(self):
    """
    DESCR: Scan for XSS vulnerabilities on given URL. (ext)
    TOOLS: xsscon
    """

    target = self.target.rstrip('/')
    if self.opts['attack_url']:
      target = self.opts['attack_url'].rstrip('/')
      opts = f"--single '{target}' --user-agent '{self.useragent}'"
    else:
      opts = f"-u '{target}' --depth 2 --user-agent '{self.useragent}'"

    if self.opts['proxy']:
      opts += f" --proxy '{self.opts['proxy']}'"

    self._run_tool('xsscon', opts, escape_codes=True, timeout=XSS.timeout)

    return


  @tool
  def xsscrapy(self):
    """
    DESCR: Crawl site and scan for XSS vulnerabilities on given URL
    TOOLS: xsscrapy
    """

    opts = f'-u {self.target}'

    if self.opts['cookies']:
      opts += f" -k '{self.cookies}'"

    if self.opts['web_user'] and self.opts['web_pass']:
      opts += f" --basic -l {self.opts['web_user']} -p {self.opts['web_pass']}"

    self._run_tool('xsscrapy', opts, timeout=XSS.timeout)

    return


  @tool
  def xsspy(self):
    """
    DESCR: Scan website for XSS vulnerabilities. (ext)
    TOOLS: xssless
    """

    target = self.target
    if self.opts['attack_url']:
      target = self.opts['attack_url']

    opts = f'-e -u {target}'

    if self.opts['cookies']:
      opts += f" -c '{self.cookies}'"

    self._run_tool('xsspy', opts, timeout=XSS.timeout, escape_codes=True)

    return


  @tool
  def xsstrike(self):
    """
    DESCR: Crawl website and scan for XSS vulnerabilities. (ext)
    TOOLS: xsstrike
    """

    opts = '--crawl --params -l 2 -t 15 -d 0 --skip --log-file /dev/stdout'
    opts += f' --timeout {XSS.timeout}'

    if self.opts['proxy']:
      opts += f" --proxy {self.opts['proxy']}"
    if self.opts['post_data']:
      opts += f" --data {self.opts['post_data']}"

    target = self.target
    if self.opts['attack_url']:
      target = self.opts['attack_url']

    opts += f" -u '{target.rstrip('/')}'"

    self._run_tool('xsstrike', opts, escape_codes=True, timeout=XSS.timeout)

    return


# EOF
