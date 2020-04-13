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
# sqli.py                                                                      #
#                                                                              #
# AUTHOR                                                                       #
# noptrix@nullsecurity.net                                                     #
#                                                                              #
################################################################################


# sys imports


# own imports
from modules.libs.base import Base, tool, timeout


class SQLI(Base):
  """ SQL Injection module """

  timeout = 3600


  def __init__(self, target, opts):
    """ init """

    Base.__init__(self, target, opts)

    return


  @tool
  def sqlmap(self):
    """
    DESCR: Crawl website and test for SQL-injection vulnerabilities. (ext)
    TOOLS: sqlmap
    """

    opts = '--timeout 10 --retries 2 --level 5 --risk=3 --time-sec 3 --eta -f'
    opts += ' --current-user --current-db --hostname --threads 8'
    opts += ' --disable-coloring --crawl 2 --batch --keep-alive'
    opts += f" --output-dir /tmp/sqlmap --user-agent '{self.useragent}'"

    target = self.target
    if self.opts['attack_url']:
      target = self.opts['attack_url']

    if self.opts['cookies']:
      opts += f" --cookie '{self.cookies}'"
    if self.opts['proxy']:
      opts += f" --proxy {self.opts['proxy']}"
    if self.opts['proxy_user'] and self.opts['proxy_pass']:
      opts += f" --proxy-cred {self.opts['proxy_user']}:"
      opts += f"{self.opts['proxy_pass']}"
    if self.opts['web_user'] and self.opts['web_pass']:
      opts += f' --auth-type Basic'
      opts += f" --auth-cred {self.opts['web_user']}:{self.opts['web_pass']}"
    if self.opts['referer']:
      opts += f" --referer {self.opts['referer']}"
    if self.opts['post_data']:
      opts += f" --data {self.opts['post_data']}"

    opts += f" -u '{target}'"

    self._run_tool('sqlmap', opts, timeout=SQLI.timeout)

    return


  @tool
  def dsss(self):
    """
    DESCR: Scan for sql injection vulnerabilities on given URL with parameters
           included. (ext)
    TOOLS: dsss
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
      target = self.opts['attack_url']

    opts += f" -u '{target}'"

    self._run_tool('dsss', opts, timeout=SQLI.timeout)

    return


  @tool
  def scanqli(self):
    """
    DESCR: Scan for SQL injection vulnerabilities on given URL. (ext)
    TOOLS: scanqli
    """

    opts = '-s'

    target = self.target
    if self.opts['attack_url']:
      target = self.opts['attack_url']

    if self.opts['cookies']:
      opts += f" -c '{self.cookies}'"

    opts = f'-u {target}'
    self._run_tool('scanqli', opts, timeout=SQLI.timeout)

    return


# EOF
