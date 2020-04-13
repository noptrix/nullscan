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
# finc.py                                                                      #
#                                                                              #
# AUTHOR                                                                       #
# noptrix@nullsecurity.net                                                     #
#                                                                              #
################################################################################


# sys imports


# own imports
from modules.libs.base import Base, tool, timeout


class Finc(Base):
  """ File Inclusion module """

  timeout = 1800  # default global timeout


  def __init__(self, target, opts):
    """ init """

    Base.__init__(self, target, opts)

    self.host, self.port, self.scheme, self.path = self._parse_url(self.target)

    return


  @tool
  def lfimap(self):
    """
    DESCR: Map local file inclusion vulnerabilities. (ext)
    TOOLS: lfimap
    """

    opts = '-n'

    if self.opts['user'] and self.opts['pass']:
      opts += f" -u {self.opts['user']} -p {self.opts['pass']}"
    if self.opts['proxy']:
      opts += f" --proxy {self.opts['proxy']}"

    target = self.target
    if self.opts['attack_url']:
      target = self.opts['attack_url']

    opts += f' -t {target}'

    self._run_tool('lfimap', opts, timeout=Finc.timeout)

    return


  @tool
  def fimap(self):
    """
    DESCR: Crawl website and test for remote and local file inclusion bugs.
           (ext)
    TOOLS: fimap
    """

    opts = f"-H -w /tmp/{self.host}-f.txt -4 -b -v 0 -d 1 -A '{self.useragent}'"

    target = self.target
    if self.opts['attack_url']:
      target = self.opts['attack_url']

    if self.opts['cookies']:
      opts += f" --cookie '{self.cookies}'"
    if self.opts['proxy']:
      h, p, s, pa = self._parse_url(self.opts['proxy'])
      opts += f' --http-proxy {h}:{p}'

    opts += f" -u {target}"

    self._run_tool('fimap', opts, timeout=Finc.timeout)
    self._run_cmd('rm fimap.log')

    return


  @tool
  def dsfs(self):
    """
    DESCR: Scan for file inclusion vulnerabilities on given URL with parameters
           included. (ext)
    TOOLS: dsfs
    """

    opts = f"--user-agent '{self.useragent}'"

    target = self.target
    if self.opts['attack_url']:
      target = self.opts['attack_url']

    if self.opts['cookies']:
      opts += f"' --cookie '{self.cookies}'"
    if self.opts['proxy']:
      opts += f" --proxy {self.opts['proxy']}"

    opts = f'-u {target} {opts}'

    self._run_tool('dsfs', opts, timeout=Finc.timeout)

    return


# EOF
