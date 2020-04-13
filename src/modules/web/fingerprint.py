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
import json
import glob


# own imports
from modules.libs.base import Base, tool, timeout


class Fingerprint(Base):
  """ Fingerprint module """


  def __init__(self, target, opts):
    """ init """

    Base.__init__(self, target, opts)

    self.host, self.port, self.scheme, self.path = self._parse_url(self.target)

    return


  @tool
  def whatweb(self):
    """
    DESCR: Fingerprint and enumerate information from website. (ext)
    TOOLS: whatweb
    """

    opts = '-a 3 --open-timeout 10 -t 20 --color=never --read-timeout 10'
    opts += f" --user-agent '{self.useragent}'"

    if self.opts['web_user'] and self.opts['web_pass']:
      opts += f" -u {self.opts['web_user']}:{self.opts['web_pass']}"

    if self.opts['cookies']:
      opts += f" --cookie '{self.cookies}'"

    if self.opts['proxy']:
      opts += f" --proxy '{self.opts['proxy']}'"
      if self.opts['proxy_user'] and self.opts['proxy_pass']:
        opts += f" --proxy user {self.opts['proxy_user']}:"
        opts += f"{self.opts['proxy_pass']}"

    opts += f' {self.target}'

    self._run_tool('whatweb', opts)

    return


  @tool
  def blindelephant(self):
    """
    DESCR: Fingerprint the website / webapp. (ext)
    TOOLS: blindelephant
    """

    opts = f'{self.target} guess'
    self._run_tool('blindelephant', opts)

    return


  @tool
  def wafp(self):
    """
    DESCR: Fingerprint the web-application. (ext)
    TOOLS: wafp
    """

    opts = f'--timeout 5 --retries 1 -t 15 {self.target}'
    self._run_tool('wafp', opts)

    return


  @tool
  def wafw00f(self):
    """
    DESCR: Detect and fingerprint web-application firewall. (ext)
    TOOLS: wafw00f
    """

    opts = f'-a {self.target}'

    if self.opts['proxy']:
      opts += f" -p {self.opts['proxy']}"

    self._run_tool('wafw00f', opts, escape_codes=True)

    return


  @tool
  def cmseek(self):
    """
    DESCR: Detect CMS version. (ext)
    TOOLS: cmseek
    """

    opts = f"--user-agent '{self.useragent}' -u {self.target}"
    self._run_tool('cmseek', opts, precmd='echo -e "\\n" |', create_log=False)

    jsonlog = ''.join(glob.glob(f'Result/{self.host}*/cms.json'))
    with open(jsonlog, 'r') as jf:
      log = json.load(jf)
    self._log('cmseek', json.dumps(log, indent=2, sort_keys=True), mode='w')

    return


  @tool
  def lbmap_web(self):
    """
    DESCR: Fingerprint web server. (ext)
    TOOLS: lbmap
    """

    self._lbmap(self.host, self.port, self.scheme)

    self.file.copy_files(f'lbmap_{self.scheme}.log', 'lbmap_web.log', move=True)

    return


  @tool
  def webanalyze(self):
    """
    DESCR: Uncovers technologies used on websites. (ext)
    TOOLS: webanalyze
    """

    opts = '-crawl 10 -output stdout -worker 10'
    opts += f' -apps /usr/share/webanalyze/apps.json -host {self.target}'

    self._run_tool('webanalyze', opts, timeout=90)

    return


  @tool
  def webtech(self):
    """
    DESCR: Identify technologies used on websites. (ext)
    TOOLS: webtech
    """

    target = self.target
    if self.opts['attack_url']:
      target = self.opts['attack_url']

    opts = f"--timeout 120 --user-agent '{self.useragent}' -u {target}"

    self._run_tool('webtech', opts, timeout=120)

    return


# EOF
