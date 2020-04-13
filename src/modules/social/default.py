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
import sqlite3


# own imports
from modules.libs.base import Base, tool, timeout


class Default(Base):
  """ Default module (social) """


  def __init__(self, target, opts):
    """ init """

    Base.__init__(self, target, opts)

    return


  @tool
  def theharvester_mail(self):
    """
    DESCR: Gather email addresses from company or domain name. (ext)
    TOOLS: theharvester
    """

    opts = f"-d '{self.target}' -l 100"
    opts = ' -b all'
    #opts += ' -b baidu,bing,bingapi,censys,crtsh,dnsdumpster,dogpile,'
    #opts += 'duckduckgo,exalead,github-code,google,hunter,intelx,linkedin,'
    #opts += 'netcraft,securityTrails,threatcrowd,trello,twitter,vhost,'
    #opts += 'virustotal,yahoo'

    if self.opts['target_type'] == 'company' or \
      self.opts['target_type'] == 'domain':
        self._run_tool('theharvester', opts, create_log=False)

    conn = sqlite3.connect('stash.sqlite', timeout=2)
    c = conn.cursor()
    c.execute('SELECT resource FROM results where type="email"')
    res = c.fetchall()
    conn.close()

    for row in res:
      for i in row:
        if '@' in i:
          self._log('theharvester_mail', i)

    return


  @tool
  def google_urls(self):
    """
    DESCR: Play google: Find any URLs (max 100) related to target. (int)
    TOOLS: python3
    """

    with timeout(self.opts['timeout']):
      for url in self._googlesearch(self.target):
        self._log('google_urls', url)

    return


  @tool
  def pwned(self):
    """
    DESCR: Query the 'have I been pwned' service. (ext)
    TOOLS: pwned
    """

    opts = f'search {self.target}'

    self._run_tool('pwned', opts, escape_codes=True)

    return


  @tool
  def sherlock(self):
    """
    DESCR: Find usernames across social networks. (ext)
    TOOLS: sherlock
    """

    log = f'/tmp/sherlock-{self.target.split()[0]}.txt'
    opts = '-r --print-found'

    cmd = f"sherlock {opts} -o {log} '{self.target}'"
    self._run_cmd(cmd)

    res = self.file.read_file(log)
    del res[-1]
    self._log('sherlock', '\n'.join(res))

    return


  @tool
  def whatsmyname(self):
    """
    DESCR: Perform user and username enumeration on various websites. (ext)
    TOOLS: whatsmyname
    """

    opts = f"-u '{self.target}'"
    res = self._run_cmd(f'whatsmyname {opts}', escape_codes=True)
    for line in res:
      if line.startswith('[+]'):
        self._log('whatsmyname', line)

    return


# EOF
