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
# csrf.py                                                                      #
#                                                                              #
# AUTHOR                                                                       #
# noptrix@nullsecurity.net                                                     #
#                                                                              #
################################################################################


# sys imports


# own imports
from modules.libs.base import Base, tool, timeout


class CSRF(Base):
  """ Cross-Site Request Forgery module """


  def __init__(self, target, opts):
    """ init """

    Base.__init__(self, target, opts)

    self.host, self.port, self.scheme, self.path = self._parse_url(self.target)

    return


  @tool
  def xsrfprobe(self):
    """
    DESCR: Crawl and check for CSRF vulnerabilities. (ext)
    TOOLS: xsrfprobe
    """

    opts = f"--no-analysis --skip-poc --crawl --user-agent '{self.useragent}'"
    opts += ' -o /tmp/'

    target = self.target
    if self.opts['attack_url']:
      target = self.opts['attack_url']

    if self.opts['cookies']:
      opts += f" -c '{self.cookies}'"

    opts += f' -u {target}'

    self._run_tool('xsrfprobe', opts, escape_codes=True, timeout=1800)

    self.file.del_file(f'/tmp/{self.host}', _dir=True)

    return


# EOF
