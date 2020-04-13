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
# rce.py                                                                       #
#                                                                              #
# AUTHOR                                                                       #
# noptrix@nullsecurity.net                                                     #
#                                                                              #
################################################################################


# sys imports


# own imports
from modules.libs.base import Base, tool, timeout


class WAF(Base):
  """ WAF module """


  def __init__(self, target, opts):
    """ init """

    Base.__init__(self, target, opts)

    return


  @tool
  def wafpass(self):
    """
    DESCR: Analysing parameters with all payloads' bypass methods. (ext)
    TOOLS: wafpass
    """

    opts = f"-t all -a '{self.useragent}'"

    target = self.target
    if self.opts['attack_url']:
      target = self.opts['attack_url']

    if self.opts['cookies']:
      opts += f" -c {self.cookies}"
    if self.opts['proxy']:
      opts += f" -x {self.opts['proxy']}"
    if self.opts['post_data']:
      opts += f" -p {self.opts['post_data']}"

    opts += f" -u '{target}'"

    self._run_tool('wafpass', opts)

    return


  @tool
  def wafw00f(self):
    """
    DESCR: Identify and fingerprint Web Application Firewall (WAF) products
           protecting a website. (ext)
    TOOLS: wafw00f
    """

    opts = f'-a {self.target}'

    if self.opts['proxy']:
      opts += f" -p {self.opts['proxy']}"

    self._run_tool('wafw00f', opts, escape_codes=True)

    return


# EOF
