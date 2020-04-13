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
# javascript.py                                                                #
#                                                                              #
# AUTHOR                                                                       #
# noptrix@nullsecurity.net                                                     #
#                                                                              #
################################################################################


# sys imports


# own imports
from modules.libs.base import Base, tool, timeout


class Javascript(Base):
  """ Javascript module """


  def __init__(self, target, opts):
    """ init """

    Base.__init__(self, target, opts)

    return


  @tool
  def dsjs(self):
    """
    DESCR: Scan for Javascript vulnerabilities on given URL with parameters
           included. (ext)
    TOOLS: dsjs
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

    self._run_tool('dsjs', opts)

    return


  @tool
  def gwtenum(self):
    """
    DESCR: Enumerate GWT-RCP method calls. (ext)
    TOOLS: gwtenum
    """

    opts = f'-u {self.target}'

    if self.opts['cookies']:
      opts += f" -k '{self.cookies}'"
    if self.opts['proxy']:
      opts += f" -p {self.opts['proxy']}"

    self._run_tool('gwtenum', opts)

    return


# EOF
