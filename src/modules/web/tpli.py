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
# tpli.py                                                                      #
#                                                                              #
# AUTHOR                                                                       #
# noptrix@nullsecurity.net                                                     #
#                                                                              #
################################################################################


# sys imports


# own imports
from modules.libs.base import Base, tool, timeout


class TPLI(Base):
  """ Server-Side Template Injection module """


  def __init__(self, target, opts):
    """ init """

    Base.__init__(self, target, opts)

    return


  @tool
  def tplmap(self):
    """
    DESCR: Test URL for template-injection vulnerability. (ext)
    TOOLS: tplmap
    """

    opts = f"--level 5 -A '{self.useragent}'"

    if self.opts['post_data']:
      opts += f" -d '{self.opts['post_data']}'"
    if self.opts['cookies']:
      opts += f" -c '{self.cookies}'"
    if self.opts['proxy']:
      opts += f" --proxy='{self.opts['proxy']}'"

    target = self.target
    if self.opts['attack_url']:
      target = self.opts['attack_url']

    opts = f'{opts} -u {target}'

    self._run_tool('tplmap', opts)

    return


# EOF
