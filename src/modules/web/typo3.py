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
# typo3.py                                                                     #
#                                                                              #
# AUTHOR                                                                       #
# noptrix@nullsecurity.net                                                     #
#                                                                              #
################################################################################


# sys imports


# own imports
from modules.libs.base import Base, tool, timeout


class Typo3(Base):
  """ Typo3 CMD module """


  def __init__(self, target, opts):
    """ init """

    Base.__init__(self, target, opts)

    self.host, self.port, self.scheme, self.path = self._parse_url(self.target)

    return


  @tool
  def typo_enumerator(self):
    """
    DESCR: Enumerate Typo3 version and extensions. (ext)
    TOOLS: typo-enumerator
    """

    opts = f'-d {self.target} --timeout 5 --threads 15'
    opts += f" --agent '{self.useragent}'"

    if self.opts['cookies']:
      opts += f" --cookies '{self.cookies}'"

    if self.opts['web_user'] and self.opts['web_pass']:
      opts += f" --auth '{self.opts['web_user']}:{self.opts['web_pass']}'"

    self._run_tool('typo-enumerator', opts, 'typo_enumerator')

    return


# EOF
