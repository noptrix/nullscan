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
# mambo.py                                                                     #
#                                                                              #
# AUTHOR                                                                       #
# noptrix@nullsecurity.net                                                     #
#                                                                              #
################################################################################


# sys imports


# own imports
from modules.libs.base import Base, tool, timeout


class Mambo(Base):
  """ Mambo module """


  def __init__(self, target, opts):
    """ init """

    Base.__init__(self, target, opts)

    return


  @tool
  def cms_explorer_mambo(self):
    """
    DESCR: Reveal infos from Mambo website. (ext)
    TOOLS: cms-explorer
    """

    opts = f'-url {self.target} -type mambo -explore'

    if self.opts['proxy']:
      h, p, s, pa = self._parse_url(self.opts['proxy'])
      opts += f" -proxy {h}:{p}"

    self._run_tool('cms-explorer', opts, 'cms_explorer_mambo', timeout=600)

    return


# EOF
