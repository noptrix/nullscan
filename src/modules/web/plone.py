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
# plone.py                                                                     #
#                                                                              #
# AUTHOR                                                                       #
# noptrix@nullsecurity.net                                                     #
#                                                                              #
################################################################################


# sys imports
import concurrent.futures as cf


# own imports
from modules.libs.base import Base, tool, timeout


class Plone(Base):
  """ Plone CMS module """


  def __init__(self, target, opts):
    """ init """

    Base.__init__(self, target, opts)

    return


  @tool
  def plown(self):
    """
    DESCR: Enumerate Plone CMS. (ext)
    TOOLS: plown
    """

    opts = f'-T 20 {self.target}'
    self._run_tool('plown', opts)

    return


  @tool
  def plown_brute(self):
    """
    DESCR: Bruteforce logins Plone CMS. (ext)
    TOOLS: plown
    """

    opts = f'-b -T 20 {self.target}'
    threads = 5

    if self.opts['ulists'] and self.opts['plists']:
      with cf.ThreadPoolExecutor(threads) as exe:
        for ulist in self.opts['ulists']:
          for plist in self.opts['plists']:
            opts = f'-U {ulist} -P {plist} {opts}'
            exe.submit(self._run_tool, 'plown', opts, 'plown_brute')

    return


# EOF
