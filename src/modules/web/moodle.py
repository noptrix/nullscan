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
# moodle.py                                                                    #
#                                                                              #
# AUTHOR                                                                       #
# noptrix@nullsecurity.net                                                     #
#                                                                              #
################################################################################


# sys imports


# own imports
from modules.libs.base import Base, tool, timeout


class Moodle(Base):
  """ Moodle module """


  def __init__(self, target, opts):
    """ init """

    Base.__init__(self, target, opts)

    return


  @tool
  def droopescan_moodle(self):
    """
    DESCR: Enumerate everything possible on Moodle website. (ext)
    TOOLS: droopescan
    """

    self._droopescan('moodle')

    return


  @tool
  def mooscan(self):
    """
    DESCR: Scan a moodle website. (ext)
    TOOLS: mooscan
    """

    opts = f'--url {self.target}'
    self._run_tool('mooscan', opts)

    return


# EOF
