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
# concrete5.py                                                                 #
#                                                                              #
# AUTHOR                                                                       #
# noptrix@nullsecurity.net                                                     #
#                                                                              #
################################################################################


# sys imports


# own imports
from modules.libs.base import Base, tool, timeout


class Concrete5(Base):
  """ Concrete5 CMS module """


  def __init__(self, target, opts):
    """ init """

    Base.__init__(self, target, opts)

    return


  @tool
  def c5scan(self):
    """
    DESCR: Gather Concrete5 cms information and scan known vulnerabilities.
           (ext)
    TOOLS: c5scan
    """

    opts = f'-u {self.target}'
    self._run_tool('c5scan', opts)

    return


  @tool
  def conscan(self):
    """
    DESCR: Gather Concrete5 cms information and scan for known vulnerabilities.
           (ext)
    TOOLS: conscan
    """

    opts = f'-t {self.target} -e'
    self._run_tool('conscan', opts)

    return


# EOF
