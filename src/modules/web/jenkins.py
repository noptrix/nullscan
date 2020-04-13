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
# jenkins.py                                                                   #
#                                                                              #
# AUTHOR                                                                       #
# noptrix@nullsecurity.net                                                     #
#                                                                              #
################################################################################


# sys imports


# own imports
from modules.libs.base import Base, tool, timeout


class Jenkins(Base):
  """ Jenkins module """


  def __init__(self, target, opts):
    """ init """

    Base.__init__(self, target, opts)

    self.host, self.port, self.scheme, self.path = self._parse_url(self.target)

    return


  @tool
  def jexboss_jenkins(self):
    """
    DESCR: Check for Jenkins CLI vulnerability (CVE-2015-5317). (ext)
    TOOLS: jexboss
    """

    opts = '-D --jenkins'

    self._jexboss(self.host, self.port, 'jexboss_jenkins', scheme=self.scheme)

    return


# EOF
