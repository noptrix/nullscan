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
# sharepoint.py                                                                #
#                                                                              #
# AUTHOR                                                                       #
# noptrix@nullsecurity.net                                                     #
#                                                                              #
################################################################################


# sys imports


# own imports
from modules.libs.base import Base, tool, timeout


class Sharepoint(Base):
  """ Sharepoint module """


  def __init__(self, target, opts):
    """ init """

    Base.__init__(self, target, opts)

    self.host, self.port, self.scheme, self.path = self._parse_url(self.target)

    return


  @tool
  def sparty_sp(self):
    """
    DESCR: Audit MS-Frontpage application: fingerprint, dump data, exploit etc.
           (ext)
    TOOLS: sparty
    """

    self._sparty(self.target, 'sparty_sp', mode='sharepoint')

    return


# EOF
