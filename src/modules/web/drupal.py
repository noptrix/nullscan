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
# drupal.py                                                                    #
#                                                                              #
# AUTHOR                                                                       #
# noptrix@nullsecurity.net                                                     #
#                                                                              #
################################################################################


# sys imports


# own imports
from modules.libs.base import Base, tool, timeout


class Drupal(Base):
  """ Drupal module """


  def __init__(self, target, opts):
    """ init """

    Base.__init__(self, target, opts)

    return


  @tool
  def cms_explorer_drupal(self):
    """
    DESCR: Reveal infos about drupal website. (ext)
    TOOLS: cms-explorer
    """

    opts = f'-url {self.target} -type Drupal -explore'

    if self.opts['proxy']:
      h, p, s, pa = self._parse_url(self.opts['proxy'])
      opts += f" -proxy {h}:{p}"

    self._run_tool('cms-explorer', opts, 'cms_explorer_drupal', timeout=600)

    return


  @tool
  def drupalscan(self):
    """
    DESCR: Fingerprint Drupal modules and versions. (ext)
    TOOLS: drupalscan
    """

    opts = f'-u {self.target}'
    self._run_tool('drupalscan', opts)

    return


  @tool
  def dpscan(self):
    """
    DESCR: Enumerate Drupal modules. (ext)
    TOOLS: dpscan
    """

    opts = f'{self.target}'
    self._run_tool('dpscan', opts)

    return


  @tool
  def droopescan_drupal(self):
    """
    DESCR: Enumerate everything possible on Drupal site. (ext)
    TOOLS: droopescan
    """

    self._droopescan()

    return


  @tool
  def drupwn(self):
    """
    DESCR: Enumerate everything possible on Drupal site. (ext)
    TOOLS: drupwn
    """

    opts = '--users --nodes --modules --dfiles --themes --thread 15'
    opts += f" --ua '{self.useragent}'"

    if self.opts['cookies']:
      opts += f" --cookies '{self.cookies}'"
    if self.opts['proxy']:
      opts += f" --proxy {self.opts['proxy']}"

    opts += f" enum {self.target}"

    self._run_tool('drupwn', opts, escape_codes=True)

    return


# EOF
