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
# joomla.py                                                                    #
#                                                                              #
# AUTHOR                                                                       #
# noptrix@nullsecurity.net                                                     #
#                                                                              #
################################################################################


# sys imports


# own imports
from modules.libs.base import Base, tool, timeout


class Joomla(Base):
  """ joomla module """


  def __init__(self, target, opts):
    """ init """

    Base.__init__(self, target, opts)

    return


  @tool
  def cms_explorer_joomla(self):
    """
    DESCR: Reveal infos from Joomla website. (ext)
    TOOLS: cms-explorer
    """

    opts = f'-url {self.target} -type joomla -explore'

    if self.opts['proxy']:
      h, p, s, pa = self._parse_url(self.opts['proxy'])
      opts += f" -proxy {h}:{p}"

    self._run_tool('cms-explorer', opts, 'cms_explorer_joomla', timeout=600)

    return


  @tool
  def droopescan_joomla(self):
    """
    DESCR: Enumerate everything possible on Joomla website. (ext)
    TOOLS: droopescan
    """

    self._droopescan('joomla')

    return


  @tool
  def joomlascan(self):
    """
    DESCR: Scan for Joomla instance and vulnerabilities. (ext)
    TOOLS: joomlascan
    """

    opts = f'{self.target} -404'

    if self.opts['proxy']:
      h, p, s, pa = self._parse_url(self.target)
      opts += f' -p {h}:{p}'

    self._run_tool('joomlascan', opts)

    return


  @tool
  def joomscan(self):
    """
    DESCR: Scan for Joomla vulnerabilities and more. (ext)
    TOOLS: joomscan
    """

    opts = f"-u {self.target} -ec -a '{self.useragent}'"

    if self.opts['cookies']:
      opts += f" --cookie '{self.cookies}'"
    if self.opts['proxy']:
      opts += f" --proxy {self.opts['proxy']}"

    self._run_tool('joomscan', opts, escape_codes=True)

    return


  @tool
  def joomlavs(self):
    """
    DESCR:
    TOOLS: joomlavs
    """

    opts = f'-u {self.target} -a --disable-tls-checks --follow-redirection'
    opts += ' --no-colour --threads 10 --hide-banner'

    if self.opts['proxy']:
      opts += f" --proxy {self.opts['proxy']}"
      if self.opts['proxy_user'] and self.opts['proxy_pass']:
        opts += f" --proxy-auth {self.opts['proxy_user']}:"
        opts += f"{self.opts['proxy_pass']}"

    self._run_tool('joomlavs', opts)

    return


# EOF
