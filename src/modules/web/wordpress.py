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
# wordpress.py                                                                 #
#                                                                              #
# AUTHOR                                                                       #
# noptrix@nullsecurity.net                                                     #
#                                                                              #
################################################################################


# sys imports
import concurrent.futures as cf


# own imports
from modules.libs.base import Base, tool, timeout


class Wordpress(Base):
  """ Wordpress module """

  timeout = 3600    # 1h default timeout


  def __init__(self, target, opts):
    """ init """

    Base.__init__(self, target, opts)

    return


  @tool
  def cms_explorer_wordpress(self):
    """
    DESCR: Reveal infos from Wordpress website. (ext)
    TOOLS: cms-explorer
    """

    opts = f'-url {self.target} -type wordpress -explore'

    if self.opts['proxy']:
      h, p, s, pa = self._parse_url(self.opts['proxy'])
      opts += f" -proxy {h}:{p}"

    self._run_tool('cms-explorer', opts, 'cms_explorer_wordpress', timeout=600)

    return


  @tool
  def plecost(self):
    """
    DESCR: Fingerprint wordpress version. (ext)
    TOOLS: plecost
    """

    opts = f'-nb -f --concurrency 10 -o /dev/stdout {self.target}'
    self._run_tool('plecost', opts, timeout=Wordpress.timeout)

    return


  @tool
  def wpscan(self):
    """
    DESCR: Enumerate everything from wordpress website. (ext)
    TOOLS: wpscan
    """

    wp_format = self.opts.get('wp_output_format', 'cli-no-color')
    opts = f"-f {wp_format} --no-banner -t 10 --connect-timeout 5"
    opts += ' --enumerate u,p,t,tt,cb,dbe --request-timeout 10'
    opts += f" --disable-tls-checks --user-agent '{self.useragent}' "

    if self.opts['cookies']:
      opts += f" --cookie '{self.cookies}'"

    if self.opts['web_user'] and self.opts['web_pass']:
      opts += f" --http-auth {self.opts['web_user']}:{self.opts['web_pass']}"

    if self.opts['proxy']:
      opts += f" --proxy {self.opts['proxy']}"
      if self.opts['proxy_user'] and self.opts['proxy_pass']:
        opts += f" --proxy-auth {self.opts['proxy_user']}:"
        opts += f"{self.opts['proxy_pass']}"

    opts += f' --url {self.target}'

    self._run_tool('wpscan', opts, precmd='yes |', timeout=Wordpress.timeout)

    return


  @tool
  def droopescan_wordpress(self):
    """
    DESCR: Enumerate everything on Wordpress website. (ext)
    TOOLS: droopescan
    """

    self._droopescan('wordpress')

    return


  @tool
  def vane(self):
    """
    DESCR: Enumerate everything from wordpress website. (ext)
    TOOLS: vane
    """

    opts = '--force --enumerate u,p,t --follow-redirection --batch --no-color'
    opts += ' --request-timeout 10 --connect-timeout 5 --threads 10'
    opts += f" --user-agent '{self.useragent}'"

    if self.opts['cookies']:
      opts += f" --cookie '{self.cookies}'"

    if self.opts['proxy']:
      opts += f" --proxy {self.opts['proxy']}"

    opts = f'--url {self.target} {opts}'

    self._run_tool('vane', opts, timeout=Wordpress.timeout)

    return


  @tool
  def wordpresscan(self):
    """
    DESCR: Enumerate everything from wordpress site. (ext)
    TOOLS: wordpresscan
    """

    opts = f'--aggressive --threads 15 --random-agent -u {self.target}'
    self._run_tool('wordpresscan', opts, escape_codes=True,
      timeout=Wordpress.timeout)

    return


  @tool
  def wpseku(self):
    """
    DESCR: Enumerate everything from wordpress site. (ext)
    TOOLS: wpseku
    """

    opts = f"-t 10 -a '{self.useragent}' -u {self.target}"

    if self.opts['cookies']:
      opts += f" -c '{self.cookies}'"

    if self.opts['proxy']:
      opts += f" -p self.opts['proxy']"

    self._run_tool('wpseku', opts, escape_codes=True, timeout=Wordpress.timeout)

    return


# EOF
