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
# geo.py                                                                       #
#                                                                              #
# AUTHOR                                                                       #
# noptrix@nullsecurity.net                                                     #
#                                                                              #
################################################################################


# sys imports
import requests
import json


# own imports
from modules.libs.base import Base, tool, timeout


class Geo(Base):
  """ GEO module (host) """


  def __init__(self, target, opts):
    """ init """

    Base.__init__(self, target, opts)

    return


  @tool
  def geoiplookup(self):
    """
    DESCR: Get country name and country code. (ext)
    TOOLS: geoiplookup
    """

    opts = f"{self.target['host']}"

    if not self.target['privip']:
      self._run_tool('geoiplookup', opts)

    return


  @tool
  def geoiplookup6(self):
    """
    DESCR: Get country name and country code. (ext)
    TOOLS: geoiplookup6
    """

    opts = f"{self.target['host']}"

    if not self.target['privip']:
      self._run_tool('geoiplookup6', opts)

    return


  @tool
  def geoiptools(self):
    """
    DESCR: Get GEO information via geoip.tools site. (int)
    TOOLS: python3
    """

    url = f"http://api.ipapi.com/{self.target['host']}?access_key="
    url += f"{self.opts['ipapi_key']}"
    headers = {'User-Agent': self.useragent}

    if not self.target['privip']:
      res = requests.get(url, verify=False, headers=headers).json()
      self._log('geoiptools', json.dumps(res, indent=2, sort_keys=True))

    return


# EOF
