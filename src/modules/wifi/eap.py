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
# eap.py                                                                       #
#                                                                              #
# AUTHOR                                                                       #
# noptrix@nullsecurity.net                                                     #
#                                                                              #
################################################################################


# sys imports
import os


# own imports
from modules.libs.base import Base, tool, timeout


class Eap(Base):
  """ EAP WiFi module """


  def __init__(self, target, opts):
    """ init """

    Base.__init__(self, target, opts)

    return


  @tool
  def eapeak(self):
    """
    DESCR: Analysis tool for EAP enabled networks. (ext)
    TOOLS: eapeak
    """

    interface = self.target
    tool_name = 'eapeak'
    pcaps = self._get_wifi_pcaps()
    for idx, pcap in enumerate(pcaps):
      self._run_tool(tool_name, f"-f {pcap} --xml")
      if os.path.exists('eapeak.xml'):
        os.rename('eapeak.xml', f"{tool_name}_{idx}.xml.log")

    return


  @tool
  def eapmd5pass(self):
    """
    DESCR: Dictionary attack against EAP-MD5. (ext)
    TOOLS: eapmd5pass
    """

    interface = self.target
    tool_name = 'eapmd5pass'
    pcaps = self._get_wifi_pcaps()
    pw_list = self.opts['plists'][0]
    for pcap in pcaps:
      self._run_tool(tool_name, f"-r {pcap} -w {pw_list}")

    return


# EOF
