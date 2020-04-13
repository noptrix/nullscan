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
# rogue.py                                                                     #
#                                                                              #
# AUTHOR                                                                       #
# noptrix@nullsecurity.net                                                     #
#                                                                              #
################################################################################


# sys imports
import os
import shutil


# own imports
from modules.libs.base import Base, tool, timeout
import modules.libs.wifi  as wifi


class Rogue(Base):
  """ Rogue WiFi module """


  def __init__(self, target, opts):
    """ init """

    Base.__init__(self, target, opts)

    return


  @tool
  def eaphammer(self):
    """
    DESCR: Targeted evil twin attacks against WPA2-Enterprise networks. (ext)
    TOOLS: eaphammer
    """

    #TODO: needs more testing. On my test system I run into the following error:
    #----> Failed to setup control interface for wlan0

    # Note: make sure that the supplied target (interface) is NOT in
    #       monitor mode (started with airmon-ng start wlan0 --> wlan0mon).

    kb = wifi.KbWifi(self)
    interface = self.target
    channel = self.opts['wifi_channel']
    ssid = self.opts['ssid']
    bssid = self.opts['bssid']
    tool_name = "eaphammer"

    if len(ssid) > 0 or len(bssid) > 0:
      target = kb.targets({'bssid': bssid, 'ssid': ssid})
      ap = target['aps'].pop()
      ssid = ap.essid
      channel = ap.channel

    channel_opt = ''
    if len(channel) > 0:
      channel_opt = f"--channel {channel} "

    if len(ssid) == 0:
      self._log(tool_name, "no ssid given or found")
      return

    opts = f"-i {interface} {channel_opt} --auth wpa-eap --essid {ssid} --creds"

    self._run_tool(tool_name, opts,
      timeout=self.opts['wifi_timeout'],
      precmd=force_flush,
      escape_codes=True
      )

    # copy captured handshakes to target log folder
    search_line = "[*] WPA handshakes will be saved to "
    handshake_path = None
    for line in self._read_log(tool_name):
      if line.startswith(search_line):
        handshake_path = line[len(search_line):-1].rstrip('\n')
        break
    if handshake_path is not None and os.path.exist(handshake_path):
      shutil.copyfile(handshake_path, 'eaphammer_wpa_handshakes.hccapx.log')

    return


# EOF
