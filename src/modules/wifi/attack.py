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
# attack.py                                                                    #
#                                                                              #
# AUTHOR                                                                       #
# noptrix@nullsecurity.net                                                     #
#                                                                              #
################################################################################


# sys imports


# own imports
from modules.libs.base import Base, tool, timeout
import modules.libs.wifi as wifi
import modules.wifi.handshake as handshake
import modules.wifi.crack as crack


class Attack(Base):
  """
              Attack WiFi module
  The WiFi Attack Module combines multiple Tools
  to create multi stage attacks where results
  from earlier stages can be used in later stages.
  """


  def __init__(self, target, opts):
    """ init """

    Base.__init__(self, target, opts)

    return


  @tool
  def wpa2_deauth_crack(self):
    """
    DESCR: Implements an attack-chain on WPA2 Networks:
           1) deauth stations from target ap to capture handshakes
           2) crack captured handshakes
           (int)
    TOOLS: bettercap aircrack-ng
    """

    h = handshake.Handshake(self.target, self.opts)
    c = crack.Crack(self.target, self.opts)
    kb = wifi.KbWifi(self)
    tool_name = 'wpa2_deauth_crack'

    self._log(tool_name, 'starting bettercap_wifi_deauth')
    #self.opts['wifi_timeout'] = 30
    h.bettercap_wifi_deauth()
    self._log(tool_name, 'starting aircrack')
    c.aircrack()

    return


# EOF
