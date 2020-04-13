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
# parser.py                                                                    #
#                                                                              #
# AUTHOR                                                                       #
# noptrix@nullsecurity.net                                                     #
#                                                                              #
################################################################################


# sys imports
import re
import os


# own imports
from modules.libs.helper import Helper


class Parser():
  """ tools results (logfiles) parser class """


  def __init__(self):
    """ init """

    return


  def _get_arpsweep_hosts(self):
    """ get hosts from parsed arpsweep.log """

    hosts = []

    data = self._parse_arpsweep_log()
    for i in data:
      hosts.append(i['host'])

    return hosts


  def _parse_arpsweep_log(self):
    """ parse arpsweep.log """

    hosts = []

    data = self._read_log('arpsweep')
    for d in data:
      d = d.split()
      hosts.append({'host': d[0], 'mac': d[1], 'vendor': ' '.join(d[2:])})

    return hosts


  def _parse_pyrit_analyze(self, data):
    """ parse pyrit analyze output
        will return:
        dict({'<bssid>':[('<sta>', handshakes), ...], '<bssid>':...})
    """

    """ example output:
    #1: AccessPoint 92:f3:65:74:d2:db ('None'):
      #1: Station 54:63:6b:d4:80:65
    #2: AccessPoint ff:ff:ff:ff:ff:3f ('None'):
      #1: Station 40:04:94:70:85:fd
    #3: AccessPoint 98:d3:04:64:fa:55 ('None'):
      #1: Station 00:0d:93:82:36:3a
    #4: AccessPoint 00:0c:41:82:b2:55 ('Coherer'):
      #1: Station 00:0d:93:82:36:3a, 1 handshake(s):
        #1: HMAC_SHA1_AES, good*, spread 1
      #2: Station 00:0d:1d:06:e0:f2
    """

    ret = dict()
    regex_mac = ':'.join(['[\d,a,b,c,d,e,f]{2}']*6)
    cur_ap = None
    for line in data:
      if 'AccessPoint' in line:
        # handle Access point line
        m = re.match(r'.*({})\s+\(\'(\S+)\'\):'.format(regex_mac), line)
        if m:
          bssid, ssid = m.group(1), m.group(2)
          if ssid == 'None':
            cur_app = None
            continue
          ret[ssid] = []
          cur_ap = ssid
      elif 'Station' in line and cur_ap != None:
        # handle Station line
        handshakes = 0
        if 'handshake' in line:
          m = re.match(r'.*, (\d+) handshake\(s\):', line)
          if m:
            handshakes = int(m.group(1))
        m = re.match(r'.*Station ({}).*'.format(regex_mac), line)
        if m:
          ret[cur_ap].append((m.group(1), handshakes))

    return ret




# EOF
