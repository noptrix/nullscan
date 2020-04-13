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
# wifi.py                                                                      #
#                                                                              #
# AUTHOR                                                                       #
# noptrix@nullsecurity.net                                                     #
#                                                                              #
################################################################################


# sys imports
from enum import Enum
import re

# own imports

class KbWifi:
  """ knowledge base class of WiFi tools """


  def __init__(self, ctx):
    """
    init takes ctx=tool.self object to get access to all the things.

    KbWifi is an abstraction of the information source and is indented to
    simplify all later running wifi modules/tools by providing a simple
    interface to access common information about currently
    available wifi networks.
    """

    self.ctx = ctx
    self.airodump = Airodump(self.ctx)
    #self.kismet = Kismet()

    return


  def essids(self):
    """ set of all found essids """

    return set([ap.essid for ap in self.airodump.aps if ap.essid is not None])

  def ssids(self):
    return self.essids()


  def bssids(self):
    """ set of all found bssids """

    return set([ap.bssid for ap in self.airodump.aps if ap.bssid is not None])


  def stations(self):
    """ set of all found stations """

    return self.airodump.stations


  def aps(self):
    """ set of all found access points """

    return self.airodump.aps

  def targets(self, opts):
    """
    Will return all known targets (aps and stations) that match supplied opts.
    More option add cumulative more targets and will not filter for less.
    The tool should filter the result as needed.

    opts.keys() = set(['bssid', 'station_mac', 'wifi_channel', 'ssid'])
    """

    station_mac = opts.get('station_mac', False)
    if station_mac:
      ret['stations'] |= set([sta for sta in self.stations() \
                              if sta.mac == station_mac])
      # there should only be one station that match statio_mac but just
      # to be sure
      for sta in ret['stations']:
        ret['aps'].add(sta.ap)

    ret = {'aps': set([]), 'stations': set([])}
    bssid = opts.get('bssid', False)
    if bssid:
      ret['aps'] |= set([ap for ap in self.aps() if ap.bssid == bssid])
      for ap in ret['aps']:
        ret['stations'] |= ap.stations


    ssid = opts.get('ssid', False)
    if ssid:
      ret['aps'] |= set([ap for ap in self.aps() if ap.essid == ssid])
      for ap in ret['aps']:
        ret['stations'] |= ap.stations

    wifi_channel = opts.get('wifi_channel', False)
    if wifi_channel:
      ret['aps'] |= set([ap for ap in self.aps() if ap.channel == wifi_channel])
      for ap in ret['aps']:
        ret['stations'] |= ap.stations

    return ret


class Station:
  """ station infos """


  def __init__(self, mac, ap=None, probs=None):
    """ init """

    self.mac = mac
    self.ap = ap
    self.probs = probs

    return


  def __hash__(self):
    """ ... """

    return self.mac.__hash__()


  def __cmp__(self, other):
    """ ... """

    return self.mac.__cmp__(other.bssid)


  def __eq__(self, other):
    """ ... """

    return self.mac.__eq__(other.mac)


  def __str__(self):
    """ ... """

    return f"<Sta: {self.mac} />"


  def __repr__(self):
    """ ... """

    return self.__str__()


class Ap:
  """ access point infos """


  def __init__(self, bssid, essid, channel,
    privacy=None, auth=None, cipher=None, power=None):
    """ init """

    self.bssid = bssid
    self.essid = essid
    self.channel = channel
    self.privacy = privacy
    self.auth = auth
    self.cipher = cipher
    self.power = power
    self.stations = set()
    self.handshakes = False

    return


  def __hash__(self):
    """ ... """

    return self.bssid.__hash__()


  def __cmp__(self, other):
    """ ... """

    return self.bssid.__cmp__(other.bssid)


  def __eq__(self, other):
    """ ... """

    return self.bssid.__eq__(other.bssid)


  def __str__(self):
    """ ... """

    return f"<Ap: {self.bssid}, {self.essid}, {self.channel} />"


  def __repr__(self):
    """ ... """

    return self.__str__()


# Note: if we add more info sources it would make sense to inherit from a
#       InfoSource base class and use the shared interface in KbWifi
class Airodump:
  """ parse and create python object of airodump csv infos """


  def __init__(self, ctx):
    """ init """

    self.ctx = ctx
    self.stations = set()
    self.aps = set()
    self._parse_airodump_csv()

    return


  def _parse_airodump_csv(self):
    """ parse airodump.log and extract all needed infos """

    ad_logs = self.ctx._get_all_log_files('.*airodump-ng.*\d+\.csv\.log')
    if len(ad_logs) == 0:
      self.ctx.log("[!] no matching airodump csv log found\n")
    ad_log = ad_logs[0]

    with open(ad_log, 'r') as fd:
      first_round = True

      # parse first part of the csv file
      for line in fd:
        if not first_round and len(line) == 1:
          # move on to second part
          break
        if first_round:
          first_round = False
        if line.startswith("BSSID,"):
          # skip header
          continue
        #ll = re.sub(r'\s+', '', line).split(',')
        ll = line.split(',')
        if len(ll) < 13:
          continue

        bssid     = self._str_or_none(ll[0])
        channel   = self._str_or_none(ll[3])
        essid     = self._str_or_none(ll[13])
        privacy   = self._str_or_none(ll[5])
        auth      = self._str_or_none(ll[6])
        cipher    = self._str_or_none(ll[7])
        power     = self._str_or_none(ll[8])

        self.aps.add(Ap(bssid, essid, channel, privacy, auth, cipher, power))

      # parse second part of the csv file
      for line in fd:
        ll = line.rstrip('\n').split(',')
        if len(ll) == 1:
          break
        if len(ll[0].split(':')) != 6:
          # skip header
          continue

        station   = self._str_or_none(ll[0])
        bssid     = self._str_or_none(ll[5])
        probe     = self._str_or_none(ll[6])
        if len(bssid.split(':')) != 6:
          bssid = None
          ap = None
        else:
          ap = self._get_ap(bssid)
        sta = Station(station, ap=ap, probs=probe)
        self.stations.add(sta)
        if ap is not None:
          ap.stations.add(sta)

    return


  def _str_or_none(self, x):
    """ ... """

    if len(x) > 0:
      return x.strip(' ').rstrip(' ')

    return None


  def _get_ap(self, bssid):
    """ ... """

    for ap in self.aps:
      if ap.bssid == bssid:
        return ap

    return None


if __name__ == '__main__':
  # testing code
  class FakeCtx:

    def _get_all_log_files(self, pattern):
      return ["/home/user/s/nullscan/nullscan-2020-01-20/logs/targets/"+\
            "wlan0mon/wifi/default/airodump-ng-01.csv.log"]

    def log(self, msg):
      print(msg)

  ctx = FakeCtx()
  kb = KbWifi(ctx)
  print(kb.essids())
  print(kb.bssids())

  print("aps:")
  for ap in kb.aps():
    print(f"{ap.bssid}, {ap.essid}, {ap.channel}, {ap.privacy},"+\
        f" {ap.auth}, {ap.cipher}, {ap.power}, {ap.stations}")

  print("stations:")
  for sta in kb.stations():
    print(f"{sta.mac}, {sta.ap}, {sta.probs}")


# EOF
