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
# crack.py                                                                     #
#                                                                              #
# AUTHOR                                                                       #
# noptrix@nullsecurity.net                                                     #
#                                                                              #
################################################################################


# sys imports


# own imports
from modules.libs.base import Base, tool, timeout
import modules.libs.wifi as wifi


class Crack(Base):
  """ Cracker WiFi module """


  def __init__(self, target, opts):
    """ init """

    Base.__init__(self, target, opts)

    return


  @tool
  def speedpwn(self):
    """
    DESCR: Active bruteforce for weak standard passwords of wpa APs. (ext)
    TOOLS: speedpwn
    """

    kb = wifi.KbWifi(self)
    interface = self.target
    tool_name = 'speedpwn'
    ssid = self.opts['ssid']
    bssid = self.opts['bssid']
    wifi_channel = self.opts['wifi_channel']
    ready_to_run = False


    if len(bssid) > 0 and len(ssid) > 0 and len(wifi_channel):
      # all infos are already given, just use them
      ready_to_run = True
    elif len(bssid) > 0 or len(ssid) > 0:
      # some infos are missing but we can try to get the infos from kb
      target = kb.targets({'bssid': bssid, 'ssid': ssid})
      if len(targets['aps']) > 0:
        ap = target['aps'].pop()
        bssid = ap.bssid
        ssid =  ap.essid
        wifi_channel = ap.channel
        ready_to_run = True
      else:
        self._log(tool_name, f"no ap found for ssid={ssid}, bssid={bssid}")

    if not ready_to_run:
      # still not all infos found, stop here
      return

    # ready_to_run == True
    opts = [' -0']
    opts += ['-e', ssid]
    opts += ['-b', bssid]
    opts += ['-c', wifi_channel]
    opts += ['-w', self.opts['plists'][0]]
    opts += ['--medium']

    opts = f"{' '.join(opts)} {interface}"
    self._run_tool(tool_name, opts, timeout=self.opts['wifi_timeout'])

    return


  @tool
  def pyrit(self):
    """
    DESCR: Multi-Core-CPU/GPU-driven WPA/WPA2-PSK key cracker. (ext)
    TOOLS: pyrit
    """

    interface = self.target
    tool_name = 'pyrit'

    """
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

     parsed dict:
     -->
     {'Coherer': [('00:0d:93:82:36:3a', 1),('00:0d:1d:06:e0:f2', 0)]}
                                        ^
                                        |
                                   one handshake found
    """

    pcap_files = self._get_wifi_pcaps()
    for pcap_file in pcap_files:
      # init analysis
      out = self._run_cmd(tool_name+f" -r {pcap_file} analyze")
      res = self._parse_pyrit_analyze(out)
      for ssid in res.keys():
        sta_with_handshake = False
        for sta in res[ssid]:
          if sta[1] > 0:
            sta_with_handshake = True
            break
        if not sta_with_handshake:
          continue
        # create_essid
        self._run_tool(tool_name, f"-e {ssid} create_essid")

      # import password lists
      for pw_list in self.opts['plists']:
        self._run_tool(tool_name, f"-i {pw_list} import_passwords")

      # compute PMKs
      self._run_tool(tool_name, "batch", tool_name)

      # execute the actual dictionary attack
      self._run_tool(tool_name, f"-r {pcap_file} attack_db")

    return


  @tool
  def wifibroot(self):
    """
    DESCR: WiFi-Pentest/Cracking tool for WPA/WPA2. (ext)
    TOOLS: wifibroot
    """

    interface = self.target
    tool_name = 'wifibroot'

    # only mode 03 (offline cracking mode) is non interactive

    pcap_files = self._get_wifi_pcaps()
    pw_list = self.opts['plists'][0]
    for pcap_file in pcap_files:

      # try to crack pmkid
      self._run_tool(tool_name,
        f" --mode 03 --type pmkid -d {pw_list} -r {pcap_file}" +
        f" -e {self.opts['ssid']}",
        escape_codes=True)

      # try to crack handshake
      self._run_tool(tool_name,
        f" --mode 03 --type handshake -d {pw_list} -r {pcap_file}" +
        f" -e {self.opts['ssid']}",
        escape_codes=True)

    return


  @tool
  def wpa_halfhandshake_crack(self):
    """
    DESCR: Crack WPA2 network without full handshake capture. (ext)
    TOOLS: wpa2-halfhandshake-crack
    """

    kb = wifi.KbWifi(self)
    interface = self.target
    tool_name = 'wpa2-halfhandshake-crack'
    pw_list = self.opts['plists'][0]
    pcap_files = self._get_wifi_pcaps()
    bssid = self.opts['bssid']
    ssid = self.opts['ssid']
    ready_to_run = False

    if len(bssid) == 0 or len(ssid) == 0:
      target = kb.targets({'bssid': bssid, 'ssid': ssid})
      if len(target['aps']) > 0:
        ap = target['aps'].pop()
        ssid = ap.essid
        bssid = ap.bssid
        ready_to_run = True
      else:
        self._log(tool_name, f"no ap found for ssid={ssid} bssid={bssid}")

    if not ready_to_run:
      self._log(tool_name, f"need more infos -> ssid={ssid} and bssid={bssid}")
      return

    for pcap_file in pcap_files:
      self._run_tool(tool_name,
        f" -r {pcap_file} -m {bssid} -s '{ssid}'" +
        f" -d {pw_list}")

    return


  @tool
  def cowpatty(self):
    """
    DESCR: Offline dictionarry attack against WPA/WPA2. (ext)
    TOOLS: cowpatty
    """

    interface = self.target
    tool_name = 'cowpatty'
    pw_list = self.opts['plists'][0]
    pcap_files = self._get_wifi_pcaps()

    for pcap_file in pcap_files:
      self._run_tool(tool_name, f" -r '{pcap_file}' -f '{pw_list}'" +
        f" -s '{self.opts['ssid']}'")

    return


  @tool
  def wepbuster(self):
    """
    DESCR: WEP Cracker + Wordlist Generator. (ext)
    TOOLS: wepbuster
    """

    interface = self.target
    tool_name = 'wepbuster'

    # The interface needs to be setup inside the
    # actual file (/usr/bin/wepbuster)

    channel = self.opts['wifi_channel']
    if channel:
      self._run_tool(tool_name, channel)
    else:
      self._run_tool(tool_name, "")

    # clean up created files during wepbuster run
    self._add_dot_log_postfix('.')

    return


  @tool
  def wirouterkeyrec(self):
    """
    DESCR: Recovers default WPA passphrases of supported router's. (ext)
    TOOLS: wirouterkeyrec
    """

    kb = wifi.KbWifi(self)
    interface = self.target
    tool_name = 'wirouterkeyrec'
    ssids = ",".join(kb.essids())
    self._log(tool_name, f"Found SSIDS: {ssids}")
    self._run_tool(tool_name, f"-s '{ssids}'")

    return


  @tool
  def reaver(self):
    """
    DESCR: WPS brute force attack. (ext)
    TOOLS: reaver
    """

    kb = wifi.KbWifi(self)
    interface = self.target
    tool_name = 'reaver'
    bssid = self.opts['bssid']
    ssid = self.opts['ssid']
    testing = self.opts.get('wifi_testing', None)
    timeout = self.opts['wifi_timeout']

    if len(bssid) == 0 and len(ssid) > 0:
      # ssid is given but we need bssid
      target = kb.targets({'ssid': ssid})
      if len(target['aps']) == 0:
        self._log(tool_name, f"no ap found for given {ssid}")
        return
      bssid = target['aps'].pop().bssid

    if len(bssid) == 0:
      return

    # pixie-dust attack
    self._run_tool(tool_name, f"-i {interface} -b {bssid}" +
      " -c 10 -vvv -K 1 -f --no-nacks", timeout=timeout)

    # normal pin brute
    self._run_tool(tool_name, f"-i {interface} -b {bssid}" +
      " -c 10 -vvv -f --no-nacks", timeout=timeout)

    return


  @tool
  def aircrack(self):
    """
    DESCR: Crack WPA + WEP passphrases. (ext)
    TOOLS: aircrack-ng
    """

    kb = wifi.KbWifi(self)
    interface = self.target
    tool_name = 'aircrack-ng'
    ssid = self.opts['ssid']
    bssid = self.opts['bssid']
    pcaps = self._get_wifi_pcaps()
    pw_list = self.opts['plists'][0]

    if len(ssid) == 0 and len(bssid) > 0:
      # bssid is given but we want ssid
      target = kb.targets({'bssid': bssid})
      if len(target['aps']) == 0:
        self._log(tool_name, f"no ap found for given {bssid}")
        return
      ssid = target['aps'].pop().essid

    if len(ssid) == 0:
      self._log(tool_name, "no ssid given or found")
      return

    for pcap in pcaps:
      self._run_tool(tool_name, f"{pcap} -e {ssid} -w {pw_list}")

    return


  @tool
  def bully(self):
    """
    DESCR: WPS brute force attack with Pixie support. (ext)
    TOOLS: bully
    """

    kb = wifi.KbWifi(self)
    interface = self.target
    tool_name = 'bully'
    force_flush = 'stdbuf -i 0 -o 0 -e 0 '

    bssid = self.opts['bssid']
    ssid = self.opts['ssid']
    channel = self.opts['wifi_channel']

    testing = self.opts.get('wifi_testing', None)
    timeout = self.opts['wifi_timeout']
    raedy_to_run = False

    if len(bssid) > 0 or len(ssid) > 0:
      target = kb.targets({'bssid': bssid, 'ssid': ssid})
      if len(target['aps']) > 0:
        ap = target['aps'].pop()
        ssid = ap.essid
        bssid = ap.bssid
        channel = ap.channel
        ready_to_run = True
    if not ready_to_run:
      self._log(tool_name, "can not find ap for ssid={ssid} bssid={bssid}")
      return

    opts += f" -b {bssid} -c {channel} -v 4 {interface} >> {tool_name}.log"

    def cbkill():
      self._run_cmd(f"pkill --signal=SIGKILL {tool_name}")

    # pixie attack
    self._run_tool(f"{force_flush} {tool_name}", f' -d {opts}', tool_name,
      timeout=timeout,
      cbkill=cbkill
      )
    ## normal pin brute
    #self._run_tool(f"{force_flush} {tool_name}", opts, tool_name,
    #  timeout=timeout,
    #  cbkill=cbkill
    #  )

    return


# EOF
