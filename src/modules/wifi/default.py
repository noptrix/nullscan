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
# default.py                                                                   #
#                                                                              #
# AUTHOR                                                                       #
# noptrix@nullsecurity.net                                                     #
#                                                                              #
################################################################################


# sys imports
import os


# own imports
from modules.libs.base import Base, tool, timeout


class Default(Base):
  """ Default module (WiFi) """


  def __init__(self, target, opts):
    """ init """

    Base.__init__(self, target, opts)

    self._check_iputils()
    self.uname = self._get_uname()[0]

    return


  def __will_run(self, tool_name):
    """
    There should only be one tool for initial data collection on wifi
    because multiple tools will interfere with each other e. g. during
    channel hopping. Therefore, there is the wifi_defaul_tool option
    that determine what tool should be used for initial data collection.

    Note: Currently the best tool of initial data collection is
          airodump-ng. It is also currently the only tool that can feed
          the nullscan wifi knowledge base interface with inital information.
          New wifi_default_tool needs to implement support in:
          * src/modules/libs/wifi.py
          Use the airodump-ng parser as example.
    """

    return self.opts['wifi_default_tool'] == tool_name


  @tool
  def airodump(self):
    """
    DESCR: Collect and store WiFi data with airodump. (ext)
    TOOLS: airodump-ng
    """

    interface = self.target
    tool_name = 'airodump-ng'
    opts = f"-w {tool_name}"
    opts += ' --output-format pcap,csv,gps,kismet,netxml,logcsv'
    opts += ' --manufacturer --uptime --wps '
    opts += interface

    if not self.__will_run(tool_name):
        return

    def cbkill():
      self._run_cmd(f"pkill --signal SIGINT {tool_name}")

    self._run_tool(tool_name,
      opts,
      'airodump',
      timeout=self.opts['wifi_timeout'],
      cbkill=cbkill,
      create_log=False)

    # fix log file names by appending .log
    self._add_dot_log_postfix('.')

    return


  @tool
  def kismet(self):
    """
    DESCR: Collect and store WiFi data with kismet. (ext)
    TOOLS: kismet
    """

    interface = self.target
    tool_name = 'kismet'

    opts = [' --log-types=kismet,pcapng']
    opts += ['--silent', '--no-line-wrap']
    opts += ['--no-console-wrapper', '--no-ncurses-wrapper']
    opts += ['-c ', interface]

    if not self.__will_run(tool_name):
        return

    def kill_callback():
      self._run_cmd(f"pkill --signal SIGKILL {tool_name}")

    self._run_tool(tool_name, ' '.join(opts),
      timeout=self.opts['wifi_timeout'],
      cbkill=kill_callback)

    # fix log file names by appending .log
    self._add_dot_log_postfix('.')

    return


  @tool
  def probequest(self):
    """
    DESCR: Sniff Prope Requests from Stations. (ext)
    TOOLS: probequest
    """

    interface = self.target
    tool_name = 'probequest'

    if not self.__will_run(tool_name):
        return

    opts = [' -i', interface]
    opts += ['--debug']
    opts += ['-o', f"{tool_name}.csv.log"]
    if len(self.opts['ssid']) > 0:
      opts += ['-e', self.opts['ssid']]

    self._run_tool(tool_name, ' '.join(opts) +
      f" > {tool_name}.stdout.log",
      timeout=self.opts['wifi_timeout'])

    return


  @tool
  def wash(self):
    """
    DESCR: Scans for WPS APs. (ext)
    TOOLS: wash
    """

    interface = self.target
    tool_name = 'wash'
    opts = ' -i ' + interface

    if not self.__will_run(tool_name):
        return

    self._run_tool(tool_name, opts, timeout=self.opts['wifi_timeout'])

    return


  @tool
  def trackerjacker(self):
    """
    DESCR: Maps and tracks wifi networks and deivces through 802.11 monitoring.
           (ext)
    TOOLS: trackerjacker
    """

    interface = self.target
    tool_name = 'trackerjacker'

    opts = [' -i', interface]
    opts += ['--map', '--map-file', f'{tool_name}.log']
    opts += ['--log-level', 'DEBUG']

    if not self.__will_run(tool_name):
        return

    if len(self.opts['bssid']) > 0:
      opts += ['--access-points', self.opts['bssid']]
    if len(self.opts['wifi_channel']) > 0:
      opts += ['--channels-to-monitor', self.opts['wifi_channel']]

    self._run_tool(tool_name, ' '.join(opts),
      timeout=self.opts['wifi_timeout'])

    return


  # Temp. disabled because of Zombie Process
  #@tool
  #def hoover(self):
  #  """
  #  DESCR: WiFi probe request sniffer. (ext)
  #  TOOLS: hoover
  #  """
  #  interface = self.target
  #  tool_name = 'hoover'
  #  def cbkill():
  #    pass
  #    #self._run_cmd(f'pkill --signal SIGKILL ".*{tool_name}.*"')

  #  self._run_tool(tool_name, f"--interface={interface}",
  #    timeout=self.opts['wifi_timeout'], cbkill=cbkill)

  #  return


  @tool
  def zizzania(self):
    """
    DESCR: Dumping WPA Handshakes. (ext)
    TOOLS: zizzania
    """

    interface = self.target
    tool_name = 'zizzania'

    if not self.__will_run(tool_name):
        return

    self._run_tool(tool_name, f"-i {interface} -w {tool_name}.pcap.log" +
      " -a 5 -d 4 -v",
      timeout=self.opts['wifi_timeout']
      )

    return


  @tool
  def hcxdumptool(self):
    """
    DESCR: Small tool to capture packets from wlan devices. (ext)
    TOOLS: hcxdumptool
    """

    interface = self.target
    tool_name = 'hcxdumptool'
    lf_base = tool_name

    if not self.__will_run(tool_name):
        return

    self._run_tool(tool_name, f"-i {interface}" +
      f" -o {lf_base}.eapol.pcap.log" +
      f" -O {lf_base}.ip.pcap.log" +
      f" -W {lf_base}.wep.pcap.log",
      timeout=self.opts['wifi_timeout']
      )

    return


  @tool
  def bettercap_wifi_recon(self):
    """
    DESCR: The Swiss Army knife for 802.11, BLE and Ethernet networks
           reconnaissance and MITM attacks. (ext)
    TOOLS: bettercap
    """

    # Example on how to run bettercap in nullscan without interaction

    interface = self.target
    tool_name = 'bettercap'
    timeout = int(float(self.opts['wifi_timeout']))-2

    if not self.__will_run(tool_name):
        return

    bettercap_script =  'wifi.recon on;'+\
                       f'set ticker.period {timeout};'+\
                        'set ticker.commands '+\
                          '\\"ticker off;quit\\"; ticker on'
    opts = f'-iface {interface} -no-colors -eval "{bettercap_script}"'
    self._run_tool(tool_name, opts,
      timeout=self.opts['wifi_timeout'],
      logfile=tool_name+'_wifi_recon'
      )

    return


  #@tool
  #def wireless_ids(self):
  #  """
  #  DESCR: IDS for Wireless Networks. (ext)
  #  TOOLS: wireless-ids
  #  """

  # !!! Disabled for now                                                 !!!
  # !!! --> this tool some how manages to mess up the wifi interface     !!!

  #  interface = self.target
  #  tool_name = 'wireless-ids'

  #  def kill_callback():
  #    import re
  #    out = self._run_cmd("ps aux | grep wids.py | grep -v 'grep'")
  #    pid = re.sub(r'\s+', ' ', "\n".join(out)).split(' ')[1]
  #    self._run_cmd(f"kill {pid}")

  #  self._run_cmd(tool_name + f" -i {interface}", tool_name,
  #    timeout=self.opts['wifi_timeout'], cbkill=kill_callback)

  #  return


# EOF
