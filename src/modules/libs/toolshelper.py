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
# toolshelper.py                                                               #
#                                                                              #
# AUTHOR                                                                       #
# noptrix@nullsecurity.net                                                     #
#                                                                              #
################################################################################


# sys imports
import os
import ipaddress
import requests
import concurrent.futures as cf
from collections import deque
import glob


# own imports
from modules.libs.helper import Helper


class ToolsHelper():
  """ tools helper class """


  def __init__(self):
    """ init """

    return


  def _is_tomcat(self, host, port, scheme='http'):
    """ check if web-server is tomcat """

    futures = deque()
    links = deque((
      '/html', '/manager/html', '/host-manager/html', '/admin/html',
      '/administration/html'
    ))
    threads = len(links)
    s = requests.session()

    with cf.ThreadPoolExecutor(threads) as exe:
      for l in links:
        url = f'{scheme}://{host}:{port}{l}'
        try:
          futures.append(exe.submit(s.get, url, timeout=5, verify=False))
        except:
          pass
      for f in cf.as_completed(futures):
        if 'manager-gui' in f.result().text or '="s3cret"' in f.result().text:
          return f.result().url

    return None


  def _get_ipv4addr(self, host):
    """ wrapper to get ipv4 address out of given target host or logfile """

    if self._is_ipaddr(host) != 'ipv4':
      host = self._read_log('ipv4addr')[0]
    else:
      host = self.target['host']

    return host


  def _is_ipaddr(self, host):
    """ check if given target is ip address and return protocol version """

    try:
      addr = ipaddress.ip_address(host)
      ver = repr(addr.version)
      if ver == '4':
        return 'ipv4'
      elif ver == '6':
        return 'ipv6'
      else:
        return False
    except:
      return False

    return True


  def _check_iputils(self):
    """ check if ip utils is installed """

    res = '\n'.join(self._run_cmd('ip'))

    if 'Usage:' in res:
      self.iputils = True
    else:
      self.iputils = False

    return


  def _add_dot_log_postfix(self, cwd):
    """ will run over all files in cwd and append .log if needed """

    bin_file_ext = set(['.bin', '.cap', '.pcap', '.sqlite'])

    for el in os.listdir(cwd):
      try:
        el = os.path.join(cwd, el)
        if os.path.isfile(el) and el.split('.')[-1] != 'log':
          # found file with no .log postfix
          bin_tag = ''
          for bin_ext in bin_file_ext:
            if bin_ext in el:
              bin_tag = '.bin'
              break
          new_name = f'{el}{bin_tag}.log'
          os.rename(el, new_name)
      except OSError as e:
        self._log('error', str(e))
        # Suppress exception due to race condition when multiple process try to
        # rename the same file. Global lock is needed to really fix this.
        pass

    return


  def _get_wifi_pcaps(self):
    """ returns all collected pcap files from wifi/**/* """

    pcap_files = []
    pcap_exts = set(['.cap', '.pcap', '.pcapng'])
    wifi_root = f"{self.opts['nullscan_logdir']}{self._target}/wifi/"

    for el in glob.iglob(wifi_root + '**/*', recursive=True):
      for pcap_ext in pcap_exts:
        if pcap_ext in el:
          pcap_files.append(el)
          break

    return pcap_files


  def _get_all_found_essids(self):
    """ parses essids from airodump csv log """

    entries = self._parse_airodump_csv()

    return [e['essid'] for e in entries if len(e.get('essid', '')) > 0]


  def _get_all_found_bssids(self):
    """ parses bssids from airodump csv log """

    entries = self._parse_airodump_csv()

    return [e['bssid'] for e in entries if len(e.get('essid', '')) > 0]


# EOF
