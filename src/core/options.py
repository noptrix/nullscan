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
# options.py                                                                   #
#                                                                              #
# AUTHOR                                                                       #
# noptrix@nullsecurity.net                                                     #
#                                                                              #
################################################################################


# sys imports
import ast


# own imports
from core.constants import *


class Option:
  """ nullscan options declaration """


  def __init__(self, argv):
    """ init """

    self.argv = argv
    self.declare_options()

    return


  def update_extra_opts(self):
    """ update extra opts (generic, net, wifi, web, etc.) """

    opts = {
      'generic': (
        'user', 'pass', 'ulists', 'plists', 'shodan_key', 'censys_id',
        'censys_sec', 'ipapi_key', 'proxy', 'proxy_user', 'proxy_pass',
        'searchstr', 'resp_size',
      ),
      'net': (
        'shost', 'sport', 'smac', 'dhost', 'dport', 'dmac', 'rhost',
        'rport', 'rmac', 'ndev', 'nmap',
      ),
      'social': (
        'linkedin_user', 'linkedin_pass',
      ),
      'wifi': (
        'ssid', 'bssid', 'wifi_timeout', 'station_mac', 'wifi_channel',
        'wifi_default_tool',
      ),
      'web': (
        'start_url', 'login_url', 'attack_url', 'post_data', 'web_user',
        'web_pass', 'referer', 'cookies', 'ua', 'ua_lists', 'flists',
      ),
    }

    # if an option is not set try to get option from nullscan config file
    for key, val in opts.items():
      for opt in val:
        if opt not in self.opts['targets_opts']:
          if opt == 'nmap':
            self.opts['targets_opts'][opt] = self.copts[opt].split()
          else:
            self.opts['targets_opts'][opt] = self.copts[opt]

    # copy nmap options
    if type(self.opts['targets_opts']['nmap']) != list:
      self.opts['targets_opts']['nmap'] = \
        self.opts['targets_opts']['nmap'].split()
    self.opts['targets']['nmap']['opts'] = self.opts['targets_opts']['nmap']

    # remove nmap log file option if set by user
    logopts = ['-oA', '-oN', '-oX', '-oG']
    for l in logopts:
      if l in self.opts['targets_opts']['nmap']:
        self.opts['targets_opts']['nmap'].remove(l)

    # remove empty strings from lists
    for l in self.opts['targets_opts']:
      if type(self.opts['targets_opts'][l]) == list:
        self.opts['targets_opts'][l] = list(filter(None,
          self.opts['targets_opts'][l]))

    return


  def update_mod_tools_opts(self):
    """ update / merge modules and tools options """

    for i in ('in_modules', 'ex_modules'):
      if not self.opts['modules'][i]:
        self.opts['modules'][i] = self.copts[i]
      #else:
      #  self.opts['modules'][i] = self.opts['modules'][i] + self.copts[i]
      #self.opts['modules'][i] = list(set(self.opts['modules'][i]))

    for i in ('in_tools', 'ex_tools'):
      if not self.opts['tools'][i]:
        self.opts['tools'][i] = self.copts[i]
      else:
        self.opts['tools'][i] = self.opts['tools'][i] + list(self.copts[i])

      # unique list
      self.opts['tools'][i] = list(set(self.opts['tools'][i]))

      # remove new lines
      self.opts['tools'][i] = [x for x in self.opts['tools'][i] if x != '\n']

      # remove empty items
      self.opts['tools'][i] = list(filter(None, self.opts['tools'][i]))

    return


  def update_generic_opts(self):
    """ update generic options """

    opts = ('t_workers', 'm_workers', 'p_workers', 'timeout', 'report',
      'verbose', 'debug')

    # if an option is not set get option from nullscan config file (if defined)
    for opt in opts:
      if opt not in self.opts:
        if opt == 'verbose' or opt == 'debug' or opt == 'report':
          self.opts[opt] = ast.literal_eval(self.copts[opt])
        else:
          self.opts[opt] = self.copts[opt]

    self.opts['t_workers'] = int(self.opts['t_workers'])
    self.opts['m_workers'] = int(self.opts['m_workers'])
    self.opts['p_workers'] = int(self.opts['p_workers'])

    # copy timeout option
    if self.opts['timeout'] == '0.0' or self.opts['timeout'] == '0':
      self.opts['timeout'] = False
    self.opts['targets_opts']['timeout'] = self.opts['timeout']

    return


  def update_opts(self):
    """ delete/merge options from cmdline and config file """

    # just shortening (config opts)
    self.copts = self.opts['config']['opts']

    self.update_generic_opts()
    self.update_mod_tools_opts()
    self.update_extra_opts()

    # we don't need options from config file anymore
    del self.opts['config']

    return


  def declare_options(self):
    """ declare and define several (needed) nullscan options """

    # parent dict containing all options for nullscan
    self.opts = {}

    # cmdline options
    self.opts['cmdline'] = self.argv

    # all targets for all modes
    self.opts['targets'] = {}
    self.opts['targets']['tcp'] = []
    self.opts['targets']['udp'] = []
    self.opts['targets']['nmap'] = {}
    self.opts['targets']['lan'] = []
    self.opts['targets']['wifi'] = []
    self.opts['targets']['web'] = []
    self.opts['targets']['social'] = {}

    # extra options for all modes (-o)
    self.opts['targets_opts'] = {}

    # modules
    self.opts['modules'] = {}

    # include modules (-i)
    self.opts['modules']['in_modules'] = []

    # exclude modules (-x)
    self.opts['modules']['ex_modules'] = []

    # tools
    self.opts['tools'] = {}

    # include tools (-I)
    self.opts['tools']['in_tools'] = []

    # exclude tools (-X)
    self.opts['tools']['ex_tools'] = []

    # workers
    self.opts['t_workers'] = 10
    self.opts['m_workers'] = 10
    self.opts['p_workers'] = 10

    # create and add a new module (-m)
    self.opts['add_module'] = None

    # add new tool (-a)
    self.opts['add_tool'] = None

    # check missing tools
    self.opts['check_tools'] = None

    # print tools (-p)
    self.opts['print_tools'] = None

    # config file and its options
    self.opts['config'] = {}
    self.opts['config']['file'] = NULLSCAN_CONF
    self.opts['config']['opts'] = {}

    # nullscan's default work, log and report dir
    self.opts['nullscan_dir'] = NULLSCAN_DIR

    return


# EOF
