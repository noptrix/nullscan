#!/usr/bin/env python
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
# checks.py                                                                    #
#                                                                              #
# AUTHOR                                                                       #
# noptrix@nullsecurity.net                                                     #
#                                                                              #
################################################################################


# sys imports
import os
import re
import itertools
import importlib


# own imports
from core.constants import *
from core.modules import Module
from core.logger import Logger


class Check:
  """ class to perform checks """


  def __init__(self):
    """ constructor """

    self.logger = Logger()
    self.log = self.logger.log

    return


  def check_deps(self, libs):
    """ check for missing dependencies (third-party libs) """

    missing = []

    try:
      for l in libs:
        splitted = l.split(':')
        check = splitted[0]
        lib = splitted[1]
        importlib.import_module(check)
    except:
      missing.append(lib)

    if missing:
      self.log('pydeps', _type='err', exit=False, end='\n\n')
      for l in missing:
        self.log(f'{l}\n', _type='vmsg')
      os._exit(FAILURE)

    return


  def check_tools(self):
    """ check for missing tools on the system (-C) """

    tools = []
    missing_tools = []
    found_files = []
    suffixes = ('', '.py', '.pl', '.rb', '.php', '.jar', '.sh', '.bin', '.exe')

    # get docstrings
    m = Module(MOD_PATH)
    m.get_docstrings()

    # get paths from PATH to search for tools
    paths = list(filter(None, os.environ.get('PATH').split(':')))
    paths.extend(['/opt', '/usr/share'])

    # search for files in given paths and unique+append them
    for rootdir in paths:
      for root, dirs, files in os.walk(rootdir):
        if 'nmap/scripts/vulscan' in root:
          files.append('vulscan')
        found_files.append(files)
    found_files = list(set(itertools.chain.from_iterable(found_files)))

    # get defined tools list out of doscstrings
    for key in m.docstrings.keys():
      for tool in m.docstrings[key]['tools']:
        if tool not in tools:
          tools.append(tool)

    # message if not found
    for tool in tools:
      for suffix in suffixes:
        if '.' in tool:
          tool = tool.split('.')[0]
        if tool + suffix in found_files:
          break
      else:
        self.log(f'{tool} not found\n', _type='vmsg')
        missing_tools.append(tool)

    # one-liner for parsing
    if len(missing_tools) > 0:
      self.log('\n')
      self.log('One-liner for parsing\n\n', _type='msg')
      self.log(f"    {' '.join(missing_tools)}\n")
    else:
      self.log('All tools are available\n', _type='msg')

    return


  def check_extra_opts(self, opts):
    """ check extra options for wrong specification and values """

    # mac addr: smac, dmac, rmac, bssid
    for mac in (opts['targets_opts']['smac'], opts['targets_opts']['dmac'],
      opts['targets_opts']['rmac'], opts['targets_opts']['bssid']):
      if mac:
        if not re.match("[0-9a-f]{2}([-:])[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$",
          mac.lower()):
            self.log('mac', eargs=mac, _type='err', end='\n')

    return


  def check_generic_opts(self, opts):
    """ check generic options for wrong specification and values """

    # workers
    workers = ('t_workers', 'm_workers', 'p_workers')
    try:
      t_workers = int(opts['t_workers'])
      m_workers = int(opts['m_workers'])
      p_workers = int(opts['p_workers'])
      if opts['t_workers'] > WORKERS_MAX or opts['m_workers'] > WORKERS_MAX \
        or opts['p_workers'] > WORKERS_MAX:
          self.log('workers', _type='warn', end='\n')
    except:
      self.log('workers', _type='err', end='\n')

    # timeout
    try:
      if opts['timeout']:
        timeout = float(opts['timeout'])
    except:
      self.log('timeout', _type='err', end='\n')

    # -i + -x are not allowed at the same time
    if opts['modules']['in_modules'] and opts['modules']['ex_modules']:
      self.log('mod_opts', _type='err', end='\n')
    #if opts['tools']['in_tools'] and opts['tools']['ex_tools']:
    #  self.log('tool_opts', _type='err')

    return


  def check_port(self, port):
    """ check for wrong tcp/udp port specification """

    try:
      if int(port) < PORT_MIN or int(port) > PORT_MAX:
        self.log('port', _type='err', eargs='port', end='\n')
    except:
      self.log('port', _type='err', eargs='port', end='\n')

    return


  def check_target_opts(self, opts):
    """ check for wrong target specifications and values """

    # ports
    for p in ('tcp', 'udp'):
      for i in opts['targets'][p]:
        for port in i['ports']:
          self.check_port(port[0])

    # web
    for url in opts['targets']['web']:
      if not re.search('^http://|^https://', url):
        self.log('wwwurl', _type='err', eargs=url, end='\n')

    # social types
    for o in opts['targets']['social']:
      if o not in ('company', 'mail', 'person', 'domain'):
        self.log('social', _type='err', eargs=o, end='\n')

    return


  def check_opts(self, opts):
    """ check all options for wrong specification and values """

    self.check_target_opts(opts)
    self.check_generic_opts(opts)
    self.check_extra_opts(opts)

    return


  def check_uid(self):
    """ check if user !root and print a warning message """

    if os.geteuid() != 0:
      self.log('r00t', _type='err', end='\n')
    else:
      return 'root'

    return 'user'


  def check_argc(self, argc):
    """ check argument count """

    if argc == 1:
      self.log('help', _type='err', end='\n')

    return


  def check_argv(self, argv):
    """ check if *argv usage is correct """

    # at least one of these options is needed otherwise exit
    needed = ['-t', '-u', '-l', '-o', '-i', '-I', '-x', '-X', '-C', '-p', '-m',
      '-a', '-V', '-H']

    # check if argv has options in needed
    if set(needed).isdisjoint(set(argv)):
      self.log('brain', _type='err', end='\n')

    return


# EOF
