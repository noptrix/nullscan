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
# controller.py                                                                #
#                                                                              #
# AUTHOR                                                                       #
# noptrix@nullsecurity.net                                                     #
#                                                                              #
################################################################################


# sys imports
import sys
import os
import time
import glob
import requests
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor


# own imports
from core.options import Option
from core.parser import Parser
from core.checks import Check
from core.file import File
from core.constants import *
from core.modules import Module
from core.misc import Misc
from core.logger import Logger
from core.nmap import Nmap
from report.html import HTML


class Controller:
  """ program controller class """


  def __init__(self):
    """ constructor """

    # options and modules
    self.opt = None
    self.mod = Module(MOD_PATH)

    # logger
    self.logger = Logger()
    self.log = self.logger.log

    # rest we need
    self.file = File()
    self.check = Check()
    self.misc = Misc()
    self.parser = None

    # nullscan working dir
    self.nullscan_dir = None

    return


  def prepare(self):
    """ preparation/initialization of opts and env: parsing & checks """

    # declare nullscan options
    self.opt = Option(sys.argv)

    # check argc and argc (usage)
    self.check.check_argc(len(sys.argv))
    self.check.check_argv(sys.argv)

    # check for missing libraries / deps / python modules
    self.check.check_deps(self.file.read_file(PYDEPS))

    # parse cmdline and config options, update final options dictionary
    try:
      self.parser = Parser(self.opt.opts)
      self.parser.parse_cmdline()
      self.parser.parse_config()
      self.opt.opts = self.parser.opts
    except:
      self.log('usage', _type='err', end='\n')

    # update final options dictionary
    self.opt.update_opts()

    # further checks for usage, options, env, etc.
    self.check.check_opts(self.opt.opts)

    # collect all py-files and grep the tools out of the py-files
    tools = []
    py_files = self.misc.find_py_files(MOD_PATH)
    for py in py_files:
      tools.append(self.misc.grep_tools(py))
    tools = [x for sublist in tools for x in sublist]

    # create the locks for each tool except for excluded ones
    with ThreadPoolExecutor(50) as exe:
      for tool in tools:
        if tool not in self.opt.opts['tools']['ex_tools']:
          exe.submit(self.file.create_lock, tool)

    # copy debug flag to target_opts (for nullscan tools)
    self.opt.opts['targets_opts']['debug'] = self.opt.opts['debug']

    return


  def run_misc(self):
    """ run chosen misc options """

    if self.opt.opts['check_tools']:
      self.log('Checking for missing tools\n\n', _type='msg')
      self.check.check_tools()
      os._exit(SUCCESS)
    if self.opt.opts['print_tools']:
      self.log('Printing tools and information\n\n', _type='msg')
      self.misc.print_tool(self.opt.opts['print_tools'])
      os._exit(SUCCESS)
    if self.opt.opts['add_module']:
      self.log('Adding new module\n', _type='msg')
      self.misc.add_mod_tool('mod', self.opt.opts['add_module'])
      os._exit(SUCCESS)
    if self.opt.opts['add_tool']:
      self.log('Adding new tool\n', _type='msg')
      self.misc.add_mod_tool('tool', self.opt.opts['add_tool'])
      os._exit(SUCCESS)

    return


  def prepare_modules(self):
    """ filter in-/excluded mods + return a unique list """

    self.mod.filter_modules(self.opt.opts)
    self.mod.mods = list(set(self.mod.mods))

    return


  def run_nmap_mode(self):
    """ run nmap scan mode """

    nmap = Nmap(self.opt.opts['targets']['nmap'])

    # create nmap logdir based on scan type requested
    logpath = f'{self.nullscan_dir}/logs/nmap/{nmap.get_protocol()}'
    logfile = f'{logpath}/results'
    self.file.make_dir(logpath)
    nmap.set_logfile(logfile)

    # build nmap command line
    nmap.build_cmd()

    # start scans
    self.log('NMAP mode activated\n', _type='msg', color='blue')
    self.log('Targets added: {}\n'.format(len(
      self.opt.opts['targets']['nmap']['hosts'])), _type='msg')
    if self.opt.opts['verbose']:
      self.log('\n')
      for target in self.opt.opts['targets']['nmap']['hosts']:
        self.log(f'{target}\n', _type='msg')
    nmap.scan(debug=self.opt.opts['debug'])

    return f'{logfile}.xml'


  def run_social_mode(self, target):
    """ run social mode """

    if '.social.' in str(self.mod.mods):
      # availabel social modules to import and load
      mods = [i for i in self.mod.mods if '.social.' in i]

      with ProcessPoolExecutor(self.opt.opts['m_workers']) as exe:
        for key in target.keys():
          if target[key]:
            for t in target[key]:
              # default module
              rdir = f'{self.nullscan_dir}/logs/targets/'
              wdir = f"{rdir}{t}/social/{key}/default"
              exe.submit(self.mod.run_module, 'modules.social.default', t,
                self.opt.opts, wdir)

              # non-default modules
              for m in mods:
                if 'default' not in m:
                  splitted = m.split('.')
                  moddir = splitted[1]
                  modname = splitted[2]
                  wdir = f"{rdir}{t}/{moddir}/{key}/{modname}"
                  exe.submit(self.mod.run_module, m, t, self.opt.opts, wdir)

    return


  def run_wifi_mode(self, target):
    """ run wifi mode """

    if '.wifi.' in str(self.mod.mods):
      # available wifi modules to import and load
      mods = [i for i in self.mod.mods if '.wifi.' in i]

      # default module first
      rdir = f'{self.nullscan_dir}/logs/targets/'
      wdir = f'{rdir}{target}/wifi/default'
      self.mod.run_module('modules.wifi.default', target, self.opt.opts, wdir)

      # non-default modules
      with ProcessPoolExecutor(self.opt.opts['m_workers']) as exe:
        for m in mods:
          if 'default' not in m:
            splitted = m.split('.')
            moddir = splitted[1]
            modname = splitted[2]
            wdir = f'{rdir}{target}/{moddir}/{modname}'
            exe.submit(self.mod.run_module, m, target, self.opt.opts, wdir)

    return


  def run_lan_mode(self, target):
    """ run lan mode """

    if '.lan.' in str(self.mod.mods):
      # available lan modules to import and load
      mods = [i for i in self.mod.mods if '.lan.' in i]

      # default module first
      rdir = f'{self.nullscan_dir}/logs/targets/'
      wdir = f'{rdir}{target}/lan/default'
      self.mod.run_module('modules.lan.default', target, self.opt.opts, wdir)

      # non-default modules
      with ProcessPoolExecutor(self.opt.opts['m_workers']) as exe:
        for m in mods:
          if 'default' not in m:
            splitted = m.split('.')
            moddir = splitted[1]
            modname = splitted[2]
            wdir = f'{rdir}{target}/{moddir}/{modname}'
            exe.submit(self.mod.run_module, m, target, self.opt.opts, wdir)

    return


  def run_web_mode(self, target):
    """ run web mode """

    if '.web.' in str(self.mod.mods):
      # available web modules to import and load
      mods = [i for i in self.mod.mods if '.web.' in i]

      # we need host name for working directory
      host = requests.utils.urlparse(target).netloc

      # default module first
      rdir = f'{self.nullscan_dir}/logs/targets/'
      wdir = f'{rdir}{host}/web/default'
      self.mod.run_module('modules.web.default', target, self.opt.opts, wdir)

      # non-default modules
      with ProcessPoolExecutor(self.opt.opts['m_workers']) as exe:
        for m in mods:
          if 'default' not in m:
            splitted = m.split('.')
            moddir = splitted[1]
            modname = splitted[2]
            wdir = f'{rdir}{host}/{moddir}/{modname}'
            exe.submit(self.mod.run_module, m, target, self.opt.opts, wdir)

    return


  def run_udp_mode(self, target):
    """ run udp mode """

    # we need to run host modules before tcp and we need to run default
    # tool first
    self.run_host_mode(target)

    # now tcp modules
    if '.udp.' in str(self.mod.mods):
      with ProcessPoolExecutor(self.opt.opts['m_workers']) as exe:
        for p in target['ports']:
          exe.submit(self.run_tcp_udp_mode, target, p, 'udp')

    return


  def run_tcp_mode(self, target):
    """ run tcp mode """

    # we need to run host modules before tcp and we need to run default
    # module first
    self.run_host_mode(target)

    # now tcp modules
    if '.tcp.' in str(self.mod.mods):
      with ProcessPoolExecutor(self.opt.opts['m_workers']) as exe:
        for p in target['ports']:
          exe.submit(self.run_tcp_udp_mode, target, p, 'tcp')

    return


  def run_tcp_udp_mode(self, host, port, proto):
    """ wrapper for tcp/udp mode """

    # available modules
    mod = f'modules.{proto}.{port[1]}'

    # force default module for given port if module does not exist
    if mod not in self.mod.mods:
      mod = f'modules.{proto}.default'

    # new target dict as we only need the corresponding port
    t = {'host': host['host'], 'port': port[0]}

    # default module first
    rdir = f'{self.nullscan_dir}/logs/targets/'
    wdir = f"{rdir}{t['host']}/{proto}/{port[0]}/default"
    self.mod.run_module(f'modules.{proto}.default', t, self.opt.opts, wdir)

    # now non-default module
    if '.default' not in mod:
      wdir = f"{rdir}{t['host']}/{proto}/{port[0]}/{port[1]}"
      self.mod.run_module(mod, t, self.opt.opts, wdir)

    return


  def run_host_mode(self, target):
    """ run host mode """

    # available host modules to import and load
    mods = [i for i in self.mod.mods if '.host.' in i]

    # default module
    rdir = f'{self.nullscan_dir}/logs/targets/'
    wdir = f"{rdir}{target['host']}/host/default"
    self.mod.run_module('modules.host.default', target, self.opt.opts, wdir)

    # non-default modules
    with ProcessPoolExecutor(self.opt.opts['m_workers']) as exe:
      for m in mods:
        if 'default' not in m:
          splitted = m.split('.')
          moddir = splitted[1]
          modname = splitted[2]
          wdir = f"{rdir}{target['host']}/{moddir}/{modname}"
          exe.submit(self.mod.run_module, m, target, self.opt.opts, wdir)

    return


  def run_modes(self):
    """ run chosen modes """

    scans = []
    modes = {
      'tcp': self.run_tcp_mode, 'udp': self.run_udp_mode,
      'wifi': self.run_wifi_mode, 'web': self.run_web_mode,
      'social': self.run_social_mode, 'http': self.run_web_mode,
      'https': self.run_web_mode,
    }

    # run lan mode first if requested
    if self.opt.opts['targets']['lan']:
      ifaces = []
      self.log('LAN mode activated\n', color='blue', _type='msg')
      self.log(f"Targets added: {len(self.opt.opts['targets']['lan'])}\n\n",
        _type='msg')
      for iface in self.opt.opts['targets']['lan']:
        if self.opt.opts['verbose']:
          self.log(f'{iface}\n', _type='vmsg')
        ifaces.append((self.run_lan_mode, iface))
      if self.opt.opts['verbose']:
        self.log('\n')
      with ProcessPoolExecutor(self.opt.opts['t_workers']) as exe:
        self.log('Shooting tools\n\n', color='green', _type='msg')
        for iface in ifaces:
          exe.submit(iface[0], iface[1])
      self.log('\n')
      if not self.opt.opts['verbose']:
        self.log('\n')
      self.log('Tools done\n\n', color='green', _type='msg')
      for log in glob.glob('**/lan/portscan/*.xml', recursive=True):
        if log:
          self.parser.parse_nmap_logfile(log, lan=True)

    # collect scan modes for each target
    for k, v in self.opt.opts['targets'].items():
      if self.opt.opts['targets'][k]:
        if k == 'lan':
          continue
        else:
          self.log(f'{k.upper()} mode activated\n', color='blue', _type='msg')
        self.log(f'Targets added: {len(v)}\n\n', _type='msg')
        if k == 'social':
          if self.opt.opts['verbose']:
            for targets in v.values():
              for target in targets:
                self.log(f'{target}\n', _type='vmsg')
            self.log('\n')
          scans.append((modes[k], v))
        else:
          for target in v:
            scans.append((modes[k], target))
            if self.opt.opts['verbose']:
              if 'host' in target:
                target_head = target['host']
              else:
                target_head = target
              self.log(f'{target_head}\n', _type='vmsg')
          if self.opt.opts['verbose']:
            self.log('\n')

    # start mode for each target
    with ProcessPoolExecutor(self.opt.opts['t_workers']) as exe:
      if scans:
        self.log('Shooting tools\n\n', color='green', _type='msg')
        for scan in scans:
          exe.submit(scan[0], scan[1])
    if scans:
      self.log('\n')
      if not self.opt.opts['verbose']:
        self.log('\n')
      self.log('Tools done\n\n', _type='msg', color='green')

    return


  def start(self):
    """ nullscan starts here with actions """

    self.check.check_uid()
    self.log('Game Started\n\n', _type='msg')

    # create nullscan working, targets and log dir
    self.nullscan_dir = self.file.make_dir(self.opt.opts['nullscan_dir'],
      incr=True)
    self.file.make_dir(f'{self.nullscan_dir}/logs/targets')
    self.opt.opts['targets_opts']['nullscan_logdir'] = \
      f'{self.nullscan_dir}/logs/targets/'

    # run nmap mode first if requested
    if 'hosts' in self.opt.opts['targets']['nmap']:
      self.parser.parse_nmap_logfile(self.run_nmap_mode())
      self.log('\n')

    # delete nmap key
    del self.opt.opts['targets']['nmap']

    # prepare modules for other modes
    self.prepare_modules()

    # run the nullscan modes now
    self.run_modes()

    return


  def end(self):
    """ program ends here. clean-ups, reporting, etc. """

    # go back to root dir
    os.chdir(ROOT_PATH)

    # clean up empty directories and empty (log-)files or logfiles containing
    # a singl ebyte (newline) (failed tools)
    self.misc.remove_empty_files_dirs(f'{self.nullscan_dir}/logs/targets/')

    # just to be safe - delete all locks, in case tools didn't
    self.file.del_file('/tmp/nullscan', _dir=True)

    # create report
    if self.opt.opts['report']:
      self.log('Creating report\n', _type='msg')
      tmpl_dir = f'{ROOT_PATH}/src/report/template'
      rep_dir = f'{self.nullscan_dir}/report'
      logs_dir = f'{self.nullscan_dir}/logs'
      self.report = HTML(TODAY, self.opt.opts, tmpl_dir, rep_dir, logs_dir)
      self.report.make_report()
      self.log('Report done\n\n', _type='msg')
    self.log('Game Over\n', _type='msg')

    # reset terminal to original state. sometimes fuck up occurs because of
    # color and other escape codes.
    self.misc.reset_terminal()

    return


# EOF
