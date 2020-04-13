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
import sys
import os
import re
import getopt             # don't tell me 'argparse' ...
from libnmap.parser import NmapParser
from configparser import ConfigParser
import ipaddress


# own imports
from core.logger import Logger
from core.usage import Usage
from core.constants import *
from core.file import File
from core.misc import Misc


class Parser:
  """ class for parsing cmdline and config file from nullscan """


  def __init__(self, opts):
    """ constructor"""

    self.opts = opts            # all nullscan options
    self.logger = Logger()
    self.log = self.logger.log
    self.file = File()
    self.misc = Misc()

    # tmp stupid fix to strip bad chars out of options
    self.bad_chars = '<>()[]{}:;.,="\'*&^%$#@!+-_/?°²³´`'

    return


  def parse_config(self):
    """ parse nullscan config file and get options+values as dictionary+list. """

    try:
      cfg = ConfigParser()
      data = cfg.read(self.opts['config']['file'])
      if not data:
        raise Exception
      for s in cfg.sections():
        for o in cfg.options(s):
          values = cfg.get(s, o).replace('$NULLSCAN_DIR/', ROOT_PATH)
          if ',' in values and o != 'nmap':
            self.opts['config']['opts'][o] = values.split(',')
          else:
            self.opts['config']['opts'][o] = values
    except:
      self.log('config', eargs=f"{self.opts['config']['file']}", _type='err',
        end='\n')

    return


  def parse_add_module_tool(self, args, dest):
    """ parse add module/tool option (-m/-a) """

    s = args.split()

    try:
      m = s[0].split('/')
      d = {'moddir': m[0], 'modname': m[1], 'func': s[1], 'tool': s[2],
        'args': s[3:]}
    except:
      self.log('add_mod_tool', _type='err', end='\n')

    self.opts[dest] = d

    return


  def parse_print_tools(self, args):
    """ parse print tools option (-p) """

    dicted = {}
    splitted = list(filter(None, args.split(';')))

    for item in splitted:
      if item == 'all':
        dicted['all'] = True
        break
      if '=' in item:
        i = item.split('=')
        for j in i:
          if ',' in j:
            dicted[i[0]] = j.split(',')
          else:
            dicted[i[0]] = [j]
      else:
        dicted[item] = []

    self.opts['print_tools'] = dicted

    return


  def parse_tools(self, args, dest):
    """ parse tools include/exclude option (-I/-X) """

    self.opts['tools'][dest] = args.split(',')

    return


  def parse_modules(self, args, dest):
    """ parse modules include/exclude options (-i/-x) """

    # remove empty ones, if ';' was used at the end without further opts
    if ';' in args:
      mods = [x.strip(self.bad_chars) for x in args.split(';') if x]
    elif '=' in args:
      mods = args.split()
    else:
      self.log('inexmods', _type='err', end='\n')

    # create dict out of list itmes
    dicted = dict(d.split('=') for d in mods)

    for key, val in dicted.items():
      if ',' in val:
        dicted[key] = val.split(',')
      else:
        dicted[key] = [val]

    self.opts['modules'][dest] = dicted

    return


  def parse_extra_opts(self, args):
    """ parse extra options option (-o) """

    # remove empty ones, if ';' was used at the end without further opts
    if ';' in args:
      args = [x.strip(self.bad_chars) for x in args.split(';') if x]
    else:
      args = [args]

    # create dict out of list items except for nmap
    dicted = dict(d.split('=') for d in args)
    for key in dicted.keys():
      if ',' in dicted[key] and key != 'nmap':
        dicted[key] = dicted[key].split(',')

    self.opts['targets_opts'] = dicted

    return


  def parse_nmap_targets(self, targets):
    """ parse nmap targets to scan from either ranges or from file (-t) """

    hosts = []

    if os.path.isfile(targets):
      hosts = self.file.read_file(targets)
    else:
      try:
        # host range format
        if '-' in targets:
          splitted = targets.split('-')
          try:
            start = ipaddress.IPv4Address(splitted[0])
            end = ipaddress.IPv4Address(splitted[1])
            for i in range(int(start), int(end) + 1):
              ipaddr = str(ipaddress.IPv4Address(i))
              hosts.append(ipaddr)
          except:
            # must be a hostname/domain then
            if ',' in targets:
              hosts = targets.split(',')
            else:
              hosts.append(targets)
        # cidr range format
        elif '/' in targets:
          for ipaddr in ipaddress.IPv4Network(targets).hosts():
            hosts.append(str(ipaddr))
        # multiple single hosts
        elif ',' in targets:
          hosts = targets.split(',')
        # single host
        else:
          hosts.append(targets)
      except Exception as e:
        self.log('hostrange', eargs=repr(e.args[0]), _type='err', end='\n')

    if hosts:
      self.opts['targets']['nmap']['hosts'] = hosts

    return


  def parse_nmap_logfile(self, logfile, privip=False):
    """ parse hosts and ports from nmap xml logfile (-l) """

    nmap = NmapParser()

    try:
      parsed = nmap.parse_fromfile(logfile)
    except:
      self.log('nmap', eargs=f'{logfile}', _type='err', end='\n')
    else:
      for host in parsed.hosts:
        if len(host.hostnames) >= 1:
          _host = host.hostnames[0] # better work with hostname
        else:
          _host = host.address
          try:
            if ipaddress.ip_address(_host).is_private:
              privip = True
          except:
            pass # hostname
        ports = []
        res = host.get_open_ports()
        if res:
          for port, proto in res:
            tmp = str(host.get_service(port)).translate(str.maketrans('', '',
              ':[])')).split()
            service = self.misc.lookup_port_service(str(port), proto)
            ports.append([str(port), service])
          self.opts['targets'][proto].append({'host': _host, 'ports': ports,
            'privip': privip})
        else:
          # host up but no ports found
          self.opts['targets']['tcp'].append({'host': _host, 'ports': [],
            'privip': privip})

    return


  def parse_targets(self, args, privip=False):
    """ parse all targets from line specified via URIs (-u) """

    targets = []

    # remove empty ones, if ';' was used at the end without further targets
    if ';' in args:
      targets = [x.strip() for x in args.split(';') if x]
    elif 'person://' in args or 'company://' in args:
      targets.append(args)
    else:
      targets = args.split()

    for t in targets:
      if re.search('^tcp://|^udp://', t):
        ports = []
        part = t.split('://')
        proto = part[0].strip(self.bad_chars)
        self.opts['targets_opts']['target_type'] = proto
        host = part[1].split(':')[0].strip(self.bad_chars)
        try:
          if ipaddress.ip_address(host).is_private:
            privip = True
        except:
          pass # hostname
        if ':' in part[1]:
          tmp_ports = part[1].split(':')[1]
          tmp_ports = tmp_ports.split(',')
          for p in tmp_ports:
            if '=' in p:
              ports.append(p.split('='))
            else:
              service = self.misc.lookup_port_service(p)
              if service:
                p = f'{p}={service}'
              else:
                # assign default service if not given
                p = f'{p}=default'
              ports.append(p.split('='))
        self.opts['targets'][proto].append({'host': host, 'ports': ports,
          'privip': privip})
      elif re.search('^http://|^https://', t):
        self.opts['targets_opts']['target_type'] = t.split(':')[0]
        self.opts['targets']['web'] = t.split(',')
        # add leading '/' to url if not given
        #for u in t.split(','):
        #  if not u.endswith('/'):
        #    u = f'{u}/'
        #  self.opts['targets']['web'].append(u)
      elif re.search('\
        ^mail://|^person://|^company://|^domain://|^lan://|^wifi://', t):
        self.opts['targets_opts']['target_type'] = t.split(':')[0]
        line = list(filter(None, [l.replace('://', ':') for l in t.split(';')]))
        line = dict(l.split(':') for l in line)
        for k in line.keys():
          if k == 'mail' or k == 'person' or k == 'company' or k == 'domain':
            self.opts['targets']['social'][k] = line[k].split(',')
          else:
            self.opts['targets'][k] = line[k].split(',')
      else:
        unknown_mode = t.split('://')[0]
        self.log('mode', eargs=unknown_mode, _type='err', end='\n')

    return


  def parse_cmdline(self):
    """ parse command line """

    try:
      opts, args = getopt.getopt(self.opts['cmdline'][1:],
        't:u:l:o:i:I:x:X:T:M:P:k:rR:c:vdCp:m:a:VH')
    except getopt.GetoptError as err:
      self.log('default', eargs=repr(err), _type='err', end='\n')

    for o, a in opts:
      if o == '-t':
        if a == '?':
          Usage.nmap_mode_usage()
          os._exit(SUCCESS)
        else:
          self.parse_nmap_targets(a)
      elif o == '-u':
        if a == '?':
          Usage.host_mode_usage()
          os._exit(SUCCESS)
        else:
          self.parse_targets(a)
      elif o == '-l':
        self.parse_nmap_logfile(a)
      elif o == '-o':
        if a == '?':
          Usage.extra_opts_usage()
          os._exit(SUCCESS)
        else:
          self.parse_extra_opts(a)
      elif o == '-i':
        if a == '?':
          Usage.modules_usage()
          os._exit(SUCCESS)
        else:
          self.parse_modules(a, 'in_modules')
      elif o == '-I':
        if a == '?':
          Usage.tools_usage()
          os._exit(SUCCESS)
        else:
          self.parse_tools(a, 'in_tools')
      elif o == '-x':
        if a == '?':
          Usage.modules_usage()
          os._exit(SUCCESS)
        else:
          self.parse_modules(a, 'ex_modules')
      elif o == '-X':
        if a == '?':
          Usage.tools_usage()
          os._exit(SUCCESS)
        else:
          self.parse_tools(a, 'ex_tools')
      elif o == '-T':
        self.opts['t_workers'] = a
      elif o == '-M':
        self.opts['m_workers'] = a
      elif o == '-P':
        self.opts['p_workers'] = a
      elif o == '-k':
        self.opts['timeout'] = a
      elif o == '-r':
          self.opts['report'] = True
      elif o == '-R':
        self.opts['nullscan_dir'] = a + '-' + TODAY
      elif o == '-c':
        self.opts['config']['file'] = a
      elif o == '-v':
        self.opts['verbose'] = True
      elif o == '-d':
        self.opts['debug'] = True
      elif o == '-C':
        self.opts['check_tools'] = True
      elif o == '-p':
        if a == '?':
          Usage.print_tools_usage()
          os._exit(SUCCESS)
        else:
          self.parse_print_tools(a)
      elif o == '-m':
        if a == '?':
          Usage.add_module_usage()
          os._exit(SUCCESS)
        else:
          self.parse_add_module_tool(a, 'add_module')
      elif o == '-a':
        if a == '?':
          Usage.add_tool_usage()
          os._exit(SUCCESS)
        else:
          self.parse_add_module_tool(a, 'add_tool')
      elif o == '-V':
        self.log(VERSION, _type='msg', end='\n')
        os._exit(SUCCESS)
      elif o == '-H':
        Usage.usage()
        os._exit(SUCCESS)
      else:
        self.log('cmdopt', eargs=o, _type='err', end='\n')

    return


# EOF
