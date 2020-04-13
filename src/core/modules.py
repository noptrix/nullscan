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
# modules.py                                                                   #
#                                                                              #
# AUTHOR                                                                       #
# noptrix@nullsecurity.net                                                     #
#                                                                              #
################################################################################


# sys imports
import os
import importlib
import itertools
import glob
from concurrent.futures import ProcessPoolExecutor


# own imports
from core.constants import *
from core.logger import Logger
from core.file import File


class Module:
  """ module handler class """


  def __init__(self, mod_path):
    """ constructor """

    # logger
    self.logger = Logger()
    self.log = self.logger.log

    # file i/o
    self.file = File()

    # get all modules
    self.mod_path = mod_path
    self.mods = []
    self.get_modules()

    # all loaded module
    self.lmod = {}

    # docstrings for all tools
    self.docstrings = {}

    return


  def get_docstrings(self):
    """ get a list of docstrings from all nullscan tools """

    tools = []    # tools from sub classes

    for mod in self.mods:
      self.load_module(mod)
      cls = next(iter(self.lmod[mod].keys()))
      for tool in self.lmod[mod][cls]:
        modsplit = mod.split('.')
        moddir = modsplit[1]
        module = modsplit[2]
        if 'Base' not in str(cls):
          t_attr = getattr(cls, tool)
        docstr = ' '.join(t_attr.__doc__.split()).split()
        try:
          d_idx = docstr.index('DESCR:')
          t_idx = docstr.index('TOOLS:')
        except:
          pass
        descr = ' '.join((docstr[d_idx + 1:t_idx]))
        tools.append(docstr[t_idx + 1:])
        unique_tools = list(set(itertools.chain.from_iterable(tools)))
        self.docstrings[tool] = {'moddir': moddir, 'module': module,
          'descr': descr, 'tools': unique_tools }

    return


  def get_objects(self, mod, lmod):
    """ get classes and their methods out of a loaded module """

    methods = []

    for d in dir(lmod):
      if d[0].isupper() and 'Base' not in d:
        attr = getattr(lmod, d) # class
        for m in dir(attr): # public methods
          if not m.startswith('_') and not m.startswith('__') and \
            callable(getattr(attr, m)):
              methods.append(m)
        self.lmod = {mod: {attr: list(filter(None, methods))}}

    return


  def get_modules(self):
    """ get all modules out of MOD_PATH directory """

    for f in glob.glob(f'{self.mod_path}/**', recursive=True):
      if '__' not in f and '/libs/' not in f and f.endswith('.py'):
        self.mods.append('.'.join(f.split('/')[-3:]).split('.py')[0])
    #for root, dirs, files in os.walk(self.mod_path, topdown=True):
    #  dirs[:] = [d for d in dirs if d != 'libs']
    #  for f in files:
    #    if f != '__init__.py' and f.endswith('.py'):
    #      mod = '.'.join(os.path.join(root, f).split('/')[-3:])
    #      self.mods.append((mod.replace('.py', '')))
    return


  def filter_modules(self, opts):
    """ filter included or excluded modules """

    # all default modules out of modules/ dir
    def_mods = [
      x.replace('/','.').replace('src.','') + '.default' \
        for x in glob.glob('src/modules/**') if not '__' in x
    ]
    tmp = []

    # add/remove chosen module by user
    if 'in_modules' in opts['modules'] and opts['modules']['in_modules']:
      # list with default modules (force) + user chosed modules to import
      self.mods = def_mods
      for key, val in opts['modules']['in_modules'].items():
        for v in val:
          self.mods.append(f'modules.{key}.{v}')
    elif 'ex_modules' in opts['modules'] and opts['modules']['ex_modules']:
      for key, val in opts['modules']['ex_modules'].items():
        for v in val:
          if v == 'default':
            self.log('mod_default', _type='err', end='\n')
          tmp.append(f'modules.{key}.{v}')
      for i in self.mods:
        if i in tmp:
          self.mods.remove(i)

    return


  def load_module(self, mod):
    """ load desired module and get classes+methods from loaded modules """

    try:
      lmod = importlib.import_module(mod)
      self.get_objects(mod, lmod)
    except Exception as e:
      self.log('mod_import', eargs=f"{mod} -> {e}", _type='err', end='\n')

    return


  def run_module(self, mod, target, opts, wdir):
    """ load and run module with its tools """

    # change temp working dir for tool logs
    rootdir = os.getcwd()
    os.chdir(self.file.make_dir(wdir))

    # load module, get class and create object of
    self.load_module(mod)
    cls = next(iter(self.lmod[mod].keys()))
    c = cls(target, opts['targets_opts'])

    # for status line
    cur_tool = 0
    sum_tool = len(self.lmod[mod][cls])

    # get method (tool) string, create object and run desired tool
    with ProcessPoolExecutor(opts['p_workers']) as exe:
      for t in self.lmod[mod][cls]:
        cur_tool += 1
        if 'host' in target:
          target_head = target['host']
        else:
          target_head = target
        stat_line = f"{target_head} | {'.'.join(mod.split('.')[1:])}.{t}" + \
          f' ({cur_tool}/{sum_tool})' + ' ' * 25
        tool = getattr(c, t)

        # filter in-/ex-cluded tools by user
        if '.default' not in repr(cls):
          if opts['tools']['in_tools']:
            if t not in opts['tools']['in_tools']:
              continue
          if t in opts['tools']['ex_tools']:
            continue

        # run tool
        try:
          if opts['verbose']:
            self.log(stat_line, _type='vmsg', end='\n')
          else:
            self.log(stat_line, _type='vmsg', flush=True, end='\r')
          exe.submit(tool)
        except:
          self.log('tool_failed', eargs=t, _type='err', end='\n')

    # done, move bitch...
    os.chdir(rootdir)

    return


# EOF
