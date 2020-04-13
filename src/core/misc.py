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
# misc.py                                                                      #
#                                                                              #
# AUTHOR                                                                       #
# noptrix@nullsecurity.net                                                     #
#                                                                              #
################################################################################


# sys imports
import shutil
import glob
import subprocess
import termios
import sys
from concurrent.futures import ThreadPoolExecutor


# own imports
from core.constants import *
from core.file import File
from core.modules import Module
from core.logger import Logger


class Misc:
  """ class for miscellaneous stuff """


  def __init__(self):
    """ constructor """

    # logger
    self.logger = Logger()
    self.log = self.logger.log

    # file i/o
    self.file = File()

    # original terminal state
    self.term_fd = sys.stdin.fileno()
    self.term_state = termios.tcgetattr(self.term_fd)

    return


  def reset_terminal(self):
    """ reset terminal to original state """

    termios.tcsetattr(self.term_fd, termios.TCSADRAIN, self.term_state)

    return


  def grep_tools(self, py_file):
    """ Find all tools (method names) of given file """

    tools = []

    lines = self.file.read_file(py_file)
    for line in lines:
      if 'def ' in line:
        method = line.split()[1].split('(')[0]
        if not method.startswith('_'):
          tools.append(method)

    return sorted(list(set(tools)))


  def find_py_files(self, root_path):
    """ Find all py files with some exceptions of given root_path """

    py_files = []

    files = glob.glob(f'{root_path}/*/*.py', recursive=True)
    [py_files.append(x) for x in files if '__ini' not in x and '/libs' not in x]

    return sorted(list(set(py_files)))


  def kill_process(self, pattern, signal='TERM'):
    """ kill (all) processes matched by pattern """

    cmd = ['pkill', f'-{signal}', '-f', pattern]
    subprocess.run(cmd)

    return


  def remove_empty_files_dirs(self, rootpath):
    """ delete empty (log-)files and directories """

    threads = 20
    files = glob.glob(f'{rootpath}/**', recursive=True)

    # files
    with ThreadPoolExecutor(max_workers=threads) as exe:
      # files
      for f in files:
        if os.path.isfile(f):
          fsize = os.path.getsize(f)
          if fsize <= 3:
            exe.submit(os.unlink, f)

      # directories
      for f in files:
        if os.path.isdir(f) and not os.listdir(f):
          exe.submit(os.rmdir, f)
          self.remove_empty_files_dirs(rootpath)

    return


  def lookup_port_service(self, port, proto='tcp'):
    """ return corresponding service from services.csv for a given port """

    service = None
    services = self.file.read_csv_file(f'{ROOT_PATH}/lists/services.csv')

    for s in services:
      if port in s and proto in s:
        service = s[0]

    return service


  def print_tool(self, opts):
    """ print tool and a description of it """

    tools = []

    m = Module(MOD_PATH)
    m.get_docstrings()

    if 'all' in opts.keys():
      for tool in m.docstrings.keys():
        tools.append(tool)
    else:
      for moddir, module in opts.items():
        if module:
          for mod in module:
            for tool in m.docstrings:
              if m.docstrings[tool]['moddir'] == moddir and \
                m.docstrings[tool]['module'] == mod:
                  tools.append(tool)
        else:
          for k, v in m.docstrings.items():
            if moddir in v['moddir']:
              tools.append(k)

    tools = sorted(list(set(tools)))
    for tool in tools:
      self.log(m.docstrings[tool]['moddir'] + '/' +
        m.docstrings[tool]['module'] + '/' + tool + ' - ' +
        m.docstrings[tool]['descr'], end='\n', _type='vmsg')

    return


  def add_mod_tool(self, form, opts):
    """ create a new module and/or add tool to exisiting module """

    template = f'{MOD_PATH}libs/template.py'
    modpart = f"{MOD_PATH}{opts['moddir']}/"
    moddir = modpart
    module = f"{modpart}{opts['modname']}.py"
    tmpmod = f'{modpart}tmpxxx.py'

    if form == 'mod':
      with open(template, 'r') as fin:
        if not os.path.isdir(moddir):
          self.file.make_dir(moddir)
        with open(module, 'w') as fout:
          for line in fin:
            if '<template>.py' in line:
              fout.write(line.replace('<template>', opts['modname']))
            elif '<file>' in line:
              fout.write(line.replace('<file>', opts['modname']))
            elif '<class>' in line:
              fout.write(line.replace('<class>',
                opts['modname'].capitalize()))
            elif '<mod>' in line:
              fout.write(line.replace('<mod>', opts['modname']))
            else:
              fout.write(line)
      self.log(f"Created module {opts['moddir']}/{opts['modname']}.py\n",
        _type='msg')

    # append new tools
    try:
      shutil.copyfile(module, tmpmod)
      with open(tmpmod, 'a') as fout:
        fout.write('\n\n  @tool\n')
        fout.write(f"  def {opts['func']}(self):\n")
        fout.write('    """\n')
        fout.write('    DESCR: <REPLACE MANUALLY>\n')
        fout.write('    TOOLS: <ADD MANUALLY>\n')
        fout.write('    """\n\n')
        fout.write(f"    opts = \'{' '.join(opts['args'])}\'\n\n")
        fout.write(f"    self._run_tool(\'{opts['tool']}\', opts)\n\n")
        fout.write('    return\n')
      shutil.move(tmpmod, module)
      self.log(f"Added tool {opts['func']} to {opts['moddir']}/" +
        f"{opts['modname']}.py\n", _type='msg')
    except:
      self.log('add_tool', _type='err', end='\n')

    return


# EOF
