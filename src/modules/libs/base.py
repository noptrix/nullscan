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
# base.py                                                                      #
#                                                                              #
# AUTHOR                                                                       #
# noptrix@nullsecurity.net                                                     #
#                                                                              #
################################################################################


# sys imports
import sys
import os
import subprocess
from threading import Timer
import traceback
import functools
import psutil
import signal
from contextlib import contextmanager


# own imports
from core.logger import Logger
from core.file import File
from modules.libs.helper import Helper
from modules.libs.tools import Tools
from modules.libs.parser import Parser
from modules.libs.toolshelper import ToolsHelper


# from: http://www.blog.pythonlibrary.org/2016/06/09/python-how-to-create-
#   an-exception-logging-decorator/
def tool(func):
  """
  A decorator that takes care of exception printing and file.destroy_lock
  """

  @functools.wraps(func)
  def wrapper(*args, **kwargs):
    try:
      self = args[0]
      ret = func(*args, **kwargs)
      log = f'{os.getcwd()}/{func.__name__}.log'
      if not os.path.isfile(log) or os.path.getsize(log) == 0:
        with open(log, 'a') as f:
          print(' ', file=f)
      self.file.destroy_lock(func.__name__)
      return ret
    except:
      self.file.destroy_lock(func.__name__)
      #traceback.print_exc()

    return None

  return wrapper


@contextmanager
def timeout(time_out, name='', ctx=None):
  """ timeout contextmanager function """

  # Source:
  # - https://www.jujens.eu/posts/en/2018/Jun/02/python-timeout-function/
  def __raise_timeout(signum, frame):
    if ctx: ctx._log('timeout', f"__raise_timeout --> {name} ({time_out})")
    raise TimeoutError

  if isinstance(time_out, str):
    if len(time_out) > 0:
      time_out = int(time_out.split('.')[0])
    else:
      # empty timeout option, set it to an extra high value
      time_out = False
  elif time_out is None or int(time_out) == 0:
    # empty timeout option, set it to an extra high value
    time_out = False

  if time_out:
    signal.signal(signal.SIGALRM, __raise_timeout)
    signal.alarm(time_out)

  try:
    yield
  except TimeoutError:
    if ctx: ctx._log('timeout', f"got TimeoutError for {name} ({time_out})")
  finally:
    # Unregister the signal so it won't be triggered
    # if the timeout is not reached.
    if ctx: ctx._log('timeout', f"finished timeout function {name} ({time_out})")
    if time_out:
      signal.signal(signal.SIGALRM, signal.SIG_IGN)

  return


class Base(Helper, ToolsHelper, Tools, Parser):
  """ the base (parent) module for all tools """


  def __init__(self, target, opts):
    """ init """

    Helper.__init__(self, target, opts)
    ToolsHelper.__init__(self)
    Tools.__init__(self, target, opts)
    Parser.__init__(self)

    self.logger = Logger()
    self.log = self.logger.log
    self.file = File()
    self.logfile = None         # logfile for command

    return


  def _kill(self, proc, cbkill=None, nullscan_tool=None):
    """ kill process and all childs """

    if not nullscan_tool:
      nullscan_tool = proc.args.split()[0]

    self.log('tool_timeout', eargs=f"{nullscan_tool} {proc.pid}" + ' ' * 30 + \
      '\n', _type='warn', flush=True)

    if cbkill is None:
      # remove quotes from options. this still needs to be improved...
      # cmd = cmd.translate({ord(c): None for c in "\"'"})
      #self._run_cmd(f"pkill --signal SIGKILL -f '{cmd}'")
      self._run_cmd(f'kill -9 {proc.pid}')
    else:
      cbkill()

    return


  def _set_cmd_timeout(self, timeout):
    """ set command timeout """

    # set command timeout. precedence: user-supplied > in-build
    if self.opts['timeout']:
      self.opts['timeout'] = float(self.opts['timeout'])
    elif timeout:
      self.opts['timeout'] = float(timeout)
    else:
      self.opts['timeout'] = None

    return


  def _set_logfile(self, nullscan_tool, logfile):
    """ set logfile """

    # set default logfile if not given by caller
    if not logfile:
      if nullscan_tool:
        self.logfile = f'{nullscan_tool}.log'
    else:
      self.logfile = f'{logfile}.log'

    return


  def __run_cmd_intern(self, cmd, func, nullscan_tool=None, logfile=None,
    newlines=False, timeout=None, escape_codes=False):
    """
      +++ WARNING +++ WARNING +++ WARNING +++ WARNING +++ WARNING +++
      run a specified command and redirect output (logfile or variable)
      this method can be exploited ;) so use this at your own risk.
      +++ WARNING +++ WARNING +++ WARNING +++ WARNING +++ WARNING +++
    """

    self._set_logfile(nullscan_tool, logfile)
    self._set_cmd_timeout(timeout)

    # run command and log everything to logfile or return the data
    try:
      if nullscan_tool:
        with open(self.logfile, 'a') as f:
          output = func(cmd)
          if escape_codes:
            output = self._strip_ansi_codes(output)
          f.write(output)
          if self.opts['debug']:
            sys.stdout.write(output)
        if newlines:
          self._add_newlines(self.logfile)
          if self.opts['debug']:
            sys.stdout.write('\n--- next run ---\n')
      else:
        output = func(cmd)
        if escape_codes:
          output = self._strip_ansi_codes(output)
        return list(filter(None, output.split('\n')))   # remove empty items
    except subprocess.TimeoutExpired:
      self.log('tool_timeout', eargs=nullscan_tool + ' ' * 30 + '\n',
        _type='warn')
      return
    except KeyboardInterrupt:
      self.log('tool_interrupt', eargs=nullscan_tool + ' ' * 30 + '\n',
        _type='warn')
      return # don't exit. continue with other tools
    except:
      #traceback.print_exc() # print stacktrace for debuging
      return # don't exit. continue with other tools

    return


  def _run_cmd(self, cmd, nullscan_tool=None, logfile=None, newlines=False,
    timeout=None, cbkill=None, escape_codes=False):
    """ <descr> """

    def cb_exec(cmd):
      proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT)
      # from: http://www.blog.pythonlibrary.org/2016/05/17/python-101-how-
      #    to-timeout-a-subprocess/
      my_timer = Timer(self.opts['timeout'], self._kill, [proc, cbkill,
        nullscan_tool])
      try:
        my_timer.start()
        stdout, _ = proc.communicate()
      finally:
        my_timer.cancel()

      return stdout.decode('latin-1')

    return self.__run_cmd_intern(cmd, cb_exec, nullscan_tool, logfile, newlines,
      timeout, escape_codes)


  def _run_tool(self, real_tool, opts, nullscan_tool=None, precmd='',
    create_log=True, logfile=None, newlines=False, timeout=None, cbkill=None,
    escape_codes=False):
    """ wrapper of _run_cmd() wrapper to concat real_tool with (user-)opts. """

    # nullscan_tool == tool, so we can simply copy it, but only if create_log is
    # TRUE (default). otherwise _run_tool('tool', opts, ...) is called like
    # 'res = _run_cmd(cmd)'
    if not nullscan_tool and create_log:
      nullscan_tool = real_tool

    # user passed his own real_tool opts. overwrite with build-in opts
    if nullscan_tool in self.opts:
      opts = self.opts[nullscan_tool]

    cmd = f'{precmd} {real_tool} {opts}'
    self._run_cmd(cmd, nullscan_tool, logfile, newlines, timeout, cbkill,
      escape_codes)

    return


# EOF
