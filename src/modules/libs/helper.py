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
# helper.py                                                                    #
#                                                                              #
# AUTHOR                                                                       #
# noptrix@nullsecurity.net                                                     #
#                                                                              #
################################################################################


# sys imports
import os
import glob
import filecmp
import urllib
import psutil
import re


# own imports
import core.nmap


class Helper():
  """ generic helper and wrapper class """


  def __init__(self, target, opts):
    """ init """

    self.target = target
    self.opts = opts

    if type(self.target) == dict and self.target['host']:
      self._target = self.target['host']
    else:
      self._target = self.target

    return


  def _strip_ansi_codes(self, line, ecodes=r'\x1B[@-_][0-?]*[ -/]*[@-~]'):
    """ strip ansi escape-codes (special color codes) from given line """

    escape = re.compile(ecodes)

    return escape.sub('', line)


  def _parse_url(self, url):
    """ parse host, port and scheme out of url """

    parsed = urllib.parse.urlparse(url)

    if ':' in parsed.netloc:
      splitted = parsed.netloc.split(':')
      host = splitted[0]
      port = splitted[1]
    else:
      host = parsed.netloc
      if parsed.scheme == 'https':
        port = '443'
      else:
        port = '80'

    return host, port, parsed.scheme, parsed.path


  def _logentry_exists(self, logfile):
    """
    check if same logfile with same log entries already exists for other targets
    of given tool. this is good if we want to avoid running, for example,
    subdomain scanner multiple times against the same domain.
    """

    curlog = None
    curpath = f"{self.opts['nullscan_logdir']}{self._target}/**/{logfile}.log"

    # get path of current logfile
    for c in glob.glob(curpath, recursive=True):
      if f'{logfile}.log' in c:
        curlog = c
        break

    logs = f"{self.opts['nullscan_logdir']}**/{logfile}.log"

    if curlog:
      for log in glob.glob(logs, recursive=True):
        if self._target not in log:
          if filecmp.cmp(log, curlog, shallow=False):
            return True

    return False


  def _get_uname(self):
    """ get uname """

    return os.uname()


  def _get_euid(self):
    """ get euid """

    return os.geteuid()


  def _add_newlines(self, logfile):
    """ add newlines to logfile for multiple results (appended)"""

    try:
      with open(logfile, 'a') as log:
        print('\n--- next run ---\n', file=log)
    except:
      pass

    return


  def _read_log(self, nullscan_tool):
    """ find given nullscan_tool's log and read the file. dirty (tmp) hack :( """

    while True:
      # Here we look for new log files created by the tools
      logs = self._get_all_log_files()
      for log in logs:
        if f'/{nullscan_tool}.log' in log:
          if os.path.getsize(log) != 0:
            return self._read_file(log)
      else:
        continue

    return


  def _get_all_log_files(self, pattern_match=None):
    """
    returns all log files under self._target,
    opt. filter via pattern_match
    """

    path = f"{self.opts['nullscan_logdir']}{self._target}/**/*.log"
    logs = glob.glob(path, recursive=True)
    if pattern_match is not None:
      logs = list(filter(lambda log: re.match(pattern_match, log), logs))

    return logs


  def _read_file(self, _file, csv=False, delim=' '):
    """ wrapper for File.read_file() """

    self._check_file(_file)

    if not csv:
      return self.file.read_file(_file)
    else:
      return self.file.read_csv_file(_file, delim)

    return False


  def _check_file(self, _file, block=True):
    """ check if file exists and check if not empty (block until) """

    # block until lockfile removed / tool done
    if '.log' in _file:
      lock = f"/tmp/nullscan/{_file.split('.log')[0].split('/')[-1]}.lck"
      while os.path.isdir(lock):
        continue

    if not block:
      if os.path.isfile(_file):
        return True

    # block until file and file is greater than 0 bytes
    while not os.path.isfile(_file) and os.path.getsize(_file) == 0:
      continue
    else:
      return True

    return False


  def _log(self, logfile, data, mode='a', data_end=''):
    """ wrapper around File.write_file() """

    self.file.write_file(f'{logfile}.log', data, mode, data_end)

    return


  def _is_process_running(self, procname):
    """ check if given process name is running. """

    for proc in psutil.process_iter():
      try:
        if procname.lower() in proc.name().lower():
          return True
        else:
          return False
      except:
        pass

    return False


# EOF
