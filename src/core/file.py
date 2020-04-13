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
# file.py                                                                      #
#                                                                              #
# AUTHOR                                                                       #
# noptrix@nullsecurity.net                                                     #
#                                                                              #
################################################################################


# sys imports
import os
import errno
import csv
import shutil


# own imports
from core.logger import Logger


class File:
  """ simple wrapper class for file i/o """


  def __init__(self):
    """ constructor """

    self.logger = Logger()
    self.log = self.logger.log

    return


  def destroy_lock(self, tool):
    """ unlock / remove directory """

    lock = f'/tmp/nullscan/{tool}.lck'

    self.del_file(lock, _dir=True)

    return


  def create_lock(self, tool):
    """ create lock-dir by '/tmp/nullscan/<tool> + '.lck' """

    lock = f'/tmp/nullscan/{tool}.lck'

    if not os.path.isdir(lock):
      os.makedirs(lock)

    return


  def del_file(self, _file, _dir=False):
    """ delete a file """

    try:
      if _dir:
        shutil.rmtree(_file, ignore_errors=True)
      else:
        os.unlink(_file)
    except:
      self.log('file_del', eargs=_file, _type='err', end='\n')

    return


  def copy_dirs(self, src, dst):
    """ copy src dir to dst dir """

    try:
      shutil.copytree(src, dst)
    except:
      self.log('file_copy', _type='err', end='\n')

    return


  def copy_files(self, src, dst, move=False):
    """ copy or move all files from src to dst """

    try:
      if not move:
        shutil.copy(src, dst)
      else:
        shutil.move(src, dst)
    except:
      self.log('file_copy', _type='err', end='\n')
      return

    return


  def read_file(self, filename):
    """ read all lines from file + strip all leading/trailing w-spaces """

    try:
      with open(filename, 'r', encoding='latin-1', errors='ignore') as f:
        return [data.strip() for data in f.readlines()]
    except:
      self.log('rfile', eargs=filename, _type='err', end='\n')

    return


  def read_csv_file(self, filename, delim=';'):
    """ read csv file """

    try:
      with open(filename, newline='', encoding='latin-1', errors='ignore') as f:
        return [rdata for rdata in csv.reader(f, delimiter=delim)]
    except:
      self.log('rfile', eargs=filename, _type='err', end='\n')

    return


  def write_file(self, filename, data, mode='w', data_end=''):
    """ write all data to file """

    try:
      with open(filename, mode) as f:
        if type(data) == list:
          return [f.write(f'{d}{data_end}') for d in data]
        else:
          return f.write(f'{data}\n')
    except:
      self.log('wfile', eargs=filename, _type='err', end='\n')

    return


  def make_dir(self, path, incr=False):
    """ create a directory. don't cry if exist: append '-' + <num> """

    i = 0
    suffix = ''

    while True:
      try:
        if incr:
          if i != 0:
            suffix = f'-{str(i)}'
        os.makedirs(path + suffix)
        break
      except OSError as err:
        if err.errno == errno.EEXIST:
          i += 1
        else:
          self.log('mkdir', eargs=str(err), _type='err', end='\n')

    return path + suffix


# EOF
