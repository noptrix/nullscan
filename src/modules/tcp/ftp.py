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
# ftp.py                                                                       #
#                                                                              #
# AUTHOR                                                                       #
# noptrix@nullsecurity.net                                                     #
#                                                                              #
################################################################################


# sys imports
import os
import concurrent.futures as cf
from ftplib import FTP as _FTP


# own imports
from modules.libs.base import Base, tool, timeout


class FTP(Base):
  """ FTP module (tcp/21) """


  def __init__(self, target, opts):
    """ init """

    Base.__init__(self, target, opts)

    self.ftp = _FTP(timeout=3)     # ftplib FTP instance

    return


  @tool
  def ftp_anon_login(self):
    """
    DESCR: Login as anonymous user to the FTP service. (int)
    TOOLS: python3
    """

    with timeout(self.opts['timeout']):
      self.ftp.connect(self.target['host'], port=int(self.target['port']))
      res = self.ftp.login()
      self._log('ftp_anon_login', res)

    return


  @tool
  def ftpmap(self):
    """
    DESCR: Fingerprint the FTP service. (ext)
    TOOLS: ftpmap
    """

    opts = f"-S -P {self.target['port']} -s {self.target['host']}"

    self._run_tool('ftpmap', opts)

    return


  @tool
  def ftp_fuzz(self):
    """
    DESCR: Fuzz the FTP service. (ext)
    TOOLS: ftp-fuzz
    """

    opts = {
      'anon': f"-p {self.target['port']} -t {self.target['host']}",
      'login': f"-U {self.opts['user']} -P {self.opts['pass']}"\
        f" -p {self.target['port']} -t {self.opts['user']}",
    }
    threads = len(opts.keys())

    with cf.ThreadPoolExecutor(threads) as exe:
      for o in opts.values():
        exe.submit(self._run_tool, 'ftp-fuzz', o, 'ftp_fuzz')

    return


  @tool
  def hydra_ftp(self):
    """
    DESCR: Bruteforce FTP logins. (ext)
    TOOLS: hydra
    """

    opts = '-e nsr -f'

    self._hydra('ftp', opts)

    return


  @tool
  def ftp_bounce(self):
    """
    DESCR: Check if target FTP service supports bounce scanning. (ext)
    TOOLS: nmap
    """

    nmap_opts = ['-n', '-Pn', '-p 80,443']
    nmap_opts.append(f"-b {self.target['host']}")
    opts = {'hosts': ['github.com', 'microsoft.com'], 'opts': nmap_opts}

    self._portscan(opts, logfile='ftp_bounce')

    self._run_cmd('mv ftp_bounce.nmap ftp_bounce.log')

    self.file.del_file('ftp_bounce.xml')
    self.file.del_file('ftp_bounce.gnmap')

    return


  @tool
  def ftp_dir(self):
    """
    DESCR: List directories with permissions of parent directory. (int)
    TOOLS: python3
    """

    login = 'anon'
    files = []
    hydra_log = self._read_log('hydra_ftp')

    # try with valid logins we cracked before
    if hydra_log:
      for line in hydra_log:
        if 'login: ' in line and 'password: ' in line:
          res = line.split()
          username = res[4]
          password = res[6]
          login = 'real'
          break

    with timeout(self.opts['timeout']):
      self.ftp.connect(self.target['host'], port=int(self.target['port']))

      if login == 'real':
        self.ftp.login(user=username, passwd=password)
      else:
        self.ftp.login()

      self.ftp.retrlines('LIST', files.append)

      self._log('ftp_dir', f'Logged in via: {login} login\n')
      [self._log('ftp_dir', f) for f in files]

    return


  @tool
  def nmap_ftp(self):
    """
    DESCR: Scan ftp service with corresponding NSE scripts. (ext)
    TOOLS: nmap
    """

    opts = '-n -sS -Pn --open --nsock-engine epoll'
    opts += ' --script ftp-anon,ftp-bounce,ftp-libopie,ftp-proftpd-backdoor,'
    opts += 'ftp-syst,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221'
    opts += f" -p {self.target['port']} {self.target['host']}"

    self._run_tool('nmap', opts, nullscan_tool='nmap_ftp')

    return


# EOF
