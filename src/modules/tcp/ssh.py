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
# ssh.py                                                                       #
#                                                                              #
# AUTHOR                                                                       #
# noptrix@nullsecurity.net                                                     #
#                                                                              #
################################################################################


# sys imports
import concurrent.futures as cf


# own imports
from modules.libs.base import Base, tool, timeout


class SSH(Base):
  """ SSH module (tcp/22) """


  def __init__(self, target, opts):
    """ init """

    Base.__init__(self, target, opts)

    return


  @tool
  def verify_ssh(self):
    """
    DESCR: Verify SSH daemon by reading banner and supported alogrithms. (ext)
    TOOLS: ncat
    """

    opts = f"-w 3 -i 1 {self.target['host']} {self.target['port']}"
    pre_cmd = "echo -e 'SSH-2.0-OpenSSH\\r\\n' |"

    self._run_tool('ncat', opts, nullscan_tool='verify_ssh', precmd=pre_cmd)

    return


  @tool
  def ssh_user_enum(self):
    """
    DESCR: SSH user enumeration using the timing attack. (ext)
    TOOLS: ssh-user-enum
    """

    threads = len(self.opts['ulists'])

    with cf.ThreadPoolExecutor(threads) as exe:
      for u in self.opts['ulists']:
        if self._check_file(u, block=False):
          opts = f"-u {u} -i {self.target['host']} -p {self.target['port']}"
          exe.submit(self._run_tool, 'ssh-user-enum', opts, 'ssh_user_enum')

    return


  @tool
  def hydra_ssh(self):
    """
    DESCR: Bruteforce SSH logins. (ext)
    TOOLS: hydra
    """

    opts = '-e nsr -f'
    self._hydra('ssh', opts)

    return


  @tool
  def nmap_ssh(self):
    """
    DESCR: Scan SSH service with corresponding NSE scripts. (ext)
    TOOLS: nmap
    """

    opts = '-n -sS -Pn --open --nsock-engine epoll'
    opts += ' --script ssh2-enum-algos,ssh-auth-methods,ssh-hostkey,sshv1'
    opts += f" -p {self.target['port']} {self.target['host']}"

    self._run_tool('nmap', opts, nullscan_tool='nmap_ssh')

    return


# EOF
