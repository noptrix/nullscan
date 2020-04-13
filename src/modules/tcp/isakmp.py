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
# isakmp.py                                                                    #
#                                                                              #
# AUTHOR                                                                       #
# noptrix@nullsecurity.net                                                     #
#                                                                              #
################################################################################


# sys imports
import os


# own imports
from modules.libs.base import Base, tool, timeout


class ISAKMP(Base):
  """ ISAKMP module (tcp/500) """


  def __init__(self, target, opts):
    """ init """

    Base.__init__(self, target, opts)

    return


  @tool
  def ikescan(self):
    """
    DESCR: Enumerate and fingerprint VPN endpoint. Try to get PSK hash via
           aggressive mode. (ext)
    TOOLS: ike-scan
    """

    # enum
    self._ikescan('--tcp -O 5', 'ikescan')

    # fingerprint
    self._ikescan('-v -v --tcp --showbackoff', 'ikescan_fingerprint')

    # PSK hash
    opts = f"--tcp -A --id=1 -Pvpn.key {self.target['host']}"
    self._run_tool('ike-scan', opts, create_log=False)
    if os.path.isfile('vpn.key') and os.path.getsize('vpn.key') > 0:
      self._run_cmd('cat vpn.key >> ikescan_pskhash.log')

    return


  @tool
  def ikeprober(self):
    """
    DESCR: Probe IKE requests and enumerate IKE related stuff. (ext)
    TOOLS: ikeprober
    """

    opts = f"-d {self.target['host']}"
    self._run_tool('ikeprober', opts)

    return


  @tool
  def ikeprobe(self):
    """
    DESCR: Test for aggressive mode and vulnerable shared PSK. (ext)
    TOOLS: wine ikeprobe
    """

    opts = f"/usr/share/windows/ikeprobe/ikeprobe.exe {self.target['host']}"
    self._run_tool('wine', opts, 'ikeprobe')

    return


  @tool
  def nmap_isakmp(self):
    """
    DESCR: Scan isakmp service with corresponding NSE scripts. (ext)
    TOOLS: nmap
    """

    opts = '-n -sS -Pn --open --nsock-engine epoll'
    opts += f" --script ike-version -p {self.target['port']}"
    opts += f" {self.target['host']}"

    self._run_tool('nmap', opts, nullscan_tool='nmap_isakmp')

    return


# EOF
