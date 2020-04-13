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
# filebuster.py                                                                #
#                                                                              #
# AUTHOR                                                                       #
# noptrix@nullsecurity.net                                                     #
#                                                                              #
################################################################################


# sys imports


# own imports
from modules.libs.base import Base, tool, timeout


class Filebuster(Base):
  """ Directory and file buster module """


  def __init__(self, target, opts):
    """ init """

    Base.__init__(self, target, opts)

    self.host, self.port, self.scheme, self.path = self._parse_url(self.target)

    return


  @tool
  def lulzbuster_web(self):
    """
    DESCR: Enumerate directories and files on webserver. (ext)
    TOOLS: lulzbuster
    """

    log = 'lulzbuster_web'

    for f in self.opts['flists']:
      self._lulzbuster(self.host, self.port, scheme=self.scheme, flist=f,
        log=log)

    return


  @tool
  def dirsearch_web(self):
    """
    DESCR: Enumerate directories and files on webserver. (ext)
    TOOLS: dirsearch
    """

    log = 'dirsearch_web'

    for f in self.opts['flists']:
      self._dirsearch(self.host, self.port, scheme=self.scheme, flist=f,
        log=log)

    return


  @tool
  def gobuster_web(self):
    """
    DESCR: Enumerate directories and files on webserver. (ext)
    TOOLS: gobuster
    """

    log = 'gobuster_web'

    for f in self.opts['flists']:
      self._gobuster(self.host, self.port, f, scheme=self.scheme, log=log)

    return


  @tool
  def nikto_web(self):
    """
    DESCR: Crawl the web-server for directories, files and vulnerabilities.
           (ext)
    TOOLS: nikto
    """

    self._nikto(self.host, self.port, scheme=self.scheme)

    return


  @tool
  def snallygaster_web(self):
    """
    DESCR: Scan for secret files on web-server. (ext)
    TOOLS: snallygaster
    """

    self._snallygaster(self.host, 'snallygaster_web')

    return


# EOF
