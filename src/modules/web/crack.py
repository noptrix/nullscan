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
# crack.py                                                                     #
#                                                                              #
# AUTHOR                                                                       #
# noptrix@nullsecurity.net                                                     #
#                                                                              #
################################################################################


# sys imports
from collections import deque


# own imports
from modules.libs.base import Base, tool, timeout


class Crack(Base):
  """ Login Cracker module """


  def __init__(self, target, opts):
    """ init """

    Base.__init__(self, target, opts)

    self.host, self.port, self.scheme, self.path = self._parse_url(self.target)

    return


  @tool
  def crack_http_auth_web(self):
    """
    DESCR: Check HTTP auth type (basic, realm, etc.) and crack login. (int)
    TOOLS: python3
    """

    url = self.target
    if self.opts['attack_url']:
      url = self.opts['attack_url']
    if self.opts['login_url']:
      url = self.opts['login_url']

    with timeout(self.opts['timeout']):
      self._crack_http_auth(url, 'crack_http_auth_web')

    return


  @tool
  def crack_tomcat_web(self):
    """
    DESCR: Check for tomcat and crack logins using tomcat's default creds. (int)
    TOOLS: python3
    """

    # default tomcat creds
    users = deque(('tomcat', 'both', 'role1', 'admin', 'manager', 'root'))
    pws = deque(('tomcat', 'both', 'role1', 'admin', 'manager', 'root', ''))

    threads = len(users)

    with timeout(self.opts['timeout']):
      url = self._is_tomcat(self.host, self.port)

      if url:
        with cf.ThreadPoolExecutor(threads) as exe:
          for us in users:
            for pw in pws:
              exe.submit(self._crack_tomcat, url, us, pw, 'crack_tomcat_web')

    return


  @tool
  def brutemap(self):
    """
    DESCR: Crack website logins using dictionary attack. (ext)
    TOOLS: brutemap
    """

    # overwrite self.target if login or attack url was given
    target = self.target.rstrip('/')
    if self.opts['login_url']:
      target = self.opts['login_url'].rstrip('/')
    elif self.opts['attack_url']:
      target = self.opts['attack_url'].rstrip('/')

    self._brutemap(target)

    return


# EOF
