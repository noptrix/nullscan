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
# github.py                                                                    #
#                                                                              #
# AUTHOR                                                                       #
# noptrix@nullsecurity.net                                                     #
#                                                                              #
################################################################################


# sys imports
import requests
import bs4
from collections import deque


# own imports
from modules.libs.base import Base, tool, timeout


class Github(Base):
  """ github module (social) """


  def __init__(self, target, opts):
    """ init """

    Base.__init__(self, target, opts)

    return


  @tool
  def github_users(self):
    """
    DESCR: Enumerate public users of a github organization. (int)
    TOOLS: python3
    """

    users = deque()
    headers = {'User-Agent': self.useragent}
    url = f'https://github.com/orgs/{self.target}/people'

    with timeout(self.opts['timeout']):
      if self.opts['target_type'] == 'company':
        try:
          res = requests.get(url, headers=headers, timeout=5)
          soup = bs4.BeautifulSoup(res.text)

          for i in soup.find_all('a', {'class': 'css-truncate-target f4'}):
            users.append(f"{i.get('href').strip('/')} ({i.text.strip()})")
          users = sorted(set(users))

          for user in users:
            self._log('github_users', user)
        except:
          pass

    return


# EOF
