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
# twitter.py                                                                   #
#                                                                              #
# AUTHOR                                                                       #
# noptrix@nullsecurity.net                                                     #
#                                                                              #
################################################################################


# sys imports
import bs4
import requests


# own imports
from modules.libs.base import Base, tool, timeout


class Twitter(Base):
  """ Twitter module (social) """


  def __init__(self, target, opts):
    """ init """

    Base.__init__(self, target, opts)

    return


  @tool
  def twitter_userinfo(self):
    """
    DESCR: Get basic public information about target twitter user. (int)
    TOOLS: python3
    """

    t_type = self.opts['target_type']
    url = f'https://twitter.com/{self.target}?lang=en'
    headers = {'user-agent': self.useragent}
    twitter = [
      ('name', 'a', 'ProfileHeaderCard-nameLink'),
      ('user', 'a', 'ProfileHeaderCard-screennameLink'),
      ('bio', 'p', 'ProfileHeaderCard-bio'),
      ('location', 'div', 'ProfileHeaderCard-location'),
      ('url', 'div', 'ProfileHeaderCard-url'),
      ('joined', 'div', 'ProfileHeaderCard-joinDate'),
      ('photos', 'a', 'PhotoRail-headingWithCount'),
    ]

    with timeout(self.opts['timeout']):
      if t_type == 'person' or t_type == 'company':
        res = requests.get(url, headers=headers, timeout=5)
        soup = bs4.BeautifulSoup(res.text)
        for i in twitter:
          try:
            info = i[0] + ': ' + soup.find(i[1], i[2]).text.strip()
            self._log('twitter_userinfo', info)
          except:
            pass

    return


  @tool
  def tweets_analyzer(self):
    """
    DESCR: Tweets metadata scraper & activity analyzer. (ext)
    TOOLS: tweets-analyzer
    """

    opts = f'--no-color --no-retweets -l 500 -n {self.target}'

    self._run_tool('tweets-analyzer', opts, 'tweets_analyzer')

    return


#  @tool
#  def tinfoleak2(self):
#    """
#    DESCR: Get general infos about the user. (ext)
#    TOOLS: tinfoleak2
#    """
#
#    opts = f'-i --mentions --meta --social -u {self.target}'
#    self._run_tool('tinfoleak2', opts)
#
#    return


# EOF
