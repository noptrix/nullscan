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
# extract.py                                                                   #
#                                                                              #
# AUTHOR                                                                       #
# noptrix@nullsecurity.net                                                     #
#                                                                              #
################################################################################


# sys imports
import requests
import json
import bs4
import re
import glob
import os


# own imports
from modules.libs.base import Base, tool, timeout


class Extract(Base):
  """ Extract module (web) """


  def __init__(self, target, opts):
    """ init """

    Base.__init__(self, target, opts)

    # requests
    self.headers = {'User-Agent': self.useragent}
    self.req = requests.get(self.target, verify=False, timeout=3,
      headers=self.headers, allow_redirects=True)

    return


  @tool
  def host_extract(self):
    """
    DESCR: Extract host and ip-addresses from website. (ext)
    TOOLS: host-extract
    """

    opts = f"-a -j -c {self.target.rstrip('/')}"
    self._run_tool('host-extract', opts, 'host_extract')
    self._run_cmd('rm host-extract_*')

    return


  @tool
  def links_extract(self):
    """
    DESCR: Extract links from webpage. (int)
    TOOLS: python
    """

    links = []
    attrs = (('a', 'href'), ('img', 'src'), ('script', 'src'))

    with timeout(self.opts['timeout']):
      soup = bs4.BeautifulSoup(self.req.text, 'html.parser')

      for a in attrs:
        for i in soup.find_all(a[0]):
          for j in i.get_attribute_list(a[1]):
            if '://' not in j:
              links.append(f'{self.target}{j}\n')
            else:
              links.append(f'{j}\n')

      links = list(sorted(set(links)))
      self._log('links_extract', links)

    return


  @tool
  def comments_extract(self):
    """
    DESCR: Extract comments from webpage. (int)
    TOOLS: python
    """

    comments = []

    with timeout(self.opts['timeout']):
      soup = bs4.BeautifulSoup(self.req.text, 'html.parser')

      comments = soup.find_all(text=lambda text: isinstance(text, bs4.Comment))
      comments = [f'<!-- {c} -->\n' for c in comments]

      self._log('comments_extract', comments)

    return


  @tool
  def mails_extract(self):
    """
    DESCR: Extract mail-addresses from webpage. (int)
    TOOLS: python
    """

    with timeout(self.opts['timeout']):
      splitted = bs4.BeautifulSoup(self.req.text, 'html.parser').text.split(' ')

      for mail in splitted:
        match = re.search(r'[\w\.-]+@[\w\.-]+', mail)
        if match:
          self._log('mails_extract', match.group(0))

    return


  @tool
  def crawlb0y(self):
    """
    DESCR: Crawl links and grab parameters. (priv)
    TOOLS: crawlb0y
    """

    opts = f'-u {self.target} -d 3 -t 15'
    self._run_tool('crawlb0y.sh', opts, nullscan_tool='crawlb0y')

    return


  @tool
  def photon(self):
    """
    DESCR: Crawl website and extract urls, emails, files, website accounts and
           much more. (ext)
    TOOLS: photon
    """

    logdir = f'{os.getcwd()}/photon/'
    opts = f'--timeout 3 -t 25 -l 2 --keys --wayback -o {logdir}'
    opts += f" --user-agent '{self.useragent}'"

    if self.opts['cookies']:
      opts += f" -c '{self.cookies}'"

    opts = f'-u {self.target} {opts}'
    self._run_tool('photon', opts)

    for log in glob.glob(f'{logdir}/*.txt'):
      name = f"photon_{log.split('/')[-1].rstrip('.txt')}"
      data = [f'{data}\n' for data in self.file.read_file(log)]
      self._log(name, data)

    self.file.del_file('photon.log')
    self.file.del_file('photon', _dir=True)

    return


  @tool
  def arjun(self):
    """
    DESCR: Extract HTTP parameter from webpage. (ext)
    TOOLS: arjun
    """

    opts = f"-t 15 -u '{self.target}'"

    self._run_tool('arjun', opts, escape_codes=True, timeout=600)

    return


  @tool
  def findstr_web(self):
    """
    DESCR: Find given string in HTTP responses. (int)
    TOOLS: python3
    """

    with timeout(self.opts['timeout']):
      if self.opts['searchstr'] in self.req.text:
        idx = self.req.text.index(self.opts['searchstr'])
        _bytes = int(self.opts['resp_size'])
        data = f"{self.target} ==> '{self.req.text[idx:idx+_bytes]}'"
        self._log('findstr_web', data)

    return


# EOF
