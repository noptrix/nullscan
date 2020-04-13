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
# tomcat.py                                                                    #
#                                                                              #
# AUTHOR                                                                       #
# noptrix@nullsecurity.net                                                     #
#                                                                              #
################################################################################


# sys imports


# own imports
from modules.libs.base import Base, tool, timeout


class Tomcat(Base):
  """ Apache Tomcat module """


  def __init__(self, target, opts):
    """ init """

    Base.__init__(self, target, opts)

    self.host, self.port, self.scheme, self.path = self._parse_url(self.target)

    return


  @tool
  def jexboss_tomcat(self):
    """
    DESCR: Check JMX JmxRemoteLifecycleListener in Tomcat (CVE-2016-8735 and
           CVE-2016-3427). (ext)
    TOOLS: jexboss
    """

    opts = '-D --jmxtomcat'

    self._jexboss(self.host, self.port, 'jexboss_tomcat', scheme=self.scheme,
      opts=opts)

    return


  @tool
  def tomcatwardeployer_web(self):
    """
    DESCR: Apache Tomcat auto WAR deployment & pwning. (ext)
    TOOLS: tomcatwardeployer
    """

    opts = '-t 5'

    if self.opts['web_user'] and self.opts['web_pass']:
      opts += f" -U {self.opts['web_user']} -P {self.opts['web_pass']}"

    opts += f" {self.scheme}://{self.host}:{self.port}/"

    self._run_tool('tomcatwardeployer', opts, 'tomcatwardeployer_web',
      timeout=10, escape_codes=True)

    return


# EOF
