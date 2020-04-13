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
# toolsattr.py                                                                 #
#                                                                              #
# AUTHOR                                                                       #
# noptrix@nullsecurity.net                                                     #
#                                                                              #
################################################################################


# sys imports


# own imports


class ToolsAttr():
  """ tools attribute (global/shared ones) wrapper class """


  def __init__(self, target, opts):
    """ init """

    self.target = target
    self.opts = opts

    # define all global/shared attributes for modules
    self._set_useragents()
    self._set_http_versions()
    self._set_http_req_types()
    self._set_icmp_types()
    self._set_dns_record_types()
    self._set_ike_auth_types()
    self._set_default_ports()
    self._set_cookies()

    return


  def _set_cookies(self):
    """ create a string of cookies """

    self.cookies = self.opts['cookies'].replace(':', '=')

    return


  def _set_useragents(self):
    """ define user agents and set default one """

    self.useragents = {
      'nullscan': 'nullscan',
      'firefox_win': 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:54.0) Gecko/20100101 Firefox/69.0',
      'firefox_linux': 'Mozilla/5.0 (X11; Linux i586; rv:31.0) Gecko/20100101 Firefox/69.0',
      'firefox_macos': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.13; rv:61.0) Gecko/20100101 Firefox/69.0',
      'firefox_android': 'Mozilla/5.0 (Android 8.0.0; Mobile; rv:61.0) Gecko/61.0 Firefox/69.0',
      'firefox_ios': 'Mozilla/5.0 (iPhone; CPU iPhone OS 12_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/18.1 Mobile/16B92 Safari/605.1.15',
      'chrome_win': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.132 Safari/537.36',
      'chrome_linux': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.132 Safari/537.36',
      'chrome_macos': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.132 Safari/537.36',
      'chrome_android': 'Mozilla/5.0 (Linux; Android 8.0.0;) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.132 Mobile Safari/537.36',
      'chrome_ios': 'Mozilla/5.0 (iPhone; CPU iPhone OS 12_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/76.0.3809.123 Mobile/15E148 Safari/605.1',
      'opera_win': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.132 Safari/537.36 OPR/63.0.3368.53',
      'opera_linux': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.132 Safari/537.36 OPR/63.0.3368.53',
      'opera_macos': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.132 Safari/537.36 OPR/63.0.3368.53',
      'opera_andoird': 'Mozilla/5.0 (Linux; Android 9; AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.132 Mobile Safari/537.36 OPR/52.4.2517.140781',
      'safari_macos': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.1.2 Safari/605.1.15',
      'safari_iphone': 'Mozilla/5.0 (iPhone; CPU iPhone OS 12_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.1 Mobile/15E148 Safari/604.1',
      'safari_ipad': 'Mozilla/5.0 (iPad; CPU OS 12_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.1 Mobile/15E148 Safari/604.1',
      'edge': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.132 Safari/537.36 Edg/44.18362.267.0',
      'edge_mobile': 'Mozilla/5.0 (Windows Mobile 10; Android 8.0.0; Microsoft; Lumia 950XL) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.132 Mobile Safari/537.36 Edge/40.15254.369',
      'ie': 'Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko',
      'googlebot': 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)'
    }

    # default
    if self.opts['ua']:
      self.useragent = self.opts['ua']
    else:
      self.useragent = self.useragents['firefox_win']

    return


  def _set_http_versions(self):
    """ set http versions """

    self.http_versions = ('0.9', '1.0', '1.1', '2')

    return


  def _set_http_req_types(self):
    """ set our own http default request types """

    self.http_req_types = ('head', 'get', 'post', 'options')

    return


  def _set_icmp_types(self):
    """ all RFC compliant ICMP types: name, type, code """

    self.icmp_types = {
      'echo_reply':           {0:   (0,)},
      'dest_unreach':         {3:   (0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15)},
      'source_quench':        {4:   (0,)},
      'redirect':             {5:   (0,1,2,3)},
      'alt_host_addr':        {6:   (0,)},
      'echo_request':         {8:   (0,)},
      'router_adver':         {9:   (0,16)},
      'router_select':        {10:  (0,)},
      'time_exceed':          {11:  (0,1)},
      'param_problem':        {12:  (0,1,2)},
      'timestamp':            {13:  (0,)},
      'timestamp_reply':      {14:  (0,)},
      'info_request':         {15:  (0,)},
      'info_reply':           {16:  (0,)},
      'addr_mask_req':        {17:  (0,)},
      'addr_mask_reply':      {18:  (0,)},
      'traceroute':           {30:  (0,)},
      'datagram_conv_err':    {31:  (0,)},
      'mobile_host_redir':    {32:  (0,)},
      'ipv6_where_r_u':       {33:  (0,)},
      'ipv6_i_am_here':       {34:  (0,)},
      'mobile_reg_req':       {35:  (0,)},
      'mobile_reg_reply':     {36:  (0,)},
      'domain_name_req':      {37:  (0,)},
      'domain_name_reply':    {38:  (0,)},
      'skip':                 {39:  (0,)},
      'photuris':             {40:  (0,1,2,3,4,5)},
      'mobile_various':       {41:  (0,)},
      'ext_echo_req':         {42:  (0,)},
      'ext_echo_reply':       {43:  (0,1,2,3,4)},
    }

    return


  def _set_dns_record_types(self):
    """ all dns record types except: A, AAAA,"""

    self.dns_record_types = (
      'a', 'aaaa', 'afsdb', 'apl', 'caa', 'cdnskey', 'cds', 'cert', 'cname',
      'dhcid', 'dlv', 'dname', 'dnskey', 'ds', 'hip', 'ipseckey', 'key', 'kx',
      'loc', 'mx', 'naptr', 'nsec', 'nsec3', 'nsec3param', 'ptr', 'rrsig', 'rp',
      'sig', 'soa', 'srv', 'sshfp', 'ta', 'tkey', 'tlsa', 'tsig', 'txt', 'uri'
    )

    return


  def _set_ike_auth_types(self):
    """ ike auth types """

    self.ike_auth_types = {
      'rfc': tuple(map(str, range(1, 6))),
      'checkpoint_hybrid': ('64221',),
      'gss-kerberos': ('65001',),
      'xauth': tuple(map(str, range(65001, 65011))),
    }

    return


  def _set_default_ports(self):
    """ set default tcp and udp ports """

    self.def_tcp_ports = (21, 22, 23, 25, 53, 80, 110, 113, 139, 143, 443, 445,
      993, 995, 3306, 5432, 8000, 8080)
    self.def_udp_port = (53, 68, 69, 123, 161, 500, 514, 1194)

    return


  def _make_portlist(self, ports, sep=','):
    """ create a port list separated by sep """

    if self.target['ports']:
      self.ports = sep.join([p[0] for p in self.target['ports']])
    else:
      newports = sep.join([str(p) for p in ports])

    return newports


# EOF
