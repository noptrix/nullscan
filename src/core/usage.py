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
# usage.py                                                                     #
#                                                                              #
# AUTHOR                                                                       #
# noptrix@nullsecurity.net                                                     #
#                                                                              #
################################################################################


# sys imports
from colorama import Style, Fore


# own imports
from core.constants import *


class Usage:
  """ class for usage and help outputs """


  def __init__(self):
    """ init """

    return


  @staticmethod
  def add_tool_usage():
    """ print usage for add tool option (-a) """

    print(
      '[+] ' + Style.BRIGHT + 'info:' + Style.RESET_ALL + '\n\n'
      '    This option adds a new tool to an existing module. Only one tool\n'
      '    can be added together with arguments per \'-a\' call. Also, note\n'
      '    that if format-strings were used as arguments then they need to\n'
      '    be edited manually in the source file afterwards. See example.\n\n'
      '\n'
      '[+] ' + Style.BRIGHT + 'syntax:' + Style.RESET_ALL + '\n\n'
      '    > <moddir/modname> <func> [tool] [tool_args]\n\n'
      '[+] ' + Style.BRIGHT + 'example:' + Style.RESET_ALL + '\n\n'
      "    > 'host/icmp ping_flood ping -f -s 9999 {0}'"
    )

    return


  @staticmethod
  def add_module_usage():
    """ print usage for add module option (-m) """

    print(
      '[+] ' + Style.BRIGHT + 'info:' + Style.RESET_ALL + '\n\n'
      '    This option creates new modules on the fly. Only one, initial tool\n'
      '    should be added. More tools can then be added afterwards using the\n'
      '    \'-a\' option or directly edit the module-source file itself,\n'
      '    respectively. Also, note that if format-strings were used as\n'
      '    arguments then they need to be edited manually in the source file\n'
      '    afterwards, respectively. See example.\n\n'
      '[+] ' + Style.BRIGHT + 'syntax:' + Style.RESET_ALL + '\n\n'
      '    > <moddir/modname> <func> [tool] [tool_args]\n\n'
      '[+] ' + Style.BRIGHT + 'example:' + Style.RESET_ALL + '\n\n'
      "    > 'tcp/mysql crack_mysql mysqlcrax0r --host {0} --port {1}'"
    )

    return


  @staticmethod
  def print_tools_usage():
    """ print usage for list tools option (-p) """

    print(
      '[+] ' + Style.BRIGHT + 'info:' + Style.RESET_ALL + '\n\n'
      '    This option prints available tools with their short descriptions.\n'
      '    Different modules and multiple values can be specified.\n\n'
      '[+] ' + Style.BRIGHT + 'syntax:' + Style.RESET_ALL + '\n\n'
      '    > all[;moddir;moddir2=mod1,mod2;...;moddirN]\n\n'
      '[+] ' + Style.BRIGHT + 'example:' + Style.RESET_ALL + '\n\n'
      "    > 'all'\n"
      "    > 'tcp;udp;social'\n"
      "    > 'host=default,whois;lan=default,arp;tcp'"
    )

    return


  @staticmethod
  def tools_usage():
    """ print usage for tools option (-I/-X) """

    print(
      '[+] ' + Style.BRIGHT + 'info:' + Style.RESET_ALL + '\n\n'
      '    This option includes (-I) / excludes (-X) individual tools of\n'
      '    modules. Options set here will be merged together with options\n'
      '    from nullscan config file.\n\n'
      '[+] ' + Style.BRIGHT + 'syntax:' + Style.RESET_ALL + '\n\n'
      '    > <tool>[,...,toolN]\n\n'
      '[+] ' + Style.BRIGHT + 'example:' + Style.RESET_ALL + '\n\n'
      "    > 'netcat,nmap,dnsspider'"
    )

    return


  @staticmethod
  def modules_usage():
    """ print usage for modules (-i/-x) """

    print(
      '[+] ' + Style.BRIGHT + 'info:' + Style.RESET_ALL + '\n\n'
      '    This option includes (-i) / excludes (-x) given modules. Options\n'
      '    set here will be merged together with options from nullscan config\n'
      '    file.\n\n'
      '[+] ' + Style.BRIGHT + 'syntax:' + Style.RESET_ALL + '\n\n'
      '    > <moddir>=<mod>[,mod2;...;moddir=modN]\n\n'
      '[+] ' + Style.BRIGHT + 'example:' + Style.RESET_ALL + '\n\n'
      "    > 'host=default,whois;tcp=ftp,ssh;udp=ntp'"
    )

    return


  @staticmethod
  def extra_opts_usage():
    """ print usage for extra options (-o) """

    print(
      '[+] ' + Style.BRIGHT + 'info' + Style.RESET_ALL + '\n\n'
      '    Extra options for modes can be defined via opts=val. Multiple\n'
      '    options and values can be specified using "," as separator. Except\n'
      '    nmap! For nmap, spaces are needed (see nmap-syntax and examples\n'
      '    below). These options are then passed to the tools. Options can\n'
      '    also be set via nullscan config file. All options set here will\n'
      '    overwrite options of nullscan config file!\n\n'
      '[+] ' + Style.BRIGHT + 'syntax' + Style.RESET_ALL + '\n\n'
      '    > <opt>=<val>[;optN=val2,...,valN]\n\n'
      '[+] ' + Style.BRIGHT + 'nmap syntax' +
      Style.RESET_ALL + '\n\n'
      '    > <nmap>=<val> [val2 ... valN] (spaces instead of comma!)\n\n'
      '[+] ' + Style.BRIGHT + 'generic' + Style.RESET_ALL + '\n\n'
      '    > tool           <opts>      - overwrite build-in tool-opts for\n'
      '                                   $tool with your opts given on\n'
      '                                   cmdline. see examples below\n'
      '    > user           <user>      - single username\n'
      '    > pass           <pass>      - single password\n'
      '    > ulists         <files>     - file with usernames\n'
      '    > plists         <files>     - file with passwords\n'
      '    > shodan_key     <key>       - shodan api key\n'
      '    > censys_id      <key>       - censys id key\n'
      '    > censys_sec     <key>       - censys sec key\n'
      '    > ipapi_key      <key>       - ipapi api key\n'
      '    > proxy          <uri>       - any proxy address (URI form)\n'
      '    > proxy_user     <user>      - proxy username\n'
      '    > proxy_pass     <pass>      - proxy password\n'
      '    > searchstr      <str>       - string to search in socket responses\n'
      '    > resp_size      <num>       - num bytes resp-data to print after\n'
      '                                   $searchstr was found (default: 32)\n\n'
      '[+] ' + Style.BRIGHT + 'network' + Style.RESET_ALL + '\n\n'
      '    > shost          <host>      - source host\n'
      '    > sport          <port>      - source port\n'
      '    > smac           <mac>       - source mac addr\n'
      '    > dhost          <host>      - target host\n'
      '    > dport          <port>      - target port\n'
      '    > dmac           <mac>       - target mac addr\n'
      '    > rhost          <host>      - router host\n'
      '    > rport          <port>      - router port\n'
      '    > rmac           <mac>       - router mac addr\n'
      '    > ndev           <iface>     - network interface\n\n'
      '[+] ' + Style.BRIGHT + 'social' + Style.RESET_ALL + '\n\n'
      '    > linkedin_user  <user>      - linkedin username\n'
      '    > linkedin_pass  <pass>      - linkedin password\n\n'
      '[+] ' + Style.BRIGHT + 'wifi' + Style.RESET_ALL + '\n\n'
      '    > ssid           <name>      - wifi ssid\n'
      '    > bssid          <mac>       - mac address of AP\n'
      '    > station_mac    <mac>       - mac address of STA\n'
      '    > wifi_channel   <number>    - wifi channel\n'
      '    > wifi_timeout   <sec>       - wifi timeout\n\n'
      '[+] ' + Style.BRIGHT + 'web' + Style.RESET_ALL + '\n\n'
      '    > start_url      <url>       - start url of website\n'
      '    > login_url      <url>       - login url to website\n'
      '    > attack_url     <url>       - single url to attack\n'
      '    > post_data      <str>       - post params and values\n'
      '    > referer        <url>       - referer url\n'
      '    > web_user       <user>      - any web-login username\n'
      '    > web_pass       <pass>      - any web-login password\n'
      '    > cookies        <cookies>   - web cookies\n'
      '    > ua             <ua>        - user-agent string\n'
      '    > ua_lists       <lists>     - files with user-agents\n'
      '    > flists         <lists>     - files with directories/filenames\n\n'
      '[+] ' + Style.BRIGHT + 'nmap' + Style.RESET_ALL +  '\n\n'
      '    > nmap           <opts>      - custom nmap options\n\n'
      '[+] ' + Style.BRIGHT + 'example' + Style.RESET_ALL + '\n\n'
      "    > 'rhost=192.168.0.1;sport=1337;ndev=em0;ssid=nullsex;\n"
      "       user=root;plists=/tmp/pass1.txt,~/haxx/mylists/pass2.txt;\n"
      "       dirsearch_web=-o my -p \"own opts\" -c 1 -f 4;\n"
      "       nmap=-sS -p 80,443 --allports -vv -n;'\n"
    )

    return


  @staticmethod
  def nmap_mode_usage():
    """ print usage for host file mode (-t) """

    print(
      '[+] ' + Style.BRIGHT + 'info:' + Style.RESET_ALL + '\n\n'
      '    Targets are defined via cmdline. See syntax below.\n'
      '    Nmap scan will be performed to gather open ports. Default protocol\n'
      '    is TCP and default port-range is nmap specific. Defaut scan will\n'
      '    not use os-fingerprinting, version scanning and such options;\n'
      '    only simple tcp-connect, tcp-syn (if uid=0) or udp. It makes no\n'
      '    sense to perform fingerprinting or version scanning as all these\n'
      '    kind of things are done later by modules for each single service.\n'
      '    Custom nmap options can be set via \'-o nmap...\'.\n'
      '    Note: nmap log file format is not needed as \'-oA results\' is\n'
      '    defined already.\n\n'
      '[+] ' + Style.BRIGHT + 'syntax:' + Style.RESET_ALL + '\n\n'
      '    > <host> single host, e.g.: -t kernel.org\n'
      '    > <host1>,...,<hostN> multi hosts: foobar.com,8.8.8.8\n'
      '    > <host-range> IPv4 host-range: 192.168.0.1-192.168.0.254\n'
      '    > <cidr-range> IPv4 CIDR-range: 192.168.0.0/24\n'
      '    > <file> file containing hosts line by line\n\n'
      '[+] ' + Style.BRIGHT + 'example:' + Style.RESET_ALL + '\n\n'
      '    > 192.168.0.0/24\n'
      '    > 8.8.8.8,192.168.0.1,192.168.0.7,1.1.1.1\n'
      '    > 192.168.0.1-192.168.0.254\n'
      '    > /tmp/to-pwn-list.txt'
    )

    return


  @staticmethod
  def host_mode_usage():
    """ print usage for target mode (-t) """

    print(
      '[+] ' + Style.BRIGHT + 'info' + Style.RESET_ALL + '\n\n'
      '    Targets are defined via cmdline using an URI scheme. Given ports\n'
      '    will count as open. Multiple targets and protocols can be\n'
      '    specified. Ports are optional; you do not to specify ports, if\n'
      '    only host modules should run. If service behind port is unknown,\n'
      '    then \'default\' module can be used, e.g.: 1337=default\n'
      '    otherwise a lookup will be performed in the lists/services.csv\n'
      '    file for corresponding port:service or you can specify the\n'
      '    service (module) to use on your own, e.g.: 8080=http.\n\n'
      '[+] ' + Style.BRIGHT + 'available modes' + Style.RESET_ALL + '\n\n'
      '    > tcp | udp      run tcp or udp tools against hosts\n'
      '    > lan            run infrastructure tools against lan\n'
      '    > http | https   run tools against websites\n'
      '    > wifi           run wifi tools against access points etc.\n'
      '    > person         run social tools against person\n'
      '    > mail           run social tools against mail address\n'
      '    > company        run social tools against company name\n'
      '    > domain         run social tools against domain name\n\n'
      '[+] ' + Style.BRIGHT + 'modes syntax' + Style.RESET_ALL + '\n\n'
      '    > tcp://<host>[:port=service][,port2=service2][;...]\n'
      '    > lan://<iface>[,iface2...]\n'
      '    > http://<site>[,site2,...]\n'
      '    > wifi://<iface>[,iface2,...]\n'
      '    > person://<firstname|nickname> [lastname]\n'
      '      [,<firstname2|nickname2> [lastname2],...]\n'
      '    > mail://<addr>[,<addr2>,...]\n'
      '    > company://<name>[,<name2>,...]\n'
      '    > domain://<name>[,<name2>,...]\n\n'
      '[+] ' + Style.BRIGHT + 'example' + Style.RESET_ALL + '\n\n'
      "    > 'tcp://nullsecurity.net:22=ssh,8080=http;udp://\n"
      "       google.com:123=ntp,1337=default;tcp://blackarch.org/'"
    )

    return


  @staticmethod
  def banner():
    """ print banner """

    print(Style.BRIGHT + Fore.BLUE + r'''                ____
   ____  __  __/ / /_____________ _____
  / __ \/ / / / / / ___/ ___/ __ `/ __ \
 / / / / /_/ / / (__  ) /__/ /_/ / / / /
/_/ /_/\__,_/_/_/____/\___/\__,_/_/ /_/''' + Style.RESET_ALL + '''

   --==[ by nullsecurity.net ]==--
    ''')

    return


  @staticmethod
  def usage():
    """ print usage and help """

    print(
      Style.BRIGHT + 'usage' + Style.RESET_ALL +
      '\n\n  nullscan <modes> [options] | <misc>\n\n'
      + Style.BRIGHT + 'modes' + Style.RESET_ALL + '\n\n'
      '  -t <targets> - hosts to scan via nmap and then attack - ? for info\n'
      '  -u <uris>    - targets to attack directly via URIs - ? for info\n'
      '  -l <file>    - parse nmap xml logfile and attack hosts on open ports\n\n'
      + Style.BRIGHT + 'options' + Style.RESET_ALL + '\n\n'
      '  -o <opts>    - extra options for modes - ? for info\n'
      '  -i <mods>    - include modules (default: all) - ? for info\n'
      '  -I <tools>   - include tools (default: all) - ? for info\n'
      '  -x <mods>    - exclude modules (default: see nullscan.cfg) - ? for info\n'
      '  -X <tools>   - exclude tools (default: see nullscan.cfg) - ? for info\n'
      '  -T <num>     - num workers for parallel target checks (default: 15)\n'
      '  -M <num>     - num workers to run parallel modules (default: 10)\n'
      '  -P <num>     - num workers to run parallel tools (default: 15)\n'
      '  -k <sec>     - num seconds for tool (global) timeout (default: 0.0)\n'
      '  -r           - generate an html report\n'
      '  -R <dir>     - work, log and report dir (default: pwd + date)\n'
      '  -c <file>    - config file (default: /etc/nullscan.conf)\n'
      '  -v           - verbose mode (default: false)\n'
      '  -d           - debug mode (default: false)\n\n'
      + Style.BRIGHT + 'misc' + Style.RESET_ALL + '\n\n'
      '  -C           - check for missing tools (recommended)\n'
      '  -p <args>    - print tools and exit - ? for info\n'
      '  -m <args>    - create and add a new module - ? for info\n'
      '  -a <args>    - add tool to existing module - ? for info\n'
      '  -V           - print version of nullscan and exit\n'
      '  -H           - print this help and exit\n\n'
      + Style.BRIGHT + 'examples' + Style.RESET_ALL + '\n\n'
      "  -t 192.168.0.0/24 -i tcp=ssh,http -r -I hydra_ssh,crack_http_auth\n\n"
      '  -u \'tcp://nsa.gov:80=http,22=ssh;udp://foo.bar:1337;\n'
      '      http://fbi.gov,https://cia.gov;mail://foo@bar.baz;\n'
      '      person://justin bieber,noptrix;lan://eth0,tap0;wifi://wlan0\'\n'
      '      -o \'user=root;plists=/tmp/pwds.txt;rhost=192.168.0.1;\n'
      '      sport=1337;dirsearch_web=-o my -p \"own opts\" -c 1 -f 4;\'\n\n'
      '  -n /tmp/scanned.xml -i \'host=icmp;tcp=default\' -r\n\n'
      '  -l hosts.txt -X sqlmap,wpscan -v -o \'httping_web=-p cia.gov;\n'
      '     rpcdump_udp=-f foo -b bar;nmap=-sT,-n,-p-;\'\n\n'
      '  -p \'tcp=ssh,http;host=zonetransfer;udp\'\n\n'
      '  -m \'icmp/ping ping_flood ping -f -s 9999\'\n\n'
      '  -a \'tcp/ssh crack_ssh sshcracker -c arg -f arg\''
    )

    return


# EOF
