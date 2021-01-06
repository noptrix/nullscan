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
# constants.py                                                                 #
#                                                                              #
# AUTHOR                                                                       #
# noptrix@nullsecurity.net                                                     #
#                                                                              #
################################################################################


# sys imports
import os
import datetime


# own imports


# nullscan version banner
VERSION = 'nullscan v1.0.1'

# our own (exit) error codes
SUCCESS = 0
FAILURE = 1

# today's date
TODAY = str(datetime.date.today())

# tcp/udp ports
PORT_MIN = 0
PORT_MAX = 65535

# max threads
WORKERS_MAX = 255

# nullscan's source path (dirty hack)
SRC_PATH = os.path.split(os.path.abspath(os.path.dirname(__file__)))[0]

# nullscan's root path
ROOT_PATH = SRC_PATH.replace('src', '')

# nullscan's share path
SHARE_PATH = '/usr/share/nullscan'

# modules path
MOD_PATH = os.path.join(SRC_PATH, 'modules/')

# doc path
DOC_PATH = '/usr/share/doc/nullscan'

# config
NULLSCAN_CONF = '/etc/nullscan.conf'

# nullscan's default parent work, log and report directory
NULLSCAN_DIR = f'{os.getcwd()}/nullscan-{TODAY}'

# pydeps.txt
PYDEPS = f'{DOC_PATH}/pydeps.txt'


# EOF
