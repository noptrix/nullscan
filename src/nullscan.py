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
# nullscan                                                                     #
#                                                                              #
# AUTHOR                                                                       #
# noptrix@nullsecurity.net                                                     #
#                                                                              #
################################################################################


# sys imports
import warnings


# own imports
from core.usage import Usage
from core.controller import Controller
from core.logger import Logger
from core.misc import Misc


if __name__ == '__main__':
  try:
    warnings.simplefilter('ignore')
    Usage.banner()
    ctrl = Controller()
    misc = Misc()
    l = Logger()
    log = l.log
    ctrl.prepare()
    ctrl.run_misc()
    ctrl.start()
    ctrl.end()
  except:
    log('aborted', _type='err', exit=False, end='\n')
    # kill left nullscan processes if ctrl+c was hit. this is a dirty hack and it
    # it will be replaced later with semaphores or queues to have a nice
    # communication channel between each proc
    misc.kill_process('python*.*nullscan', 'KILL')


# EOF
