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
# html.py                                                                      #
#                                                                              #
# AUTHOR                                                                       #
# noptrix@nullsecurity.net                                                     #
#                                                                              #
################################################################################


# sys imports
import os
import html


# own imports
from core.constants import *
from core.error import Error
from core.file import File
from modules.libs.helper import Helper


class HTML:
  """ class for HTML reporting """


  def __init__(self, date, opts, template_dir, report_dir, logs_dir):
    """ constructor """

    self.date = date
    self.opts = opts
    self.res = {}       # holds the results out of log dirs

    self.template_dir = template_dir
    self.report_dir = report_dir
    self.logs_dir = logs_dir

    self.file = File()

    self.file.copy_dirs(self.template_dir, self.report_dir)
    self.index_html = f'{self.report_dir}/index.html'
    self.res_html = f'{self.report_dir}/results.html'
    self.index_html_data = self.file.read_file(self.index_html)
    self.res_html_data = self.file.read_file(self.res_html)

    return


  def make_results(self):
    """ get all results from the targets log directory """

    logs = f'{self.logs_dir}/targets/'

    targets = os.listdir(logs)
    for target in targets:
      target_orig = target
      if ':' in target:
        target = target.replace(':', '-')
      self.res[target] = {}
      for moddir in os.listdir(logs + target_orig):
        if moddir in ('tcp', 'udp', 'social'):
          submods = os.listdir(f'{logs}{target_orig}/{moddir}')
          for s in submods:
            for modname in os.listdir(f'{logs}{target_orig}/{moddir}/{s}'):
              if moddir == 'tcp' or moddir == 'udp':
                module = f'{moddir}.{s}.{modname}'
              else:
                module = f'{moddir}.{modname}'
              self.res[target][module] = {}
              tool_path = f'{logs}{target_orig}/{moddir}/{s}/{modname}/'
              for tool in os.listdir(tool_path):
                if '.log' in tool:
                  self.res[target][module][tool] = \
                    '\n'.join(self.file.read_file(tool_path + tool))
        else:
          for modname in os.listdir(f'{logs}{target_orig}/{moddir}'):
            target = target.replace(':', '-') # url port
            module = f'{moddir}.{modname}'
            self.res[target][module] = {}
            for tool in os.listdir(f'{logs}{target_orig}/{moddir}/{modname}'):
              if '.log' in tool and '.bin' not in tool:
                tool_path = f'{logs}{target_orig}/{moddir}/{modname}/'
                self.res[target][module][tool] = '\n'.join(self.file.read_file(
                  tool_path + tool))

    return


  def make_target_html(self):
    """ create $target.html with its contents/results """

    _mods = ''
    panels = []
    panel = '''
    <div class="panel panel-default">
      <div class="panel-heading">
        <h3 class="panel-title">$TOOL</h3>
      </div>
      <div class="panel-body">
        <pre>$RESULT</pre>
      </div>
    </div>
    '''

    for target, mods in self.res.items():
      t_html = f'{self.report_dir}/{target}.html'
      self.file.copy_files(self.res_html, t_html)
      t_html_data = self.file.read_file(t_html)
      t_html_data = [w.replace('$TARGET', target) for w in t_html_data]
      self.file.write_file(t_html, ' '.join(t_html_data))
      for mod, tools in mods.items():
        _mods += f'<h5>{mod}</h5>'
        for tool, data in tools.items():
          tlink = tool.split('.log')[0]
          link = f'{mod}.{tlink}'
          _mods += f'<a href="#{link}" target="_blank">{tlink}</a><br />'
          p1 = panel.replace(f'$TOOL', f'<a name="{link}">{link}</a>')
          p2 = p1.replace('$RESULT', html.escape(data))
          panels.append(p2)
      t_html_data = [w.replace('$ALLMODS', _mods) for w in t_html_data]
      _mods = ''
      t_html_data = [w.replace('$CONTENT', ' '.join(panels)) \
        for w in t_html_data]
      panels = []

      self.file.write_file(t_html, ' '.join(t_html_data))

    return


  def make_index_html(self):
    """ create the index.html """

    num_social_targets = 0
    patterns = {
      '$DATE': self.date,
      '$CMDLINE_ARGS': ' '.join(self.opts['cmdline'])
    }

    # index.html: date + cmdline args
    for k, v in patterns.items():
      self.index_html_data = [w.replace(k, v) for w in self.index_html_data]

    # index.html: num target modes
    for k, v in self.opts['targets'].items():
      if k == 'social':
        for s in self.opts['targets'][k]:
          if self.opts['targets'][k][s]:
            num_social_targets += len(self.opts['targets'][k][s])
        self.index_html_data = [w.replace('$NUM_SOCIAL',
          str(num_social_targets)) for w in self.index_html_data]
      self.index_html_data = [w.replace(f'$NUM_{k.upper()}', str(len(v))) \
        for w in self.index_html_data]

    return


  def make_menu(self, mod, targets):
    """ create the menu and links """

    # targets menu items
    if mod == 'tcp' or mod == 'udp':
      l = []
      for target in self.opts['targets'][mod]:
        target = f"<li><a href='{target['host']}.html'>{target['host']}</a></li>"
        l.append(target)
      self.index_html_data = [
        w.replace(f'$TARGETS_{mod.upper()}', ' '.join(l)) \
        for w in self.index_html_data
      ]
      self.res_html_data = [
        w.replace(f'$TARGETS_{mod.upper()}', ' '.join(l)) \
        for w in self.res_html_data
      ]
    elif mod == 'social':
      l = []
      for part in self.opts['targets'][mod]:
        for target in self.opts['targets'][mod][part]:
          target = f'<li><a href="{target}.html">{target}</a></li>'
          l.append(target)
      self.index_html_data = [
        w.replace(f'$TARGETS_{mod.upper()}', ' '.join(l)) \
        for w in self.index_html_data
      ]
      self.res_html_data = [
        w.replace(f'$TARGETS_{mod.upper()}', ' '.join(l)) \
        for w in self.res_html_data
      ]
    else:
      for target in targets:
        if '://' in target:
          target = target.split('://')[1].rstrip('/').split('/')[0]
        if ':' in target:
          target = target.replace(':', '-') # port
        target = f'<li><a href="{target}.html">{target}</a></li>'
        self.index_html_data = [
          w.replace(f'$TARGETS_{mod.upper()}', target) \
          for w in self.index_html_data
        ]
        self.res_html_data = [
          w.replace(f'$TARGETS_{mod.upper()}', target) \
          for w in self.res_html_data
        ]

    return


  def make_report(self):
    """ make the report """

    self.make_results()

    for mod, targets in self.opts['targets'].items():
      self.make_menu(mod, targets)
    self.make_index_html()

    self.file.write_file(self.index_html, ' '.join(self.index_html_data))
    self.file.write_file(self.res_html, ' '.join(self.res_html_data))

    self.make_target_html()
    self.file.del_file(f'{self.report_dir}/results.html')

    return


# EOF
