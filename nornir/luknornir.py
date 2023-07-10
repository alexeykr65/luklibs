#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Libs for get information from routers and switches
#
# alexeykr@gmail.com
# coding=utf-8
# import codecs
"""
Classes for get information from routers Cisco using Nornir
version: 1.0
@author: alexeykr@gmail.com
"""
import warnings
import re
import time
import yaml
import os
import maskpass
import yaml

import nornir
from nornir import InitNornir
from nornir.core.inventory import Inventory
from nornir.core.plugins.inventory import InventoryPluginRegister

from nornir_utils.plugins.functions import print_result
from nornir_scrapli.tasks import get_prompt, send_command, send_configs, send_commands
from nornir.core.filter import F
from rich.console import Console
from datetime import datetime, timedelta
from pathlib import Path

class LukNornir:
    """Class for get information from routers"""
    

    def __init__(self, user="", passw="", cfg_file="nornir.yaml", filter_roles="", filter_hosts="", filter_groups='all'):
        self.cons = Console()
        dt = LukNornir.get_cfg('nornir.yaml')
        self.user = dt['username']
        self.passw = passw
        if 'PASSW' in os.environ:
            self.passw = os.environ['PASSW']
        if user != "":
            self.user = user
        if passw != "":
            self.passw = passw
        if self.passw == "":
            self.passw = maskpass.askpass(prompt="Passw Nornir:", mask="#")

        self.result = ""
        self.failed_hst = []
        # self.cons = Console()
        self.nr = self.init_nornir() or ""
        self.router_hosts = self.nr.filter(F(groups__any=filter_groups.split(',')))
        if filter_hosts != "":
            self.router_hosts = self.router_hosts.filter(F(name__any=filter_hosts.lower().split(',')))

    def init_nornir(self) -> nornir.core.Nornir:
        # InventoryPluginRegister.register("LabInventory", MyLabInventory)
        nr = InitNornir(
            runner={
                "plugin": "threaded",
                "options": {
                    "num_workers": 20,
                },
            },
            inventory={
                "plugin": "SimpleInventory",
                "options": {
                    "host_file": "~/inventory/hosts.yaml",
                    "group_file": "~/inventory/groups.yaml",
                },
            },
        )
        nr.inventory.defaults.username = self.user
        nr.inventory.defaults.password = self.passw
        return nr

    # def get_config(self, task) -> None:
    #     """
    #     Get Configs from routers
    #     """
    #     cmd_config = "show running\n"
    #     task.run(task=send_commands, commands=cmd_config.split(','))

    def send_command(self, task) -> None:
        """
        Send to router commands
        """
        task.run(task=send_commands, commands=self.cmds.split(','))

    def filter_roles(self, host):
        ret = False
        if 'role' in host.data:
            ret = host.data["role"] in self._filter_roles
        return ret

    def run_tasks(self, cmds):
        self.cmds = cmds
        self.result = self.router_hosts.run(task=self.send_command)
        self.failed_hst = [i for i in self.result.failed_hosts]
        return self.result
        # search_mac_address(result=result)

    @classmethod
    def ipaddr(cls, input_str, net_cfg):
        ip_net = IPNetwork(input_str)
        ret = ''
        if net_cfg == 'address':
            ret = ip_net.ip
        elif net_cfg == 'netmask':
            ret = ip_net.netmask
        elif net_cfg == 'hostmask':
            ret = ip_net.hostmask
        elif net_cfg == 'network':
            ret = ip_net.network
        return ret

    @classmethod
    def getdate(cls):
        '''
        This function returns a tuple of the year, month and day.
        '''
        # Get Date
        now = datetime.now()
        day = str(now.day)
        month = str(now.month)
        year = str(now.year)
        hour = str(now.hour)
        minute = str(now.minute)
        if len(day) == 1:
            day = '0' + day
        if len(month) == 1:
            month = '0' + month
        filebits = [year, month, day, hour, minute]
        return '-'.join(filebits)
    
    @staticmethod
    def get_cfg(fl):
        cfg_file = Path(Path.home(), f'inventory/{fl}')
        if cfg_file.exists():
            with open(cfg_file, 'r') as file:
                load_cfg = yaml.safe_load(file)
        return load_cfg

    def print_title_host(self, title_txt, flag_center=False) -> None:
        ln = len(title_txt)
        lf = int((80 - ln) / 2)
        rf = int(80 - ln - lf)
        if flag_center:
            cons.print("*" * lf, f' [magenta]{title_txt}', "*" * rf)
        else:
            cons.print(f' [magenta]{title_txt}')
    
    def print_body_result(self, body_txt, bg='') -> None:
        self.cons.print(f'[white]{body_txt}')
        self.cons.print("*" * 83, style="yellow")

    def display_result(self, skip_empty=False, view_res=True, srch=""):
        if view_res:
            for i, ival in self.result.items():
                chk_res = ["OK" for j in ival if j.result]
                if "OK" not in chk_res:
                    continue
                if i in self.failed_hst:
                    continue
                if srch != "":
                    self.print_title_host(f'{i.upper()}', flag_center=True)
                # bpdb.set_trace()
                for jval in ival:
                    if jval.result:
                        if srch:
                            if re.search(srch, jval.result, re.IGNORECASE):
                                self.cons.print("*" * 83, style="yellow")
                                self.print_title_host(f'{i.upper()}', flag_center=True)
                            for st in jval.result.split("\n"):
                                if re.search(srch, st, re.IGNORECASE):
                                    self.cons.print(f'[white]{st}')
                            # console.print("*" * 83, style = "yellow")
                        else:
                            self.print_body_result(str(jval.result).strip('\n'))
        self.cons.print(f'\nFailed hosts: {",".join(self.failed_hst)} Total hosts: {len(self.result)}')
     

    # print(args.hst)
    # bpdb.set_trace()
    # if args.run:
    #     logger.debug("Get running configuration ...")
    #     print_title_host(f'Get Configuration', flag_center=True)
    #     result = router_hosts.run(task=get_config)
    #     save_configs(result=result)

    # if args.mac:
    #     logger.debug("Get information about mac ...")
    #     result = router_hosts.run(task=send_command)
    #     search_mac_address(result=result)

    # if args.logs:
    #     logger.debug("Get Logs ...")
    #     result = router_hosts.run(task=send_command)
    #     analyze_logs(result=result)
    #     # save_cmds(result=result)

    # if args.inv:
    #     logger.debug("Get inventory ...")
    #     result = router_hosts.run(task=send_command)
    #     save_inventory(result=result)

    # if args.cmd:
    #     logger.debug("Send commands ...")
    #     # print_title_host(f'Send command', flag_center=True)
    #     result = router_hosts.run(task=send_command)
    #     save_cmds(result=result)

    # if args.hw:
    #     logger.debug("Send commands ...")
    #     # print_title_host(f'Send command', flag_center=True)
    #     result = router_hosts.run(task=send_command)
    #     huawei_traffic_policy(result=result)

    def filter_hosts(self, host):
        return str(host).lower() in self._filter_hosts

    @property
    def ospf_filter(self):
        return self._ospf_filter

    @ospf_filter.setter
    def ospf_filter(self, val):
        self._ospf_filter = val

    @property
    def nor(self):
        return self._nor

    @property
    def load_data(self):
        return self._load_data

    def get_config(self):
        res = self._nor.run(task=self.run_cmds_task, cmds='show run')
        for i in res:
            to_file = ""
            self.print_title_host(f'{i}', flag_center=True)
            for j in range(1, len(res[i])):
                self.print_title_result(f'{res[i][j].name}')
                self.print_body_result(f'{str(res[i][j])}')
                to_file += f'{i}#{res[i][j].name}\n'
                to_file += f'{res[i][j]}\n\n\n'
            if self._save_to_file:
                self.write_to_file(i.lower(), to_file, flag_config=True)

    def get_cdp(self, out_dir=""):
        if out_dir:
            tmp_dir = self._output_dir
            self._output_dir = out_dir
        res = self._nor.run(task=self.run_cmds_task, cmds='show cdp nei deta')
        for i in res:
            to_file = ""
            self.print_title_host(f'{i}', flag_center=True)
            for j in range(1, len(res[i])):
                self.print_title_result(f'{res[i][j].name}')
                self.print_body_result(f'{str(res[i][j])}')
                to_file += f'{i}#{res[i][j].name}\n'
                to_file += f'{res[i][j]}\n\n\n'
            if self._save_to_file:
                self.write_to_file(i.lower(), to_file, flag_config=True)
        if out_dir:
            self._output_dir = tmp_dir

