#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Get Information from Huawei NCE Fabric
#
# alexeykr@gmail.com
# coding=utf-8

import requests
import json
import re
from rich.console import Console
from rich.table import Table
from rich import box
from pathlib import Path
from collections import defaultdict
from ciscoconfparse import CiscoConfParse
from ipaddress import IPv4Network
from luklibs.nornir.luknornir import LukNornir

description = "Get information from Huawei NCE Fabric"

STAT = {0: 'ON', 1: 'OFF', 2: 'HU'}
LINKSTAT = {0: 'UP', 1: 'DOWN', 4: 'UNKNOWN'}
LINKMODE = {0: 'INTERNAL', 1: 'EXTERNAL', 3: 'INT_EXT', 4: 'COMMON'}


class NCE:
    def __init__(self, URL, login, password, raw=False) -> None:
        self.cons = Console()
        self.raw = raw
        self.URL = URL
        self.login = login
        self.password = password
        self.headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        self.token = self._get_token()
        self.headers['X-ACCESS-TOKEN'] = self.token
        self._dev_group = dict()
        self._dev_list = dict()
        self._dev_id = dict()
        self._links = dict()
        self._endports = dict()
        self._host_links = dict()
        self._ports = dict()
        self._switches = dict()
        self._epg = dict()
        self._routers_id = dict()
        self._routers = dict()

    def _get_token(self):
        url = f"{self.URL}/controller/v2/tokens"
        payload = {"userName": self.login, "password": self.password}
        requests.packages.urllib3.disable_warnings()
        response = requests.post(url, data=json.dumps(payload), headers=self.headers, verify=False).json()
        return response['data']['token_id']

    def get_url(self, url, http_method='get', payload={}):
        url = f"{self.URL}{url}"
        requests.packages.urllib3.disable_warnings()
        if http_method == 'get':
            response = requests.get(url, headers=self.headers, verify=False)
        if http_method == 'post':
            response = requests.post(url, data=json.dumps(payload), headers=self.headers, verify=False)
        if response.status_code != 200:
            print(f"Error return http code: {response.status_code}")
            return None
        return response.json()

    def raw_json_print(self, s):
        if self.raw:
            print(json.dumps(s, indent=4))

    def get_dev_group(self):
        url = f"/acdcn/v3/topoapi/dcntopo/devicegroup"
        self._dev_group = self.get_url(url)

    def get_devices(self):
        url = f"/acdcn/v3/topoapi/dcntopo/device"
        self._dev_list = self.get_url(url)
        self._dev_id = {k['id']: k for k in self._dev_list['devices']}

    def get_host_links(self):
        url = f"/acdcn/v3/topoapi/dcntopo/getHostlinks"
        self._host_links = self.get_url(url, http_method='post')

    def get_links(self):
        url = f"/acdcn/v3/topoapi/dcntopo/getLinks"
        self._links = self.get_url(url, http_method='post')

    def get_endports(self):
        self.get_logic_sw()
        url = "/controller/dc/v3/logicnetwork/logictopo/endport"
        self._endports = self.get_url(url)
        self._endportsId = {k['id']: k for k in self._endports['endPort']}
        self._endportsName = defaultdict(lambda: list())
        for k in self._endports['endPort']:
            k['log_sw'] = self._switches_id[k['belongInfo']['logicSwitchId']]
            k['con_dev'] = [i['deviceName'] for i in k['connectPort']]
            self._endportsName[k['vmName']].append(k)

    def get_ports(self):
        url = "/controller/dc/v3/logicnetwork/logictopo/port-map"
        self._ports = self.get_url(url)

    def get_logic_ports(self):
        url = "/controller/dc/v3/logicnetwork/ports"
        self._logic_ports = self.get_url(url)
        self._logic_ports_id = {k['id']: k for k in self._logic_ports['port']}

    def get_logic_sw(self):
        url = "/controller/dc/v3/logicnetwork/switchs"
        self._switches = self.get_url(url)
        self._switches_id = {k['id']: k for k in self._switches['switch']}

    def get_logic_routers(self):
        url = "/controller/dc/v3/logicnetwork/routers"
        self._routers = self.get_url(url)
        self._routers_id = {k['id']: k for k in self._routers['router']}

    def get_fabrics(self):
        url = "/controller/dc/v3/physicalnetwork/fabricresource/fabrics"
        self._fabrics = self.get_url(url)
        self._fabrics_id = {k['id']: k for k in self._fabrics['fabric']}

    def get_interfaces(self):
        url = "/controller/dc/v3/logicnetwork/interfaces"
        self._interfaces = self.get_url(url)
        self._interfaces_id = {k['id']: k for k in self._interfaces['interface']}

    def get_networks(self):
        url = "/controller/dc/v3/logicnetwork/networks"
        self._networks = self.get_url(url)
        self._networks_id = {k['id']: k for k in self._networks['network']}

    def get_epg(self):
        url = "/controller/dc/v3/sfco/epgs"
        self._epg = self.get_url(url)

    def get_subnets(self):
        url = "/controller/dc/v3/logicnetwork/subnets"
        self._subnets = self.get_url(url)

    def run_dep_routines(self, dep):
        for p in dep:
            p()

    def epg_print(self, flt):
        self.run_dep_routines([self.get_logic_sw, self.get_logic_routers, self.get_interfaces, self.get_networks, self.get_epg])
        self.raw_json_print(self._epg)
        lst_epg = defaultdict(lambda: list())
        for j in self._epg['epg']:
            lst_epg[j['routerId']].append(j)
        fields = {
            'Name EPG': 'name',
            'Description': 'description',
            'logicNetworkName': 'logicNetworkId',
            'Type': 'type',
            'Items of Type': 'item',
            'epgTermAttr': 'epgTerminalAttr',
            'mode': 'mode',
        }
        for j, val in sorted(lst_epg.items()):
            tbl = Table(
                title=f"\n\n[green]======>> [magenta]Router Name: [bold white]{self._routers_id[j]['name']}[/bold white][/magenta] <<======[/green]",
                show_lines=True,
            )

            tbl.box = box.DOUBLE

            for i in fields:
                tbl.add_column(i)
            for i in val:
                lst_raw = list()
                for k, kv in fields.items():
                    if kv == 'item':
                        if i['type'] == 'SWITCH':
                            lst_raw.append('\n'.join([self._switches_id[l['itemId']]['name'] for l in i[kv]]))
                        elif i['type'] == 'INTERFACE':
                            lst_raw.append('\n'.join([self._interfaces_id[l['itemId']]['name'] for l in i[kv]]))
                        else:
                            lst_raw.append('\n'.join([l['itemId'] for l in i[kv]]))
                    elif kv == 'logicNetworkId':
                        lst_raw.append(self._networks_id[i[kv]]['name'])
                    else:
                        lst_raw.append(str(i[kv]))
                tbl.add_row(*lst_raw)
            self.cons.print(tbl)

    def networks_print(self, flt):
        self.run_dep_routines([self.get_fabrics, self.get_networks])
        self.raw_json_print(self._networks)
        lst_log_net = {j['name']: j for j in self._networks['network']}
        fields = {'Name': 'name', 'Description': 'description', 'VNI': 'vni', 'BridgeID': 'bd', 'Net': 'subnets'}
        for j, val in sorted(lst_log_net.items()):
            tbl = Table(title=j, show_lines=True)
            tbl.box = box.DOUBLE
            tbl.add_column("Name Parameter")
            tbl.add_column("Value Parameter")
            if len([True for i in flt if re.search(i, j)]) == 0 and len(flt) > 0:
                continue
            for k in val:
                tbl.add_row(k, str(val[k]))
            self.cons.print(tbl)

    def logic_sw_print(self, flt):
        self.run_dep_routines([self.get_logic_sw])
        self.raw_json_print(self._switches)
        lst_log_sw = {j['name']: j for j in self._switches['switch']}
        fields = {'Name': 'name', 'Description': 'description', 'VNI': 'vni', 'BridgeID': 'bd', 'Net': 'subnets'}
        tbl = Table(title=f"Total switches: {len(lst_log_sw)}", show_lines=True)
        tbl.box = box.DOUBLE
        for f in fields:
            tbl.add_column(f)
        for j, val in sorted(lst_log_sw.items()):
            if len([True for i in flt if re.search(i, j)]) == 0 and len(flt) > 0:
                continue
            tb_raw = [str(val[fv]) for f, fv in fields.items()]
            tbl.add_row(*tb_raw)
        self.cons.print(tbl)

    def get_logic_net_by_switch_id(self, lsw):
        log_net = self._networks_id[self._switches_id[lsw]['logicNetworkId']]['name']
        return log_net


    def ports_print(self, flt, log_net="all"):
        self.run_dep_routines([self.get_devices, self.get_logic_ports, self.get_logic_sw, self.get_networks, self.get_endports, self.get_ports])
        lst_switches = {j['logicSwitchName']: [j['bridgeDomainId'], self.get_logic_net_by_switch_id(j['logicSwitchId'])] for j in self._ports['port']}
        fields = {'NamePort': 'name', 'VLAN': 'vlan', 'PhysicalPort': 'physicalPortlist', 'EndPorts': 'endPort'}
        self.raw_json_print(self._ports)
        for j, val in sorted(lst_switches.items()):
            if log_net != "all" and not re.search(log_net, val[1], re.IGNORECASE):
                continue
            if len([True for i in flt if re.search(i, j, re.IGNORECASE)]) == 0 and len(flt) > 0:
                continue
            filter_ports = [i for i in self._ports['port'] if i['logicSwitchName'] == j]
            tbl = Table(
                title=f"\n[magenta]BridgeID: [bold white]{val[0]}[/bold white] LogicSwitch: [bold white]{j}[/bold white] NET: [bold white]{val[1]}[/bold white][/magenta]",
                show_lines=True,
                title_justify='left',
            )
            tbl.box = box.DOUBLE
            for f in fields:
                tbl.add_column(f)
            for i in filter_ports:
                phys_ports = "\n".join(
                    [f"{self._dev_id[k['deviceId']]['name']} {k['ifname']} {k['ifstatus']} {k['devicePortName']}" for k in i[fields['PhysicalPort']]]
                )
                end_ports = "\n".join(
                    [f"{self._endportsId[k['endPortId']]['vmName']} {k['endPortIp']} {self._endportsId[k['endPortId']]['mac']}" for k in i[fields['EndPorts']]]
                )
                name_port = i[fields['NamePort']]
                vlan = ""
                vlan = str(self._logic_ports_id[i['id']]['accessInfo']['vlan'])
                if len(name_port) > 30:
                    name_port = f"{name_port[0:30]}\n{name_port[30:]}"
                tbl.add_row(f"{name_port}", vlan, phys_ports, end_ports)
            self.cons.print(tbl)

    def end_ports_print(self, flt=[]):
        self.run_dep_routines([self.get_logic_sw, self.get_endports])
        self.raw_json_print(self._endports)
        fields = ['name', 'vmName', 'vmmName', 'hostName', 'type', 'mac', 'vlan', 'ip', 'status', 'updateTime']
        fields_belong = ['logicRouterName', 'vpcName', 'tenantName', 'producer']
        fields_switches = {'LogSwitchName': 'name', 'LogSwitchBD': 'bd', 'LogSwitchVNI': 'vni', 'LogSwitchDesc': 'description'}
        total_num = self._endports['totalNum']

        for rec in self._endports['endPort']:
            if len([True for i in flt if re.search(i, rec['vmName'])]) == 0 and len(flt) > 0:
                continue
            if self.raw:
                self.cons.print(json.dumps(rec, indent=4))
            tbl = Table(title=f"\n\n[green]======>> [magenta]VM Name: [bold white]{rec['vmName']}[/bold white][/magenta] <<======[/green]", show_lines=True)
            tbl.box = box.DOUBLE
            tbl.add_column("Name Parameter")
            tbl.add_column("Value Parameter")
            for f in fields:
                tbl.add_row(f"[bold cyan]{(f[0].upper()+f[1:]):20s}", f"{rec[f]}")
            sw = self._switches_id[rec['belongInfo']['logicSwitchId']]
            for f, val in fields_switches.items():
                tbl.add_row(f"[bold cyan]{f:20s}", f"{sw[val]}")
            for f in fields_belong:
                tbl.add_row(f"[bold cyan]{(f[0].upper()+f[1:]):20s}", f"{rec['belongInfo'][f]}")
            self.cons.print(tbl)
            table = Table(title=f"\nFound Physical Ports: {len(rec['connectPort'])}", show_lines=True)
            table.box = box.DOUBLE
            table.add_column("deviceName", justify="center")
            table.add_column("devicePortName", justify="center")
            table.add_column("ifName", justify="center")
            table.add_column("ip", style='green', justify="center")
            for i in rec["connectPort"]:
                table.add_row(i["deviceName"], i["devicePortName"], i["ifName"], i["deviceIp"])
            self.cons.print(table)

    def links_print(self):
        fields = [
            'Trunk',
            'Status',
            'Mode',
            'LocName',
            'LocPort',
            'Loc_IP',
            'RemName',
            'RemPort',
            'RemIP',
        ]
        self.run_dep_routines([self.get_devices, self.get_links])

        table = Table(title=f"Found Links: {len(self._links['links'])}", show_lines=True)
        for f in fields:
            table.add_column(f)

        for i in self._links["links"]:
            table.add_row(
                str(i["trunk"]),
                LINKSTAT[i["status"]],
                LINKMODE[i["mode"]],
                self._dev_id[i['localNode']['deviceId']]['name'],
                i["localNode"]["port"],
                i["localNode"]["deviceIp"],
                self._dev_id[i['peerNode']['deviceId']]['name'],
                i["peerNode"]["port"],
                i["peerNode"]["deviceIp"],
            )
        self.cons.print(table)

    def hostLinks_switches_print(self):
        self.run_dep_routines([self.get_devices, self.get_host_links])
        self.raw_json_print(self._host_links)
        tbl = list(set([self._dev_id[j["switchId"]]["name"] for j in self._host_links["linkList"] if j["hostName"] != None]))
        fields = [
            'hostName',
            'switchPortName',
            'hostMac',
        ]
        hst_name = {}
        hst_name["NO_NAME"] = []
        for k in self._host_links["linkList"]:
            if k["hostName"]:
                if k["hostName"] not in hst_name:
                    hst_name[k["hostName"]] = []
                    hst_name[k["hostName"]].append(k)
                elif k["hostName"] in hst_name:
                    hst_name[k["hostName"]].append(k)
            else:
                hst_name["NO_NAME"].append(k)
        print(f"Total links: {self._host_links['totalNum']}")
        print(f"Count names hosts: {len(hst_name)}")
        print(f"{len(hst_name['NO_NAME'])}")
        swlist = list(set([self._dev_id[j["switchId"]]["name"] for j in hst_name['NO_NAME']]))
        for j in sorted(tbl):
            hst_lnks_dup = [k for k in self._host_links["linkList"] if self._dev_id[k["switchId"]]["name"] == j]
            hst_lnks = {}
            for k in hst_lnks_dup:
                if k["switchPortName"] not in hst_lnks:
                    hst_lnks[k["switchPortName"]] = k
                elif k["switchPortName"] in hst_lnks and k["hostName"] != None:
                    hst_lnks[k["switchPortName"]]["hostName"] = k["hostName"]

            table = Table(
                title=f"\n\n[green]======>> [magenta]Switch Name: [bold white]{j}[/bold white] Total: [bold white]{len(hst_lnks)}[/bold white][/magenta] <<======[/green]",
                show_lines=True,
            )
            for f in fields:
                table.add_column(f)
            for i, val in hst_lnks.items():
                table.add_row(val["hostName"], val["switchPortName"], val['hostMac'])
            self.cons.print(table)

    def hostLinks_print(self):
        self.run_dep_routines([self.get_devices, self.get_host_links])
        self.raw_json_print(self._host_links)
        tbl = list(set([j["hostName"] for j in self._host_links["linkList"] if j["hostName"] != None]))
        print(f"{tbl} == {len(tbl)}")
        fields = [
            'linkId',
            'switchId',
            'switchPortName',
            'trunkName',
            'hostMac',
        ]

        for j in sorted(tbl):
            table = Table(title=f"\n\n[green]======>> [magenta]Host Name: [bold white]{j}[/bold white][/magenta] <<======[/green]", show_lines=True)
            for f in fields:
                table.add_column(f)

            hst_lnks = [k for k in self._host_links["linkList"] if k['hostName'] == j]
            for i in hst_lnks:
                table.add_row(i["linkId"], self._dev_id[i["switchId"]]["name"], i["switchPortName"], i["trunkName"], i['hostMac'])
            self.cons.print(table)

    def dev_group_print(self):
        lst_type = list(set([j['type'] for j in self._dev_group['deviceGroups'] if j['type'] != ""]))
        for j in sorted(lst_type):
            dev_total = len([i for i in self._dev_group['deviceGroups'] if i['type'] == j])
            table = Table(title=f"\n\n[green]======>> {j} Group Type Devices: {dev_total} <<======", show_lines=True)
            table.add_column("PoolId")
            table.add_column("Id")
            table.add_column("Name")
            table.add_column("Type")
            table.add_column("Description")
            table.add_column("Device")

            for i in self._dev_group["deviceGroups"]:
                if i['type'] == j:
                    table.add_row(
                        i["poolId"],
                        i["id"],
                        i["name"],
                        i["type"],
                        i["description"],
                        ' '.join(i["device"]),
                    )
            self.cons.print(table)

    def dev_print_by_type(self):
        self.run_dep_routines([self.get_devices])
        lst_type = list(set([j['type'] for j in self._dev_list['devices'] if j['type'] != ""]))
        for j in sorted(lst_type):
            dev_total = len([i for i in self._dev_list['devices'] if i['type'] == j])
            table = Table(title=f"\n\n[green]======>> {j} Type Devices: {dev_total} <<======", show_lines=True)
            table.add_column("id")
            table.add_column("Name")
            table.add_column("Loc")
            table.add_column("ip")
            table.add_column("Stat")
            table.add_column("MAC")
            table.add_column("Model")
            table.add_column("vtepIp")
            for i in self._dev_list["devices"]:
                if i['type'] == j:
                    table.add_row(
                        i["id"],
                        i["name"],
                        i["location"],
                        i["ip"],
                        STAT[i['status']],
                        i["mac"],
                        i["mode"],
                        i["vtepIp"],
                    )
            self.cons.print(table)
            self.cons.print(f"Total device: {len(self._dev_list['devices'])}")

    def huawei_traffic_policy(self, result):
        failed_hst = [i for i in result.failed_hosts]
        assert failed_hst != 0, "Connect to hosts failed !"
        for i, ival in result.items():
            if i.lower() not in failed_hst:
                for h, hval in hst_huawei.items():
                    self.get_info_traffic_policy(sw_cfg=[j for j in ival[1].result.split('\n')], intrf=f"Vbdif{hval[0]['log_sw']['bd']}")

    def get_host_tp(self, hst="", user="", pwd=""):
        assert hst != "", "Name of host is empty !!!"
        self.get_endports()
        hst_huawei = {i: val for i, val in self._endportsName.items() if re.search(hst, i)}
        lst_sw = list()
        for vm, vmval in hst_huawei.items():
            for hs in vmval:
                lst_sw.extend(hs['con_dev'])
        print(f"Host Connected to: {' '.join(lst_sw)}")
        luk = LukNornir(filter_hosts=','.join(lst_sw), user=user, passw=pwd)
        res = luk.run_tasks("dis cur")
        failed_hst = [i for i in res.failed_hosts]
        assert failed_hst != 0, "Connect to hosts failed !"
        for i, ival in res.items():
            if i.lower() not in failed_hst:
                for h, hval in hst_huawei.items():
                    self.get_info_traffic_policy(sw_cfg=[j for j in ival[1].result.split('\n')], intrf=f"Vbdif{hval[0]['log_sw']['bd']}")

    def get_info_traffic_policy(self, intrf="", sw_cfg=""):
        assert intrf != "" and sw_cfg != "", "Interface and Config are empty"
        interface_name = intrf
        conf_intrf = dict()
        parse = CiscoConfParse(sw_cfg)
        prs = parse.find_objects(f"^interface\s{interface_name}")[0]
        conf_intrf[interface_name] = list()
        for i in prs.children:
            conf_intrf[interface_name].append(i.text)
            chk = re.compile(r'\straffic-policy\s(.*)\sinbound')
            res = chk.match(i.text)
            if res:
                tp = res.groups()[0]
        prs = parse.find_objects(f"^traffic policy {tp}")[0]
        classif = dict()
        for i in prs.children:
            chk = re.compile(r'^\sclassifier\s(.*)\sbehavior\s(.*)\sprecedence\s(\d+)$')
            res = chk.match(i.text)
            if res:
                classif[int(res.groups()[2])] = {
                    'classif': res.groups()[0],
                    'behav': res.groups()[1],
                    'acl': list(),
                    'acl_rules': list(),
                    'behav_rules': list(),
                }
        for j, val in classif.items():
            srch = str(val['classif']).replace('+', '\\+')
            prs = parse.find_objects(f"^traffic classifier {srch}")
            if len(prs) == 0:
                continue
            prs = prs[0]
            for i in prs.children:
                chk = re.compile(r'^\sif-match\sacl\s(.*)$')
                res = chk.match(i.text)
                if res:
                    classif[j]['acl'].append(res.groups()[0])
        for j, val in classif.items():
            for f in val['acl']:
                srch = str(f).replace('+', '\\+')
                prs = parse.find_objects(f"^acl\sname\s{srch}\sadvance")
                assert len(prs) != 0, "Check progamm, did not find object !!!"
                prs = prs[0]
                for i in prs.children:
                    rules = i.text.split()
                    del rules[2:4]
                    ips = rules[5:7]
                    nets = IPv4Network(f"{ips[0]}/{ips[1]}")
                    netd = ""
                    if len(rules) > 7:
                        ipd = rules[8:11]
                        netd = IPv4Network(f"{ipd[0]}/{ipd[1]}")
                        netd = f"{rules[7]} {str(netd)}"
                    acl_parse = f"{' '.join(rules[0:5])} {str(nets)} {netd}"
                    classif[j]['acl_rules'].append(acl_parse)
        for j, val in classif.items():
            srch = str(val['behav']).replace('+', '\\+')
            prs = parse.find_objects(f"^traffic\sbehavior\s{srch}")
            assert len(prs) != 0, "Check progamm, did not find object !!!"
            prs = prs[0]
            for i in prs.children:
                classif[j]['behav_rules'].append(i.text.strip())
        s_child = ' \n'.join(conf_intrf[interface_name])
        s = f"interface {interface_name}\n{s_child}"
        self.cons.print(s)

        for j, val in classif.items():
            tbl = Table(title=f"\n[magenta]Precedence: [bold white]{j}[/bold white][/magenta]", show_lines=True, title_justify='left')
            tbl.box = box.DOUBLE
            tbl.add_column("Name Parameter")
            tbl.add_column("Value Parameter")
            tbl.add_row("ACL RULES", '\n'.join(val['acl_rules']))
            tbl.add_row("BEHAVIOR", '\n'.join(val['behav_rules']))
            self.cons.print(tbl)
