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
# from pathlib import Path
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
        # print(json.dumps(self.headers,indent=4))

    def _get_token(self):
        url = f"{self.URL}/controller/v2/tokens"
        payload = {"userName": self.login, "password": self.password}
        requests.packages.urllib3.disable_warnings()
        response = requests.post(url, data=json.dumps(payload), headers=self.headers, verify=False)
        assert response.status_code == 200, "Password or Login is wrong to access NCE Fabric"
        return response.json()['data']['token_id']

    def get_url(self, url, http_method='get', payload={}):
        url = f"{self.URL}{url}"
        # print(f"{url}")
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

    def get_dev_groups(self):
        url = f"/acdcn/v3/topoapi/dcntopo/devicegroup"
        self._dev_groups = self.get_url(url)

    def get_devices(self):
        url = f"/acdcn/v3/topoapi/dcntopo/device"
        self._dev_list = self.get_url(url)
        self._dev_id = {k['id']: k for k in self._dev_list['devices']}

    def get_host_links(self):
        url = f"/acdcn/v3/topoapi/dcntopo/getHostlinks"
        self._host_links = self.get_url(url, http_method='post')
        # print(f"{json.dumps(self._host_links, indent=4)}")

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
            # print(json.dumps(k, indent=4))

    def get_logic_ports_map(self):
        url = "/controller/dc/v3/logicnetwork/logictopo/port-map"
        self._ports = self.get_url(url)

    def get_logic_ports(self):
        url = "/controller/dc/v3/logicnetwork/ports"
        self._logic_ports = self.get_url(url)
        self._logic_ports_id = {k['id']: k for k in self._logic_ports['port']}

    def get_logic_ports_filter(self, sw_id):
        url = f"/controller/dc/v3/logicnetwork/ports?logicSwitchId={sw_id}"
        return self.get_url(url)

    def get_logic_ports_map_filter(self, sw_id):
        url = f"/controller/dc/v3/logicnetwork/logictopo/port-map?logicSwitchId={sw_id}"
        return self.get_url(url)

    def get_logic_sw(self):
        url = "/controller/dc/v3/logicnetwork/switchs"
        self._switches = self.get_url(url)
        self._switches_id = {k['id']: k for k in self._switches['switch']}
        # self.cons.print(json.dumps(self._switches, indent=4))

    def get_logic_routers(self):
        url = "/controller/dc/v3/logicnetwork/routers"
        self._routers = self.get_url(url)
        self._routers_id = {k['id']: k for k in self._routers['router']}
        # self.cons.print(json.dumps(self._switches, indent=4))

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
        self._epg_id = {k['id']: k for k in self._epg['epg']}

    def get_nqa(self):
        url = "/controller/dc/v3/track-nqas"
        self._nqa = self.get_url(url)
        self._nqa_id = {k['id']: k for k in self._nqa['TrackNqas']}

    def get_dhcp_group(self):
        url = "/controller/dc/v3/publicservice/dhcpgroups"
        self._dhcp_group = self.get_url(url)
        self._dhcp_group_id = {k['id']: k for k in self._dhcp_group['dhcpgroup']}

    def get_scapp(self):
        url = "/controller/dc/v3/sfco/vpcConnectPolicy"
        self._scapp = self.get_url(url)
        self._scapp_id = {k['id']: k for k in self._scapp['scapp']}

    def get_subnets(self):
        url = "/controller/dc/v3/logicnetwork/subnets"
        self._subnets = self.get_url(url)

    @staticmethod
    def run_dep_routines(dep):
        for p in dep:
            p()

    def table_column_print(self, fld, val, title=""):
        tbl = Table(title=title, show_lines=True, box=box.DOUBLE)
        tbl.add_column('NameParam')
        tbl.add_column('ValueParam')

        # if len([True for i in flt if re.search(i, j['name'],  re.IGNORECASE)]) == 0 and len(flt) > 0:
        #     continue
        for k, kv in fld.items():
            if isinstance(kv, dict):
                fld_src = kv['src']
                fld_dst = kv['dst']
                if val[fld_src]:
                    tbl.add_row(k, kv['query'][val[fld_src]][fld_dst])
            else:
                tbl.add_row(k, str(val[kv]))
        self.cons.print(tbl)

    def table_print(self, fld, val, title=""):
        tbl = Table(title=title, show_lines=True, box=box.DOUBLE)
        for i in fld:
            tbl.add_column(i)
        for l in val:
            lst_raw = list()
            for k, kv in fld.items():
                if isinstance(kv, dict):
                    fld_src = kv['src']
                    fld_dst = kv['dst']
                    if l[fld_src]:
                        dd = kv['query'][l[fld_src]][fld_dst]
                    else:
                        dd = ""
                    lst_raw.append(str(dd))
                else:
                    lst_raw.append(str(l[kv]))
            tbl.add_row(*lst_raw)
        self.cons.print(tbl)

    def scapp_print(self, flt):
        self.run_dep_routines([self.get_scapp, self.get_epg, self.get_networks])
        fields = {
            'name': 'name',
            'Descr': 'description',
            # 'mode': 'mode',
            # 'srcAppId': 'srcAppId',
            # 'dstAppId': 'dstAppId',
            'srcEpgName': {'src': 'srcEpgId', 'query': self._epg_id, 'dst': 'name'},
            'srcEpgType': {'src': 'srcEpgId', 'query': self._epg_id, 'dst': 'type'},
            'dstEpgName': {'src': 'dstEpgId', 'query': self._epg_id, 'dst': 'name'},
            'dstEpgType': {'src': 'dstEpgId', 'query': self._epg_id, 'dst': 'type'},
            'Action': 'filterAction',
            'Direct': 'filterDirection',
            'ConId': 'contractId',
        }
        fields_rules = {
            'Action': 'behavior',
            'Order': 'order',
            'SrcIp': 'sourceIp',
            'DestIp': 'destinationIp',
            'Prot': 'protocol',
            'Direct': 'direction',
        }

        fields_sfps = {
            'Num': 'hopNumber',
            'Type': 'sfType',
            'failMode': 'failMode',
            'detectionMode': 'detectionMode',
        }

        for i in self._scapp['scapp']:
            netId = self._networks_id[i['logicNetworkId']]['name']
            if len([True for i in flt if re.search(i, netId, re.IGNORECASE)]) == 0 and len(flt) > 0:
                continue

            title = (
                f"\n\n[green]======>> [magenta]SFC APP: [bold white]{i['name']} [/bold white]NetName: [bold white]{netId}[/bold white][/magenta] <<======[/green]"
            )
            self.cons.rule(title, align='left', characters="=")
            # self.table_column_print(title="", fld=fields, val=i)
            self.table_print(fld=fields, val=[i])

            if i['rules']:
                rules = list()
                for j in i['rules']:
                    rule = dict()
                    rule['behavior'] = j['behavior']
                    rule['order'] = str(j['order'])
                    rule.update(j['classifier'])
                    rules.append(rule)
                self.table_print(title=f"Rules: {len(i['rules'])}", fld=fields_rules, val=rules)

            if i['sfp']['sfPathHop']:
                self.table_print(title=f"SFP Paths: {len(i['sfp']['sfPathHop'])}", fld=fields_sfps, val=i['sfp']['sfPathHop'])

    def nqa_print(self, flt):
        self.run_dep_routines([self.get_nqa])
        fields = {
            'name': 'name',
            'srcDeviceGroupName': 'srcDeviceGroupName',
            'destDeviceGroupName': 'destDeviceGroupName',
            'adminName': 'adminName',
            'testName': 'testName',
            'isAutoLinked': 'isAutoLinked',
            'status': 'status',
        }

        title = f"\n\n[green]======>> [magenta]NQA Total: [bold white]{len(self._nqa['TrackNqas'])}[/bold white][/magenta] <<======[/green]"
        self.table_print(title=title, fld=fields, val=self._nqa['TrackNqas'])

    def dhcp_group_print(self, flt):
        self.run_dep_routines([self.get_dhcp_group, self.get_logic_routers])
        fields = {
            'Name': 'name',
            'Router': {'src': 'logicRouterId', 'query': self._routers_id, 'dst': 'name'},
            'VRF': 'vrfName',
            'ServerIp': 'serverIp',
            'DhcpGroupL2VNI': 'dhcpgroupl2vni',
        }

        title = f"\n\n[green]======>> [magenta]DHCP Group Total: [bold white]{len(self._dhcp_group['dhcpgroup'])}[/bold white][/magenta] <<======[/green]"
        self.table_print(title=title, fld=fields, val=self._dhcp_group['dhcpgroup'])

    def routers_print(self, flt):
        self.run_dep_routines([self.get_logic_routers, self.get_networks, self.get_nqa])
        fields = {
            'name': 'name',
            'ID': 'id',
            'Description': 'description',
            'tenantName': 'tenantName',
            'Type': 'type',
            'VRFName': 'vrfName',
            'VNI': 'vni',
            # 'mode': 'mode',
        }
        fields_routes = {
            'Destination': 'destination',
            'NexthopIp': 'nexthopIp',
            'Pref': 'preference',
            'trackType': 'trackType',
            'TrackName': {'src': 'trackId', 'query': self._nqa_id, 'dst': 'name'},
        }
        fields_subnets = {
            'Network': 'cidr',
            'GatewayIP': 'gatewayIp',
        }

        fields_bgp = {
            'AF': 'addressFamilyType',
            'PeerIp': 'peerIp',
            'PeerAs': 'peerAs',
            'BGP-Type': 'bgpPeerType',
            'DeviceGroup': 'deviceGroupName',
            'KLV-Time': 'keepaliveTime',
            'HoldTime': 'holdTime',
        }
        for j in self._routers['router']:
            if len([True for i in flt if re.search(i, j['name'], re.IGNORECASE)]) == 0 and len(flt) > 0:
                continue
            self.cons.rule(f"\n\n[green]======>> [magenta]Router Name: [bold white]{j['name']}[/bold white][/magenta] <<======[/green]")
            tbl = Table(show_lines=True, box=box.DOUBLE)
            tbl.add_column('NameParam')
            tbl.add_column('ValueParam')
            for p, pval in fields.items():
                tbl.add_row(p, str(j[pval]))
            self.cons.print(tbl)

            self.table_print(title=f"Routes: {len(j['routes'])}", fld=fields_routes, val=j['routes'])
            self.table_print(title=f"Subnets: {len(j['subnets'])}", fld=fields_subnets, val=j['subnets'])
            if j['bgp']:
                self.table_print(title=f"BGP Peer: {len(j['bgp']['bgpPeer'])}", fld=fields_bgp, val=j['bgp']['bgpPeer'])

    def epg_print(self, flt):
        self.run_dep_routines([self.get_logic_sw, self.get_logic_routers, self.get_interfaces, self.get_networks, self.get_epg])
        self.raw_json_print(self._epg)
        lst_epg = defaultdict(lambda: list())
        for j in self._epg['epg']:
            lst_epg[j['routerId']].append(j)
        # lst_epg = {lst_epg['routerId'].append(j) for j in self._epg['epg']}
        fields = {
            'Name EPG': 'name',
            'Description': 'description',
            'logicNetworkName': 'logicNetworkId',
            'Type': 'type',
            'Items of Type': 'item',
            'epgTermAttr': 'epgTerminalAttr',
            'mode': 'mode',
        }
        fields = {
            'Name EPG': 'name',
            'Description': 'description',
            'logicNetworkName': 'logicNetworkId',
            'Type': 'type',
            'Items of Type': 'item',
            'epgTermAttr': 'epgTerminalAttr',
            'mode': 'mode',
        }

        # print(json.dumps(lst_epg,indent=4))
        # print(json.dumps(lst_epg, indent=4))
        # quit()
        for j, val in sorted(lst_epg.items()):
            tbl = Table(
                title=f"\n\n[green]======>> [magenta]Router Name: [bold white]{self._routers_id[j]['name']}[/bold white][/magenta] <<======[/green]",
                show_lines=True,
            )

            tbl.box = box.DOUBLE

            for i in fields:
                tbl.add_column(i)
                # print(self._routers_id[j]['name'])
            for i in val:
                # print(iv)
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
            # filter_ports = [i for i in self._ports['port'] if i['logicSwitchName'] == j]
            if len([True for i in flt if re.search(i, j, re.IGNORECASE)]) == 0 and len(flt) > 0:
                continue
            for k in val:
                tbl.add_row(k, str(val[k]))
            self.cons.print(tbl)

    def logic_sw_print(self, flt, net):
        self.run_dep_routines([self.get_logic_sw, self.get_networks])
        self.raw_json_print(self._switches)
        fields = {'Name': 'name', 'NetID': 'logicNetworkId', 'VNI': 'vni', 'BridgeID': 'bd', 'NetSub': 'subnets', 'Created': 'created'}
        lst_log_sw = {j['name']: j for j in self._switches['switch']}
        title = f"Total switches: {len(lst_log_sw)}"
        sws = list()
        for j, val in sorted(lst_log_sw.items()):
            if len([True for i in flt if re.search(i, j, re.IGNORECASE)]) == 0 and len(flt) > 0:
                continue
            name_net = self._networks_id[val['logicNetworkId']]['name']
            if not re.search(net, name_net, re.IGNORECASE) and len(net) > 0:
                continue
            sw = dict()
            sw = val
            sw['created'] = val['additional']['createAt']
            sw['subnets'] = ','.join(val['subnets'])
            sw['logicNetworkId'] = name_net
            sws.append(sw)
        self.table_print(title=title, fld=fields, val=sws)

    def get_logic_net_by_switch_id(self, lsw):
        log_net = self._networks_id[self._switches_id[lsw]['logicNetworkId']]['name']
        return log_net

    def ports_print(self, sw, status, flt):
        self.run_dep_routines([self.get_devices, self.get_logic_sw, self.get_networks, self.get_endports])
        lst_sw = [i for i in self._switches['switch'] if re.search(sw, i['name'], re.IGNORECASE) and len(sw)>0 ]
        fields = {'NamePort': 'name', 'VLAN': 'vlan', 'PhysicalPort': 'physicalPortlist', 'EndPorts': 'endPort'}
        ports = list()
        ports_map = list()
        for i in lst_sw:
            ret = self.get_logic_ports_filter(sw_id=i['id'])
            ports.extend(ret['port'])
            ret = self.get_logic_ports_map_filter(sw_id=i['id'])
            ports_map.extend(ret['port'])
        lst_switches = {j['logicSwitchName']: [j['bridgeDomainId'], self.get_logic_net_by_switch_id(j['logicSwitchId'])]
                        for j in ports_map}
        ports_id = {k['id']: k for k in ports}
        self.cons.print(f"Total ports in query: {len(ports_map)}")
        for j, val in sorted(lst_switches.items()):
            filter_ports = {i['name']: i for i in ports_map if i['logicSwitchName'] == j}
            tbl = Table(
                title=f"\n[magenta]BridgeID: [bold white]{val[0]}[/bold white] LogicSwitch: [bold white]{j}[/bold white] NET: [bold white]{val[1]}[/bold white][/magenta]",
                show_lines=True,
                title_justify='left',
            )
            tbl.box = box.DOUBLE
            for f in fields:
                tbl.add_column(f)
            for i, pval in sorted(filter_ports.items()):
                phys_ports = "\n".join(
                    [f"{self._dev_id[k['deviceId']]['name']} {k['ifname']} {k['ifstatus']} {k['devicePortName']}" for k in pval[fields['PhysicalPort']]]
                )
                if not re.search(status, phys_ports, re.IGNORECASE) and len(status) > 0:
                    continue
                end_ports = "\n".join(
                    [f"{self._endportsId[k['endPortId']]['vmName']} {k['endPortIp']} {self._endportsId[k['endPortId']]['mac']}" for k in pval[fields['EndPorts']]]
                )
                name_port = pval[fields['NamePort']]
                vlan = ""
                vlan = str(ports_id[pval['id']]['accessInfo']['vlan'])
                if len(name_port) > 30:
                    name_port = f"{name_port[0:30]}\n{name_port[30:]}"
                tbl.add_row(f"{name_port}", vlan, phys_ports, end_ports)
            self.cons.print(tbl)

    def ports_print_total(self, flt, net):
        self.run_dep_routines([self.get_devices, self.get_logic_ports_map, self.get_logic_sw, self.get_networks, self.get_endports, self.get_logic_ports])
        lst_switches = {j['logicSwitchName']: [j['bridgeDomainId'], self.get_logic_net_by_switch_id(j['logicSwitchId'])] for j in self._ports['port']}
        fields = {'NamePort': 'name', 'VLAN': 'vlan', 'PhysicalPort': 'physicalPortlist', 'EndPorts': 'endPort'}
        self.raw_json_print(self._ports)
        self.cons.print(f"Total ports in query: {len(self._ports['port'])}")
        for j, val in sorted(lst_switches.items()):
            if not re.search(net, val[1], re.IGNORECASE) and len(net) > 0:
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

    def end_ports_print(self, flt):
        self.run_dep_routines([self.get_logic_sw, self.get_endports])
        self.raw_json_print(self._endports)
        fields = ['name', 'vmName', 'vmmName', 'hostName', 'type', 'mac', 'vlan', 'ip', 'status', 'updateTime']
        fields_belong = ['logicRouterName', 'vpcName', 'tenantName', 'producer']
        fields_switches = {'LogSwitchName': 'name', 'LogSwitchBD': 'bd', 'LogSwitchVNI': 'vni', 'LogSwitchDesc': 'description'}
        total_num = self._endports['totalNum']

        for rec in self._endports['endPort']:
            if len([True for i in flt if re.search(i, rec['vmName'], re.IGNORECASE)]) == 0 and len(flt) > 0:
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

    def links_print(self, flt, mode, stat):
        fields = [
            'Trunk',
            'Status',
            'Mode',
            'LocName',
            'LocPort',
            'LocIP',
            'RemName',
            'RemPort',
            'RemIP',
        ]
        self.run_dep_routines([self.get_devices, self.get_links])
        count_unknown = len([i for i in self._links["links"] if i['status'] == 4])
        table = Table(title=f"Total Links: {len(self._links['links']) - count_unknown} Unknown Links: {count_unknown}", show_lines=True)
        for f in fields:
            table.add_column(f)
        for i in self._links["links"]:
            name_sw = self._dev_id[i['localNode']['deviceId']]['name']
            if len([True for i in flt if re.search(i, name_sw)]) == 0 and len(flt) > 0:
                continue
            if not re.search(mode, LINKMODE[i["mode"]], re.IGNORECASE) and len(mode) > 0:
                continue
            if not re.search(stat, LINKSTAT[i["status"]], re.IGNORECASE) and len(stat) > 0:
                continue
            table.add_row(
                str(i["trunk"]),
                LINKSTAT[i["status"]],
                LINKMODE[i["mode"]],
                name_sw,
                i["localNode"]["port"],
                i["localNode"]["deviceIp"],
                self._dev_id[i['peerNode']['deviceId']]['name'],
                i["peerNode"]["port"],
                i["peerNode"]["deviceIp"],
            )
        self.cons.print(table)


    def hostLinks_print(self, flt):
        self.run_dep_routines([self.get_devices, self.get_host_links])
        self.raw_json_print(self._host_links)
        tbl = list(set([j["hostName"] for j in self._host_links["linkList"] if j["hostName"] != None]))
        # print(f"{tbl} == {len(tbl)}")
        fields = [
            'linkId',
            'switchId',
            'switchPortName',
            'trunkName',
            'hostMac',
        ]

        for j in sorted(tbl):
            if len([True for i in flt if re.search(i, j)]) == 0 and len(flt) > 0:
                continue
            table = Table(title=f"\n\n[green]======>> [magenta]Host Name: [bold white]{j}[/bold white][/magenta] <<======[/green]", show_lines=True)
            # f"\n\n[green]======>> [magenta]VM Name: [bold white]{rec['vmName']}[/bold white][/magenta] <<======[/green]"
            # f"Found HostLinks: {len(self._host_links['linkList'])}"
            for f in fields:
                table.add_column(f)

            hst_lnks = [k for k in self._host_links["linkList"] if k['hostName'] == j]
            for i in hst_lnks:
                table.add_row(i["linkId"], self._dev_id[i["switchId"]]["name"], i["switchPortName"], i["trunkName"], i['hostMac'])
            self.cons.print(table)

    def dev_group_print(self):
        self.run_dep_routines([self.get_dev_groups, self.get_devices])
        self.raw_json_print(self._dev_groups)
        lst_type = list(set([j['type'] for j in self._dev_groups['deviceGroups'] if j['type'] != ""]))
        for j in sorted(lst_type):
            dev_total = len([i for i in self._dev_groups['deviceGroups'] if i['type'] == j])
            table = Table(title=f"\n\n[green]======>> {j} Group Type Devices: {dev_total} <<======", show_lines=True)
            # table.add_column("PoolId")
            table.add_column("Id")
            table.add_column("Name")
            table.add_column("Type")
            table.add_column("Description")
            table.add_column("Device")

            for i in self._dev_groups["deviceGroups"]:
                if i['type'] == j:
                    table.add_row(
                        # i["poolId"],
                        i["id"],
                        i["name"],
                        i["type"],
                        i["description"],
                        ' '.join([self._dev_id[j]['name'] for j in i["device"]]),
                    )
            self.cons.print(table)

    def dev_print_by_type(self, tp):
        self.run_dep_routines([self.get_devices])
        lst_type = list(set([j['type'] for j in self._dev_list['devices'] if re.search(tp, j['type'], re.IGNORECASE) or len(tp) == 0 ]))
        # if j['type'] != ""
        # print(lst_type)
        for j in sorted(lst_type):
            dev_total = len([i for i in self._dev_list['devices'] if i['type'] == j])
            table = Table(title=f"\n\n======>> [magenta]Type: [bold white]{j}[/bold white] Num:  [bold white]{dev_total} [/bold white][/magenta] <<======", show_lines=True)
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
                        # i["softWare"],
                        # str(i["cpuRate"]),
                    )
            self.cons.print(table)
        self.cons.print(f"Total devices: {len(self._dev_list['devices'])}")

    def huawei_traffic_policy(self, result):
        failed_hst = [i for i in result.failed_hosts]
        assert failed_hst != 0, "Connect to hosts failed !"
        # display_result(result)
        for i, ival in result.items():
            if i.lower() not in failed_hst:
                for h, hval in hst_huawei.items():
                    # print(ival[1].result)
                    # print(hval[0]['log_sw']['bd'])
                    # print(h)
                    self.get_info_traffic_policy(sw_cfg=[j for j in ival[1].result.split('\n')], intrf=f"Vbdif{hval[0]['log_sw']['bd']}")


    def get_host_tp(self, hst="", user="", pwd=""):
        assert hst != "", "Name of host is empty !!!"
        self.get_endports()
        hst_huawei = {i: val for i, val in self._endportsName.items() if re.search(hst, i)}
        lst_sw = list()
        for vm, vmval in hst_huawei.items():
            for hs in vmval:
                lst_sw.extend(hs['con_dev'])
        print(f"Host Connected to: {' '.join(list(set(lst_sw)))}")
        luk = LukNornir(filter_hosts=','.join(lst_sw), user=user, passw=pwd)
        res = luk.run_tasks("dis cur")
        failed_hst = [i for i in res.failed_hosts]
        assert failed_hst != 0, "Connect to hosts failed !"
        # display_result(result)
        for i, ival in res.items():
            if i.lower() not in failed_hst:
                for h, hval in hst_huawei.items():
                    self.get_info_traffic_policy(sw_cfg=[j for j in ival[1].result.split('\n')], intrf=f"Vbdif{hval[0]['log_sw']['bd']}")

    def get_info_traffic_policy(self, intrf="", sw_cfg=""):
        assert intrf != "" and sw_cfg != "", "Interface and Config are empty"
        interface_name = intrf
        conf_intrf = dict()
        parse = CiscoConfParse(sw_cfg)
        # print(interface_name)
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
        # print(json.dumps(classif, indent=4))
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
