# Copyright (C) DEFION.
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

import os
import csv
import sqlite3
import biplist
import base.job
from plugins.common.RVT_files import GetFiles


class NetworkUsage(base.job.BaseModule):

    def run(self, path=""):
        search = GetFiles(self.config)
        nusage = search.search("/netusage.sqlite$")
        output = os.path.join(self.myconfig('outdir'), "network_usage.txt")

        with open(output, "w") as out:
            for k in nusage:
                self.logger().info(f"Extracting information of file {k}")
                with sqlite3.connect(f"file://{os.path.join(self.myconfig('casedir'), k)}?mode=ro", uri=True) as conn:
                    conn.text_factory = str
                    c = conn.cursor()

                    out.write(f"{k}\n------------------------------------------\n")
                    query = '''SELECT pk.z_name as item_type, na.zidentifier as item_name, na.zfirsttimestamp as first_seen_date, na.ztimestamp as last_seen_date,
rp.ztimestamp as rp_date, rp.zbytesin, rp.zbytesout FROM znetworkattachment as na LEFT JOIN z_primarykey pk ON na.z_ent = pk.z_ent
LEFT JOIN zliverouteperf rp ON rp.zhasnetworkattachment = na.z_pk ORDER BY pk.z_name, zidentifier, rp_date desc;'''.replace('\n', ' ').upper()
                    c.execute(query)

                    out.write("\n\nitem_type|item_name|first_seen_date|last_seen_date|rp_date|ZBYTESIN|ZBYTESOUT\n--|--|--|--|--|--|--\n")
                    for i in c.fetchall():
                        out.write(f"{i[0]}|{i[1]}|{i[2]}|{i[3]}|{i[4]}|{i[5]}|{i[6]}\n")

                    query = '''SELECT pk.z_name as item_type ,p.zprocname as process_name, p.zfirsttimestamp as first_seen_date, p.ztimestamp as last_seen_date,
lu.ztimestamp as usage_since, lu.zwifiin, lu.zwifiout, lu.zwiredin, lu.zwiredout, lu.zwwanin, lu.zwwanout FROM zliveusage lu
LEFT JOIN zprocess p ON p.z_pk = lu.zhasprocess LEFT JOIN z_primarykey pk ON p.z_ent = pk.z_ent ORDER BY process_name;'''.replace('\n', ' ').upper()
                    c.execute(query)

                    out.write("\n\nitem_type|process_name|first_seen_date|last_seen_date|usage_since|ZWIFIIN|ZWIFIOUT|ZWIREDIN|ZWIREDOUT|ZWWANIN|ZWANOUT\n--|--|--|--|--|--|--|--|--|--|--\n")
                    for i in c.fetchall():
                        out.write(f"{i[0]}|{i[1]}|{i[2]}|{i[3]}|{i[4]}|{i[5]}|{i[6]}|{i[7]}|{i[8]}|{i[9]}|{i[10]}\n")
                    out.write("\n")
                    c.close()

        self.logger().info("Done parsing netusage.sqlite")
        return []


class Network(base.job.BaseModule):

    def run(self, path=""):
        self.GetNetworkInterfaceInfo()
        self.GetNetworkInterface2Info()
        self.GetDhcpInfo()
        self.ProcessActiveDirectoryPlist()
        return []

    def GetNetworkInterfaceInfo(self):
        '''Read interface info from NetworkInterfaces.plist
        modified from networking plugin from https://github.com/ydkhatri/mac_apt'''

        search = GetFiles(self.config)
        network = search.search("/Library/Preferences/SystemConfiguration/NetworkInterfaces.plist$")
        classes = ['Active', 'BSD Name', 'IOBuiltin', 'IOInterfaceNamePrefix', 'IOInterfaceType', 'IOInterfaceUnit', 'IOPathMatch', 'SCNetworkInterfaceType']

        out = open(os.path.join(self.myconfig('outdir'), 'Network_Interfaces.csv'), 'w')
        writer = csv.writer(out, delimiter="|", quotechar='"')
        headers = ["Category", "Active", "BSD Name", "IOBuiltin", "IOInterfaceNamePrefix", "IOInterfaceType",
                   "IOInterfaceUnit", "IOMACAddress", "IOPathMatch", "SCNetworkInterfaceInfo", "SCNetworkInterfaceType", "Source"]
        writer.writerow(headers)

        for net in network:
            self.logger().debug(f"Trying to read {net}")
            plist = biplist.readPlist(os.path.join(self.myconfig('casedir'), net))
            try:
                self.logger().info(f"Model = {plist['Model']}")
            except Exception:
                pass
            for category, cat_array in plist.items():
                if not category.startswith('Interface'):
                    if category != 'Model':
                        self.logger().debug(f'Skipping {category}')
                    continue
                for interface in cat_array:
                    interface_info = {'Category': category, 'Source': net}
                    for c in classes:
                        interface_info[c] = ""
                    for item, value in interface.items():
                        if item in classes:
                            interface_info[item] = value
                        elif item == 'IOMACAddress':
                            data = value.hex().upper()
                            data = [data[2 * n:2 * n + 2] for n in range(6)]
                            interface_info[item] = ":".join(data)
                        elif item == 'SCNetworkInterfaceInfo':
                            try:
                                interface_info['SCNetworkInterfaceInfo'] = value['UserDefinedName']
                            except Exception:
                                pass
                        else:
                            self.logger().info("Found unknown item in plist: ITEM=" + item + " VALUE=" + str(value))
                    writer.writerow([interface_info[c] for c in headers])
        out.close()

    def GetNetworkInterface2Info(self):
        '''Read interface info from /Library/Preferences/SystemConfiguration/preferences.plist

        Based on mac_apt plugin from https://github.com/ydkhatri/mac_apt
        '''
        search = GetFiles(self.config)
        network = search.search("/Library/Preferences/SystemConfiguration/preferences.plist$")

        with open(os.path.join(self.myconfig('outdir'), 'Network_Details.csv'), 'w') as out:
            writer = csv.writer(out, delimiter="|", quotechar='"')
            headers = ["UUID", "IPv4.ConfigMethod", "IPv6.ConfigMethod", "DeviceName", "Hardware", "Type", "SubType",
                       "UserDefinedName", "Proxies.ExceptionsList", "SMB.NetBIOSName", "SMB.Workgroup", "PPP", "Modem"]
            writer.writerow(headers)
            for net in network:
                plist = biplist.readPlist(os.path.join(self.myconfig('casedir'), net))
                for uuid in plist['NetworkServices'].keys():
                    data = [uuid] + [""] * 12
                    if 'IPv4' in plist['NetworkServices'][uuid].keys():
                        data[1] = plist['NetworkServices'][uuid]['IPv4']['ConfigMethod']
                    if 'IPv6' in plist['NetworkServices'][uuid].keys():
                        data[2] = plist['NetworkServices'][uuid]['IPv6']['ConfigMethod']
                    if 'Interface' in plist['NetworkServices'][uuid].keys():
                        data[3] = plist['NetworkServices'][uuid]['Interface']['DeviceName']
                        data[4] = plist['NetworkServices'][uuid]['Interface']['Hardware']
                        data[5] = plist['NetworkServices'][uuid]['Interface']['Type']
                        if 'SubType' in plist['NetworkServices'][uuid]['Interface'].keys():
                            data[6] = plist['NetworkServices'][uuid]['Interface']['SubType']
                        data[7] = plist['NetworkServices'][uuid]['Interface']['UserDefinedName']
                    if 'Proxies' in plist['NetworkServices'][uuid].keys() and 'ExceptionsList' in plist['NetworkServices'][uuid]['Proxies'].keys():
                        data[8] = ",".join(plist['NetworkServices'][uuid]['Proxies']['ExceptionsList'])
                    if 'SMB' in plist['NetworkServices'][uuid].keys():
                        try:
                            data[9] = plist['NetworkServices'][uuid]['SMB']['NetBIOSName']
                            data[10] = plist['NetworkServices'][uuid]['SMB']['Workgroup']
                        except Exception:
                            pass
                    if 'PPP' in plist['NetworkServices'][uuid].keys():
                        data[11] = str(plist['NetworkServices'][uuid]['PPP'])
                    if 'Modem' in plist['NetworkServices'][uuid].keys():
                        data[12] = str(plist['NetworkServices'][uuid]['Modem'])
                    writer.writerow(data)

    def GetDhcpInfo(self):
        '''Read dhcp leases & interface entries

           Based on mac_apt plugin from https://github.com/ydkhatri/mac_apt
        '''
        search = GetFiles(self.config)
        interfaces_path = search.search("/private/var/db/dhcpclient/leases$")

        out = open(os.path.join(self.myconfig('outdir'), 'Network_DHCP.csv'), 'w')
        writer = csv.writer(out, delimiter="|", quotechar='"')
        headers = ["Interface", "MAC_Address", "IPAddress", "LeaseLength", "LeaseStartDate", "PacketData", "RouterHardwareAddress", "RouterIPAddress", "SSID", "Source"]
        writer.writerow(headers)

        for interface in interfaces_path:
            for name in sorted(os.listdir(os.path.join(self.myconfig('casedir'), interface))):
                if name.find(",") > 0:
                    name_no_ext = os.path.splitext(name)[0]
                    if_name, mac_address = name_no_ext.split(",")
                    self.logger().info(f"Found mac address = {mac_address} on interface {if_name}")
                    self.logger().debug(f"Trying to read {name}")

                    plist = biplist.readPlist(os.path.join(self.myconfig('casedir'), interface, name))
                    interface_info = {}
                    for c in headers:
                        interface_info[c] = ""
                    interface_info['Source'] = os.path.join('/private/var/db/dhcpclient/leases', name)
                    interface_info['Interface'] = if_name
                    interface_info['MAC_Address'] = mac_address

                    for item, value in plist.items():
                        if item in ('IPAddress', 'LeaseLength', 'LeaseStartDate', 'RouterIPAddress', 'SSID'):
                            interface_info[item] = value
                        elif item == 'RouterHardwareAddress':
                            data = value.hex().upper()
                            data = [data[2 * n:2 * n + 2] for n in range(6)]
                            interface_info[item] = ":".join(data)
                        elif item == 'PacketData':
                            interface_info['PacketData'] = value.hex().upper()
                        else:
                            self.logger().info("Found unknown item in plist: ITEM=" + item + " VALUE=" + str(value))
                    writer.writerow([interface_info[c] for c in headers])
                else:
                    self.logger().info(f"Found unexpected file, not processing /private/var/db/dhcpclient/leases/{name} size={str(interface['size'])}")
        out.close()

    def ProcessActiveDirectoryPlist(self):
        '''Extract active directory artifacts

        Based on mac_apt plugin from https://github.com/ydkhatri/mac_apt
        '''
        search = GetFiles(self.config)
        network_paths = search.search("/Library/Preferences/OpenDirectory/Configurations/Active Directory$")

        out = open(os.path.join(self.myconfig('outdir'), 'Domain_ActiveDirectory.csv'), 'w')
        writer = csv.writer(out, delimiter="|", quotechar='"')
        headers = ["node name", "trustaccount", "trustkerberosprincipal", "trusttype", "allow multi-domain", "cache last user logon", "domain", "forest", "trust domain", "source"]
        writer.writerow(headers)

        for plist_path in network_paths:
            active_directory = {'source': plist_path}
            for archive in sorted(os.listdir(os.path.join(self.myconfig('casedir'), plist_path))):
                plist = biplist.readPlist(os.path.join(self.myconfig('casedir'), plist_path, archive))
                try:
                    for item, value in plist.items():
                        if item in ['node name', 'trustaccount', 'trustkerberosprincipal', 'trusttype']:
                            active_directory[item] = value
                    ad_dict = plist['module options']['ActiveDirectory']
                    for item, value in ad_dict.items():
                        if item in ['allow multi-domain', 'cache last user logon', 'domain', 'forest', 'trust domain']:
                            active_directory[item] = value
                except Exception:
                    self.logger().error(f'Error reading plist {os.path.join(plist_path, archive)}')
                writer.writerow([active_directory[d] for d in headers])
        out.close()
        return []
