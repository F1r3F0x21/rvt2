# Copyright (C) INCIDE Digital Data S.L.
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
import ast
import datetime
import dateutil.parser

import base.job
from base.utils import save_md_table


class Filter_Events(base.job.BaseModule):
    """ Filters events for generating a csv file """

    def run(self, path=None):
        events = ast.literal_eval(self.config.config[self.config.job_name]['events_dict'])

        for event in self.from_module.run(path):
            if event['event.code'] in events.keys() and event['event.provider'] == events[event['event.code']]:
                yield event


class LogonRDP(base.job.BaseModule):
    """ Extracts logon and rdp artifacts """

    def run(self, path=None):
        """
        Attrs:
            path (str): Absolute path to the parsed Security.xml
        """

        self.check_params(path, check_path=True, check_path_exists=True)

        logID = {}
        actID = {}

        for event in self.from_module.run(path):
            ev = dict()
            ev['TimeCreated'] = event.get('event.created', '')
            ev['EventID'] = event.get('event.code', '')
            ev['Description'] = event.get('message', '')
            ev['ActivityID'] = event.get('data.ActivityID', )
            ev['SessionID'] = event.get('data.SessionID', '')
            ev['ConnType'] = event.get('data.ConnType', '')
            ev['LogonType'] = event.get('data.LogonType', '')
            ev['ProcessName'] = event.get('process.name', '')
            ev['Logon.ProcessName'] = event.get('data.LogonProcessName', '')
            ev['AuthenticationPackageName'] = event.get('data.AuthenticationPackageName', '')

            if "client.ip" in event.keys():
                ev['source.ip'] = event['client.ip']
            elif "source.ip" in event.keys():
                ev['source.ip'] = event['source.ip']
            elif "source.address" in event.keys():
                ev['source.ip'] = event['source.address']

            if "data.ConnectionName" in event.keys():
                ev['ConnectionName'] = event['data.ConnectionName']
            else:
                ev['ConnectionName'] = event.get('data.SessionName')
            if 'data.reasonStr' in event.keys():
                ev['reasonStr'] = event['data.reasonStr']
            elif 'data.DisconnectReason' in event.keys():
                ev['reasonStr'] = event['data.DisconnectReason']
            else:
                ev['reasonStr'] = event.get('data.Reason', '')
            if 'source.user.name' in event.keys():
                if event['source.user.name'] != '-':
                    ev['User'] = "{}\\{}".format(event['source.domain'], event['source.user.name'])
                else:
                    ev['User'] = '-'
            elif 'client.source.name' in event.keys():
                ev['User'] = event['client.source.name']
            else:
                ev['User'] = event.get('User', '')
            if 'destination.user.name' in event.keys():
                if event['destination.user.name'] != '-':
                    if 'destination.domain' in event.keys():
                        ev['TargetUser'] = "{}\\{}".format(event['destination.domain'], event['destination.user.name'])
                    else:
                        ev['TargetUser'] = event['destination.user.name']
                else:
                    ev['TargetUser'] = '-'
            else:
                ev['TargetUser'] = ''
            if 'data.TargetLogonId' in event.keys():
                ev['LogonID'] = event['data.TargetLogonId']
            else:
                ev['LogonID'] = event.get('data.LogonID', '')

            if ev['EventID'] in ("4624", "4634", "4647", "4648"):
                if ev['LogonID'] not in logID.keys():
                    logID[ev['LogonID']] = []
                logID[ev['LogonID']].append(ev)
            elif ev['EventID'] in ("21", "23", "24", "25", "39", "40", "65", "66", "102", "131", "140", "1149"):
                if ev['ActivityID'] not in actID.keys():
                    actID[ev['ActivityID']] = []
                actID[ev['ActivityID']].append(ev)
            elif ev['EventID'] in ("4778", "4779"):
                activity = self.relateIDs(ev, actID)
                if activity != '':
                    actID[activity].append(ev)
                    logID[ev['LogonID']].append(ev)

            yield ev
        self.extractRDP(actID)
        self.extractLogon(logID)

    def __difTimestamp__(self, d1, d0):
        """ get seconds between dates in ISO format
        Args;
            d0 (str): date 1
            d1 (str); date 2
        Returns:
            int: absolute value of d1 - d0
        """

        if d1 == '-' or d0 in ('', '-'):
            return 1.e5
        return abs((dateutil.parser.parse(d1) - dateutil.parser.parse(d0)).total_seconds())

    def relateIDs(self, ev, actID):
        """ relates events 4778 and 4779 with RDP events
        Args:
            ev (dict): event 4778 or 4779 to relate
            actID (dict): dict with list of RDP events with key ActivityID and values a list of events
        Returns:
            str: activityID closer to ev
        """
        d0 = 100000
        actual_actID = ''
        t0 = dateutil.parser.parse(ev['TimeCreated'])
        for k, v in actID.items():
            for event in v:
                if "data.ConnectionName" in event.keys() and ev['ConnectionName'] == event['data.ConnectionName']:
                    d1 = abs((dateutil.parser.parse(event['TimeCreated']) - t0).total_seconds())
                    if d1 < d0:
                        actual_actID = event['ActivityID']
                        d0 = d1
        return actual_actID

    def extractLogon(self, logID):

        results = []
        for eventlist in logID.values():
            logon = '-'
            ip = '-'
            # ln = len(eventlist)
            for e, v in enumerate(eventlist):
                if v['LogonType'] in ("3", "4", "5"):
                    continue
                if v['EventID'] == '4634':
                    results.append({'Login': logon, 'IP': ip, 'Logoff': v['TimeCreated'], 'User': v['TargetUser']})
                    logon = ''
                    ip = ''
                    continue
                if v['EventID'] == '4624':
                    logon = v['TimeCreated']
                    ip = v['source.ip']
                # if e == ln:
                    results.append({'Login': logon, 'IP': ip, 'Logoff': v['TimeCreated'], 'User': v['TargetUser']})

        save_md_table(results, config=None,
                      outfile=os.path.join(os.path.dirname(self.myconfig('outfile')), 'logon_offs.md'),
                      fieldnames='Login IP Logoff User',
                      file_exists='OVERWRITE')

    def extractRDP(self, actID):

        results = []
        suser = ''
        auxtime = ''
        auxtime2 = ''
        for eventlist in actID.values():
            act = dict()
            insession = False
            for e, v in enumerate(eventlist):
                if v['EventID'] in ('23', '24'):
                    if not insession and self.__difTimestamp__(v["TimeCreated"], auxtime2) < 1:
                        continue  # two logoff events consecutives
                    if v['EventID'] == '23' and ('reason' not in act.keys() or act['reason'] == ''):
                        act['reason'] = 'logoff succeeded'
                    insession = False
                    act['TargetUser'] = v['TargetUser']
                    results.append({'Login': act.get('t0', '-'), 'SubjectUser': act.get('subjectUser', ''), 'IP': act.get('ip', ''), 'Logoff': v['TimeCreated'], 'User': act.get('TargetUser', ''), 'Reason': act.get('reason', '')})
                    act = dict()
                    auxtime2 = v['TimeCreated']
                elif v['EventID'] in ('39', '40'):
                    act['reason'] = v['reasonStr']
                elif v['EventID'] in ('21', '25'):
                    if 't0' in act.keys() and act['t0'] not in ('', '-'):
                        if self.__difTimestamp__(v["TimeCreated"], act['t0']) < 1:  # login event repeated
                            continue
                        else:  # unfinished event
                            results.append({'Login': act.get('t0', '-'), 'SubjectUser': act.get('subjectUser', ''), 'IP': act.get('ip', ''), 'Logoff': act.get('t1', ''), 'User': act.get('TargetUser', ''), 'Reason': act.get('reason', '')})
                    insession = True
                    act['t1'] = '-'
                    act['reason'] = ''
                    if 'subjectUser' not in act.keys():
                        act['subjectUser'] = ''
                    act['t0'] = v['TimeCreated']
                    act['ip'] = v['source.ip']
                    act['targetUser'] = v['User']
                    if self.__difTimestamp__(v['TimeCreated'], auxtime) < 2:
                        act['subjectUser'] = suser
                elif v['EventID'] == '1149':
                    act['TargetUser'] = v['TargetUser']
                    auxtime = v['TimeCreated']

            if ('t0' in act.keys() and act['t0'] not in ('', '-')) or ('t1' in act.keys() and act['t1'] not in ('', '-')):  # for writing unclosed event
                results.append({'Login': act.get('t0', '-'), 'SubjectUser': act.get('subjectUser', ''), 'IP': act.get('ip', ''), 'Logoff': act.get('t1', '-'), 'User': act.get('TargetUser', ''), 'Reason': act.get('reason', '')})
        save_md_table(results, config=None,
                      outfile=os.path.join(os.path.dirname(self.myconfig('outfile')), 'rdp.md'),
                      fieldnames='Login SubjectUser IP Logoff User Reason',
                      file_exists='OVERWRITE')


class RDPIncoming(base.job.BaseModule):
    """ Extracts events related to incoming RDP connections """

    def run(self, path=None):
        """
        Attrs:
            path (str): Absolute path to the parsed Security.xml
        """

        self.check_params(path, check_path=True, check_path_exists=True)

        sID = {}

        for event in self.from_module.run(path):
            ev = dict()
            ev['EventID'] = event.get('event.code', '')
            ev['TimeCreated'] = event.get('event.created', '')
            ev['Description'] = event.get('message', '')
            ev['User'] = event.get('destination.user.name', '')
            ev['SessionID'] = event.get('data.SessionID', '')
            ev['SourceAddress'] = event.get('source.address', '')
            if ev['SessionID'] not in sID.keys():
                sID[ev['SessionID']] = []
            sID[ev['SessionID']].append(ev)

        for result in self.extractRDP(sID):
            yield result

    def extractRDP(self, sID):

        for eventlist in sID.values():
            act = dict()
            written = True
            act['LoginDate'] = '-'
            act['LogoffDate'] = '-'
            act['User'] = ''
            act['SourceAddress'] = ''

            for v in sorted(eventlist, key=lambda k: k['TimeCreated']):
                self.logger().debug("%s %s" % (v['TimeCreated'], v['EventID']))

                if v['EventID'] in ('21', '22', '25'):
                    if act['SourceAddress'] == '':
                        act['SourceAddress'] = v.get('SourceAddress', '')
                    act['User'] = v.get('User', '')
                    act['LoginDate'] = v['TimeCreated']
                    written = False
                elif v['EventID'] in ('23', '24') and act['LoginDate'] != '-':
                    act['LogoffDate'] = v['TimeCreated']
                    yield {
                        'LoginDate': act.get('LoginDate', '-'),
                        'LogoffDate': act.get('LogoffDate', '-'),
                        'User': act.get('User', ''),
                        'SourceAddress': act.get('SourceAddress', '')
                    }
                    self.logger().debug("%s %s" % (act['LoginDate'], act['LogoffDate']))
                    act['LoginDate'] = '-'
                    act['LogoffDate'] = '-'
                    act['User'] = ''
                    act['SourceAddress'] = ''
                    written = True
            if not written:
                yield {
                    'LoginDate': act.get('LoginDate', '-'),
                    'LogoffDate': act.get('LogoffDate', '-'),
                    'User': act.get('User', ''),
                    'SourceAddress': act.get('SourceAddress', '')
                }


class RDPOutgoing(base.job.BaseModule):
    """ Extracts events related to outgoing RDP connections """

    def run(self, path=None):
        """
        Attrs:
            path (str): Absolute path to the parsed Security.xml
        """

        self.check_params(path, check_path=True, check_path_exists=True)

        actID = {}

        for event in self.from_module.run(path):
            ev = dict()
            ev['TimeCreated'] = event.get('event.created', '')
            ev['EventID'] = event.get('event.code', '')
            ev['Description'] = event.get('message', '')
            ev['ActivityID'] = event.get('data.ActivityID', '')
            ev['Address'] = event.get('destination.address', '')
            ev['user.id'] = event.get('user.id', '')
            ev['Base64Hash'] = event.get('data.Base64Hash', '')

            if ev['ActivityID'] not in actID.keys():
                actID[ev['ActivityID']] = []
            actID[ev['ActivityID']].append(ev)

        for result in self.extractRDP(actID):
            yield result

    def extractRDP(self, actID):

        for eventlist in actID.values():
            act = dict()
            writted = True
            act['LoginDate'] = '-'
            act['LogoffDate'] = '-'

            for v in sorted(eventlist, key=lambda k: k['TimeCreated']):
                self.logger().debug("%s %s %s" % (v['TimeCreated'], v['EventID'], v['ActivityID']))
                if 'SID' not in act.keys() and 'user.id' in v.keys():
                    act['SID'] = v['user.id']
                if v['EventID'] in ('1024', '1102'):
                    act['Address'] = v['Address']
                elif v['EventID'] == '1025':
                    act['LoginDate'] = v['TimeCreated']
                    writted = False
                elif v['EventID'] == '1026' and act['LoginDate'] != '-':
                    act['LogoffDate'] = v['TimeCreated']
                    yield {
                        'LoginDate': act.get('LoginDate', '-'),
                        'LogoffDate': act.get('LogoffDate', '-'),
                        'Address': act.get('Address', ''),
                        'SID': act.get('SID', '-'),
                        'B64Hash': act.get('B64Hash', '')
                    }
                    self.logger().debug("%s %s" % (act['LoginDate'], act['LogoffDate']))
                    act['LoginDate'] = '-'
                    act['LogoffDate'] = '-'
                    writted = True
                elif v['EventID'] == '1029' and 'B64Hash' not in act.keys():
                    act['B64Hash'] = v.get('data.Base64Hash', '')
            if not writted:
                yield {
                    'LoginDate': act.get('LoginDate', '-'),
                    'LogoffDate': act.get('LogoffDate', '-'),
                    'Address': act.get('Address', ''),
                    'SID': act.get('SID', '-'),
                    'B64Hash': act.get('B64Hash', '')
                }


class Poweron(base.job.BaseModule):
    """ Extracts events of parsed Security.evtx

    Events should be sorted"""

    def run(self, path=None):
        """
        Attrs:
            path (str): Absolute path to the parsed Security.xml
        """

        self.check_params(path, check_path=True, check_path_exists=True)

        eventlist = []

        for event in self.from_module.run(path):
            ev = dict()
            ev['TimeCreated'] = event.get('event.created', '')
            ev['EventID'] = event.get('event.code', '')
            ev['message'] = event.get('message', '')
            ev['reason'] = event.get('reasonStr', '')
            eventlist.append(ev)

            yield ev
        self.extractPower(eventlist)

    def extractPower(self, events):
        """
        """
        results = []
        act = dict()
        inpower = False
        for ev in events:
            if ev['EventID'] == '1':
                if not inpower:
                    results.append([act.get('t0', '-'), 'Resume from sleep', act.get('t1', '-')])
                inpower = True
                act['t0'] = ev['TimeCreated']
                act['d0'] = 'Sleep'
            elif ev['EventID'] == '12':
                inpower = True
                act['t0'] = ev['TimeCreated']
                act['d0'] = 'StartBoot'
            elif ev['EventID'] == '13':
                inpower = False
                act['t1'] = ev['TimeCreated']
                act['d1'] = 'Shutdown'
                results.append([act.get('t0', '-'), 'Shut down', act.get('t1', '-')])
            elif ev['EventID'] == '41':
                if not inpower:
                    results.append([act.get('t0', '-'), 'Unexpected shutdown', '-'])
                inpower = True
                act['t0'] = ev['TimeCreated']
                act['d0'] = 'Unexpected reboot'
            elif ev['EventID'] == '42':
                results.append([act.get('t0', '-'), 'Sleeping', act.get('t1', '-')])
                inpower = False
                act['t1'] = ev['TimeCreated']
                act['d1'] = 'Sleeping'


class Network(base.job.BaseModule):
    """ Extracts events related with wireless networking

    Events should be sorted"""

    def run(self, path=None):
        """
        Attrs:
            path (str): Absolute path to the parsed Security.xml
        """

        self.check_params(path, check_path=True, check_path_exists=True)

        net_up = []
        net_down = []

        selected_fields = {"event.created": "Created", "event.code": "Code", "data.SSID": "SSID", "data.BSSID": "BSSID", "data.ConnectionId": "ConnectionId", "data.ProfileName": "ProfileName", "data.PHYType": "PHYType", "data.AuthenticationAlgorithm": "AuthenticationAlgorithm", "data.Reason": "Reason"}
        for event in self.from_module.run(path):
            yield {field2: event.get(field, '-') for field, field2 in selected_fields.items()}

            if event["event.code"] == "8003":
                net_down.append(event)
            elif event["event.code"] == "8001":
                net_up.append(event)

        results = []

        for e in net_up:
            flag = True
            for ev in net_down:
                if ev['data.ConnectionId'] == e['data.ConnectionId'] and ev['event.created'] > e['event.created']:
                    results.append({'WirelessUp': e['event.created'], 'WirelessDown': ev['event.created'], 'SSID': e.get('data.SSID', '-'), 'MAC': e.get('data.BSSID', '-'), 'Reason': ev.get('data.Reason', '-')})
                    flag = False
                    break
            if flag:
                results.append({'WirelessUp': e['event.created'], 'WirelessDown': '', 'SSID': e.get('data.SSID', '-'), 'MAC': e.get('data.BSSID', '-'), 'Reason': ''})
        save_md_table(results, config=None,
                      outfile=os.path.join(os.path.dirname(self.myconfig('outfile')), 'network.md'),
                      fieldnames='WirelessUp WirelessDown SSID MAC Reason',
                      file_exists='OVERWRITE')


class USB(base.job.BaseModule):
    """ Extracts events related with usb plugs

    Events should be sorted"""
    def run(self, path=None):
        """ Extracts USB sticks' plugins and plugoffs data """

        PluginsIds = ('2003', '2010')
        PlugoffsIds = ('2100', '2101')
        plugins = []
        plugoffs = []

        results = []

        for event in self.from_module.run(path):
            yield event

            if event['event.code'] in PluginsIds and self.check(event, 0, plugins, plugoffs):
                plugins.append(event)
            elif event['event.code'] in PlugoffsIds and self.check(event, 1, plugins, plugoffs):
                plugoffs.append(event)

        for e in plugins:
            flag = True
            for ev in plugoffs:
                if ev['data.Lifetime'] == e['data.Lifetime'] and ev['data.Instance'] == e['data.Instance'] and ev['event.created'] > e['event.created']:
                    results.append({'Plugin': e['event.created'], 'Plugoff': ev['event.created'], 'Device': e['data.Instance']})
                    flag = False
                    break
            if flag:
                results.append({'Plugin': e['event.created'], 'Plugoff': '', 'Device': e['data.Instance']})
                results.append([e['event.created'], '', e['data.Instance']])
        save_md_table(results, config=None,
                      outfile=os.path.join(os.path.dirname(self.myconfig('outfile')), 'usb_plugs.md'),
                      fieldnames='Plugin Plugoff Device',
                      file_exists='OVERWRITE')

    def check(self, e, flag, plugins, plugoffs):
        """
        usb_main auxiliary function
        """
        if flag == 0:
            for event in plugins:
                if event['event.created'] == e['event.created'] and event["data.Instance"] == e["data.Instance"] and event["data.Lifetime"] == e["data.Lifetime"]:
                    return False  # already used
        else:
            for event in plugoffs:
                if event['event.created'] == e['event.created'] and event["data.Instance"] == e["data.Instance"] and event["data.Lifetime"] == e["data.Lifetime"]:
                    return False  # already used
            for evento in plugins:
                if event['event.created'] == e['event.created'] and event["data.Instance"] == e["data.Instance"] and event["data.Lifetime"] == e["data.Lifetime"]:
                    return False  # same time, does not used
        return True


class USBConnections(base.job.BaseModule):
    """ Extracts events related with usb plugs

    Events should be sorted"""

    def run(self, path=None):
        """ Extracts USB sticks' plugins and plugoffs data """
        # TODO: filter only USB devices on event 507

        plugins = []
        plugoffs = []
        results = []

        for event in self.from_module.run(path):
            if event['event.code'] == '1006' and not event['data.DeviceID'].startswith('USB'):
                continue
            yield event

            if event['event.action'] == "device-connected":
                plugins.append(event)
            else:
                plugoffs.append(event)

        # Delete unnecessary close events
        for plug_list in [plugins, plugoffs]:
            plug_list.sort(key=lambda k: k['event.created'])
            self.del_close_events(plug_list)

        all_plugs = plugins + plugoffs
        all_plugs.sort(key=lambda k: k['event.created'])
        for e in all_plugs:
            if 'data.DeviceID' not in e:
                e['data.DeviceID'] = ''
            results.append(e)
        save_md_table(results, config=None,
                      outfile=os.path.join(os.path.dirname(self.myconfig('outfile')), 'usb_connections.md'),
                      fieldnames='event.created event.code event.action data.DeviceID',
                      file_exists='OVERWRITE')

    def del_close_events(self, ev_list, threshold=1000):
        # Delete unnecessary close events (threshold in milliseconds)
        previous_datetime = datetime.datetime.fromtimestamp(3333333333)
        total_plugins = len(ev_list)
        for index, e in enumerate(reversed(ev_list)):  # List is reversed so deleting an item does not skip the next iteration
            if e['event.code'] == '1006':
                continue
            if previous_datetime - datetime.datetime.strptime(e['event.created'], "%Y-%m-%d %H:%M:%S.%f %Z") < datetime.timedelta(milliseconds=1000):
                del ev_list[total_plugins - index - 1]
