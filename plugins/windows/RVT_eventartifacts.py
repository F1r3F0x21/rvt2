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


import ujson as json
import os
import ast
import datetime
import re
import dateutil.parser
import hashlib
import base64
import base.job
from collections import defaultdict
from base.utils import save_md_table, save_csv, date_to_iso, sanitize_ip, get_duration
from plugins.windows.RVT_os_info import CharacterizeWindows
from plugins.windows.RVT_events import load_fields


class Filter_Events(base.job.BaseModule):
    """ Filters events for generating a csv file """

    def run(self, path=None):
        events = ast.literal_eval(self.config.config[self.config.job_name]['events_dict'])

        for event in self.from_module.run(path):
            if event['event.code'] in events.keys() and event['event.provider'] == events[event['event.code']]:
                yield event
            if "*" in events.keys() and event['event.provider'] == events["*"]:
                yield event


class IncomingLogon(base.job.BaseModule):
    """ Extracts incoming logon and RDP information from Windows events
        - 21, 22, 23, 24, 25, 39, 40 (TerminalServices-LocalSessionManager)
        - 65, 66, 102, 131, 140 (RemoteDesktopServices-RdpCoreTS)
        - 1149 (TerminalServices-RemoteConnectionManager)
        - 4624, 4625, 4634, 4647, 4648, 4776, 4778, 4779 (Security-Auditing)
        - 12, 13 (Microsoft-Windows-Kernel-General)
        - 4 (OpenSSH)
    """

    def run(self, path=None):
        """
        Attrs:
            path (str): Absolute path to the parsed Security.xml
        """

        self.check_params(path, check_path=True, check_path_exists=True)

        logID = defaultdict(list)
        actID = defaultdict(list)
        openssh = []
        events_4778_4779 = []
        events_65_66 = []
        self.events_12_13 = []

        for event in self.from_module.run(path):
            # Skip informational OpenSSH events
            if event['event.code'] == '4' and 'service' in event.get('category', []):
                continue
            # Skip event 4648 if it refers to an outgoing authentication
            if event.get('event.code', '') == "4648":
                if not (event.get('data.TargetServerName', '') == 'localhost') or (event.get('destination.user.name', '').endswith('$')):
                    continue

            # Main output structure
            ev = {
                'TimeCreated': event.get('event.created', ''),
                'EventID': event.get('event.code', ''),
                'Description': event.get('message', ''),
                'LogonType': event.get('data.LogonType', ''),           # Events 4624, 4625, 4634 (Security)
                'LogonTypeStr': event.get('data.LogonTypeStr', ''),     # Events 4624, 4625, 4634 (Security)
                'LogonID': '',
                'SessionID': event.get('data.SessionID', ''),           # Events 21, 22, 23, 24, 25, 39, 40 (TerminalServices-LocalSessionManager) and event 66 (RemoteDesktopServices-RdpCoreTS)
                'ActivityID': event.get('data.ActivityID', ''),
                'User': '',
                'TargetUser': '',
                # 'TargetServer': event.get('data.TargetServerName', ''), # Event 4648 (security)
                'SourceIP': '',
                'SourcePort': event.get('source.port', ''),             # Events 4624, 4625, 4648 (Security)
                'SourceHostname': event.get('client.hostname', ''),     # Events 4624, 4776, 4778, 4779 (Security)
                'ConnectionName': '',
                'ProcessName': event.get('process.name', ''),           # Events 4624, 4625, 4648 (Security)
                'LogonProcessName': event.get('data.LogonProcessName', '').strip(),  # Events 4624, 4625 (Security)
                'AuthenticationPackageName': event.get('data.AuthenticationPackageName', ''),  # Events 4624, 4625 (Security)
                'ConnType': event.get('network.transport', ''),         # Event 131 (RemoteDesktopServices-RdpCoreTS)
                'ReasonStr': ''
            }

            if ev['EventID'] in ["12", "13"]:
                self.events_12_13.append(ev)
                yield ev
                continue  # No extra data on these events

            for ip_name in [
                'client.ip',       # Events 131 (RemoteDesktopServices-RdpCoreTS)
                'client.address',  # Events 131 (RemoteDesktopServices-RdpCoreTS), 4478, 4779 (Security)
                'source.ip',       # Events 4624, 4625 (Security), 4 (OpenSSH)
                'source.address'   # Events 21, 22, 24, 25 (TerminalServices-LocalSessionManager), 1149 (TerminalServices-RemoteConnectionManager), 140 (RemoteDesktopServices-RdpCoreTS), 4648 (Security)
                ]:
                if ip_name in event.keys():
                    ev['SourceIP'] = event[ip_name]
            if ev['EventID'] == "131":
                ev['SourceIP'], ev['SourcePort'] = sanitize_ip(ev['SourceIP'])
            if "data.ConnectionName" in event.keys():
                ev['ConnectionName'] = event['data.ConnectionName']  # Events 65 and 66 (RemoteDesktopServices-RdpCoreTS)
            else:
                ev['ConnectionName'] = event.get('data.SessionName', '')  # Events 4778 and 4779 (Security)
            if 'data.ReasonStr' in event.keys():  # Event 40 (TerminalServices-LocalSessionManager)
                ev['ReasonStr'] = event['data.ReasonStr']
            elif 'data.Error' in event.keys():  # Event 4625, 4776 (Security)
                ev['ReasonStr'] = event['data.Error']
            else:
                ev['ReasonStr'] = event.get('data.Reason', '')
            if 'data.Reason' in event.keys():  # Only event 40 (TerminalServices-LocalSessionManager)
                ev['Reason'] = event.get('data.Reason', '')
            if 'source.user.name' in event.keys():  # Events 4624, 4625, 4648 (Security)
                if event['source.user.name'] != '-':
                    ev['User'] = f"{event.get('source.domain', '')}\\{event['source.user.name']}"
            else:
                ev['User'] = '-'
            if 'destination.user.name' in event.keys():  # Events 21, 23, 24, 25 (TerminalServices-LocalSessionManager), 1149 (TerminalServices-RemoteConnectionManager), 4624, 4625, 4634, 4647, 4648, 4478, 4776, 4779 (Security)
                ev['TargetUser'] = '-'
                if event['destination.user.name'] != '-':
                    if event.get('destination.domain', ''):
                        ev['TargetUser'] = f"{event['destination.domain']}\\{event['destination.user.name']}"
                    else:
                        ev['TargetUser'] = event['destination.user.name']
            else:
                ev['TargetUser'] = ''
            if 'data.TargetLogonId' in event.keys():  # Events 4624, 4634, 4647 (Security)
                ev['LogonID'] = event['data.TargetLogonId']
            elif 'data.SubjectLogonId' in event.keys():  # Event 4648, 4625 (Security)
                ev['LogonID'] = event['data.SubjectLogonId']
            else:
                ev['LogonID'] = event.get('data.LogonID', '')  # Events 4778, 4779 (Security)
            if ev['EventID'] == "4776":
                ev['AuthenticationPackageName'] = 'NTLM'

            # Join events by LogonId and ActivityID
            if ev['EventID'] in ("4624", "4634", "4647"):  # Ignore event 4648 because the LogonID does not correlate. Ignore 4625 because it is the SubjectLogonId
                logID[ev['LogonID']].append(ev)
            elif ev['EventID'] == "4":  # OpenSSH
                if 'start' in event.get('type', []):
                    ev["ConnType"] = "logon"
                elif 'end' in event.get('type', []):
                    ev["ConnType"] = "logoff"
                else:
                    ev["ConnType"] = ""
                openssh.append(ev)
            elif ev['EventID'] in ("4778", "4779"):
                logID[ev['LogonID']].append(ev)
                events_4778_4779.append(ev)
            elif ev['EventID'] in ("65", "66"):
                events_65_66.append(ev)
            if ev['EventID'] in ("21", "23", "24", "25", "39", "40", "65", "66", "102", "131", "140", "1149"):
                actID[ev['ActivityID']].append(ev)
            final_event = ev.copy()
            final_event.pop('Reason', '')   # Only needed for actID, but ignored in the final result
            yield final_event

        # Correlate events (4778, 4779) with events (65, 66)
        # Do this outside the loop since events are provided sorted by source and not in strict chronological order
        for to_relate_event in events_4778_4779:
            activity = self._relateIDs(to_relate_event, events_65_66)
            if activity != '':
                actID[activity].append(to_relate_event)
        self.events_12_13 = sorted(self.events_12_13, key=lambda k: k['TimeCreated'])

        # Create additional tables combining events
        self.extractLogon(logID)            # Generates `incoming_sessions.md`
        self.extractRDP(actID)              # Generates `rdp_incoming.md/csv`
        self.extractLogon8(logID, openssh)  # Generates `logons_cleartext.md/csv` and `openssh_sessions.md/csv`

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

    def _relateIDs(self, ev, ev_65_66):
        """ Assign an activityID to events 4778 and 4779 based on the closest events 65 and 66
        Args:
            ev (dict): event 4778 or 4779 to relate
            ev_65_66 (list): list of dicts containing events 65 and 66
        Returns:
            str: activityID closer to ev
        """
        d0 = 100000
        actual_actID = ''
        t0 = dateutil.parser.parse(ev['TimeCreated'])
        for event in ev_65_66:
            if event['EventID'] in ("65", "66") and ev['ConnectionName'] == event['ConnectionName']:
                d1 = abs((dateutil.parser.parse(event['TimeCreated']) - t0).total_seconds())
                if d1 < d0:  # Take the closest of the RdpCoreTS events with same ConnectionName
                    actual_actID = event['ActivityID']
                    d0 = d1
        return actual_actID

    def _power_time(self, previous_time, current_time):
        """ Get the oldest poweron/poweroff event between 'previous_time' and 'current_time' """

        for ev in self.events_12_13:
            if current_time > ev['TimeCreated'] > previous_time:
                if ev['EventID'] == "13":
                    return (ev['TimeCreated'], 'poweroff')
                else:
                    return (ev['TimeCreated'], 'poweron')
        return (current_time, 'unknown')

    def extractLogon(self, logID):
        """
        Gets successful logon sessions from the following Security events:
        4624, 4634, 4647, 4778, 4779
        """

        results = self._extract_logon(logID)
        sort_module = base.job.load_module(self.config, 'base.mutations.SortResults', extra_config={'fields': 'Logon Logoff', 'ignore_empty': True}, from_module=results)
        results_sorted = list(sort_module.run())
        save_md_table(results_sorted, config=None,
                      outfile=os.path.join(os.path.dirname(self.myconfig('outfile')), 'incoming_sessions.md'),
                      file_exists='OVERWRITE')

    def _extract_logon(self, logID):
        for logon_id, eventlist in logID.items():
            empty_result = {
                'Logon': '',
                'Logoff': '',
                'IP': '-',
                'Hostname': '',
                'User': '',
                'LogonType': '',
                'LogonTypeStr': '',
                'LogonProcessName': '',
                'AuthenticationPackage': '',
                'ProcessName': '',
                'Duration': '',
                'Comment': '',
                'LogonID': logon_id
            }
            result = empty_result
            ln = len(eventlist)
            pending = False
            for e, v in enumerate(sorted(eventlist, key=lambda d: d['TimeCreated'])):
                # if v['LogonType'] in ("3", "4", "5"):
                #     continue
                if v['EventID'] == '4624':  # Logon
                    result.update({
                        'Logon': v['TimeCreated'],
                        'IP': v.get('SourceIP'),
                        'Hostname': v.get('SourceHostname'),
                        'User': v['TargetUser'],
                        'LogonType': v['LogonType'],
                        'LogonTypeStr': v['LogonTypeStr'],
                        'LogonProcessName': v.get('LogonProcessName'),
                        'AuthenticationPackage': v.get('AuthenticationPackageName'),
                        'ProcessName': v.get('ProcessName')
                    })
                    pending = True
                elif v['EventID'] == '4778':  # Reconnect
                    if result['Logoff']:  # Previously desconnected
                        result['Duration'] = get_duration(result['Logon'], result['Logoff'])
                        yield result
                        result = empty_result
                    result.update({
                        'Logon': v['TimeCreated'],
                        'IP': v.get('SourceIP'),
                        'Hostname': v.get('SourceHostname'),
                        'User': v['TargetUser'],
                        'Comment': 'Reconnection'
                    })
                    pending = True
                elif v['EventID'] == '4779':  # Disconnect
                    result.update({
                        'Logoff': v['TimeCreated'],
                        'IP': v.get('SourceIP'),
                        'Hostname': v.get('SourceHostname'),
                        'User': v['TargetUser']
                    })
                    pending = True
                elif v['EventID'] == '4647':  # Logoff
                    result.update({
                        'Logoff': v['TimeCreated'],
                        'User': v['TargetUser']
                    })
                    pending = True
                elif v['EventID'] == '4634':  # Logoff
                    result.update({
                        'Logoff': v['TimeCreated'],
                        'User': v['TargetUser'],
                        'LogonType': v['LogonType'],
                        'LogonTypeStr': v['LogonTypeStr']
                    })
                    result['Duration'] = get_duration(result['Logon'], result['Logoff'])
                    yield result
                    result = empty_result
                    pending = False
                    continue
                if e == ln - 1 and pending:
                    result['Duration'] = get_duration(result['Logon'], result['Logoff'])
                    yield result

    def extractRDP(self, actID):
        """
        Takes into account the following events:
        21,23,24,25,39,40 (TerminalServices-LocalSessionManager)
        65,66,102,131,140 (RemoteDesktopServices-RdpCoreTS)
        1149 (TerminalServices-RemoteConnectionManager)
        4778,4779 (Security-Auditing)
        """

        results = []
        for activity_id, eventlist in actID.items():
            if not activity_id:
                continue  # Events without ActivityID are not reliable
            empty_result = {
                'Logon': '',
                'Logoff': '',
                'SourceIP': '',
                'SourceHost': '',
                'TargetUser': '',
                'Outcome': 'unknown',  # (success, failure, unknown)
                'Duration': '',
                'Reason': '',  # End of session reason
                'ConnectionName': '',
                'ActivityID': activity_id,
                'SessionID': '',
                'Comment': ''
            }
            act = empty_result.copy()
            insession = False
            completed = False  # If True --> At least one session recorded
            success = False
            # Keep track of start and end times for the different log sources
            start_time = ''     # "TerminalServices-LocalSessionManager" start events (21, 25)
            end_time = ''       # "TerminalServices-LocalSessionManager" end events (23, 24, 39, 40)
            core_ts_start = ''  # "RemoteDesktopServices-RdpCoreTS" start events (131, 65, 66)
            core_ts_end = ''    # "RemoteDesktopServices-RdpCoreTS" end events (102, 140)
            rcm_start = ''      # "TerminalServices-RemoteConnectionManager" start event (1149)
            aux_end = ''

            for v in sorted(eventlist, key=lambda d: d['TimeCreated']):
                if v['EventID'] == '131':  # Network Connection -> The server accepted a new TCP connection from client
                    act['SourceIP'] = v.get('SourceIP')
                    core_ts_start = v['TimeCreated']
                elif v['EventID'] == '65':  # Network Connection -> Connection RDP-Tcp#xx created
                    act['ConnectionName'] = v.get('ConnectionName')
                    core_ts_start = v['TimeCreated']
                elif v['EventID'] == '1149':  # Network Connection -> User authentication succeeded
                    act.update({
                        'SourceIP': v['SourceIP'],
                        'TargetUser': v['TargetUser']
                    })
                    rcm_start = v['TimeCreated']
                elif v['EventID'] == '66':  # Logon -> The connection RDP-Tcp#xx was assigned to session Y
                    act['ConnectionName'] = v.get('ConnectionName')
                    act['SessionID'] = v.get('SessionID')
                    success = True
                    core_ts_start = v['TimeCreated']
                    end_time = aux_end = ''
                elif v['EventID'] == '140':  # Authentication -> Failed because the user name or password is not correct
                    act.update({
                        'Logoff': v['TimeCreated'],
                        'SourceIP': v.get('SourceIP', act['SourceIP']),
                        'Outcome': 'failure',
                        'Reason': 'Authentication Failure'
                    })
                    success = False
                    act['Duration'] = get_duration(act['Logon'], act['Logoff'])
                    results.append(act.copy())
                    success = False
                    act = empty_result.copy()
                    start_time = end_time = core_ts_start = core_ts_end = rcm_start = aux_end = ''
                    aux_end = v['TimeCreated']
                    core_ts_end = v['TimeCreated']
                elif v['EventID'] in ('21', '25'):  # Logon -> Session logon/reconnection succeeded
                    if start_time:
                        if self.__difTimestamp__(v["TimeCreated"], start_time) < 1:  # Logon event repeated
                            continue
                        else:  # Unfinished event
                            act['Logon'] = start_time
                            if end_time and end_time > start_time:
                                act['Logoff'] = end_time
                            else:
                                # Try to get a poweroff event time as logoff time
                                dt, power_event_type = self._power_time(act['Logon'], v['TimeCreated'])
                                act['Logoff'] = dt
                                act['Comment'] = 'Session end time not reliable'
                                if power_event_type == 'poweroff':
                                    act['Reason'] = 'Possible computer poweroff or restart'
                                elif power_event_type == 'poweron':
                                    act['Reason'] = "Start event, possibly caused by an unexpected poweroff"
                                else:
                                    act['Reason'] = "Unknown"
                            act['Duration'] = get_duration(act['Logon'], act['Logoff'])
                            results.append(act.copy())
                            completed = True
                            success = False
                            act = empty_result.copy()
                            start_time = end_time = core_ts_start = core_ts_end = rcm_start = aux_end = ''
                    insession = True
                    success = True
                    start_time = v['TimeCreated']
                    end_time = aux_end = ''
                    act.update({
                        'SourceIP': v.get('SourceIP'),
                        'TargetUser': v['TargetUser'],
                        'Outcome': 'success',
                        'SessionID': v.get('SessionID'),
                        'Comment': "Reconnection" if v["EventID"] == '25' else ''
                    })
                elif v['EventID'] == '102':  # Session Disconnect -> The server has terminated main RDP connection with the client
                    core_ts_end = v['TimeCreated']
                elif v['EventID'] == '39':  # Session Disconnect -> Session X has been disconnected by session Y
                    end_time = v['TimeCreated']
                    success = True
                elif v['EventID'] == '40':  # Session Disconnect -> Session X has been disconnected, reason code Z
                    if v.get('Reason') == '0':  # Do not write "No additional information is available"
                        act['Reason'] = ''
                    else:
                        act['Reason'] = v['ReasonStr']
                    end_time = v['TimeCreated']
                    success = True
                elif v['EventID'] in ('4778', '4779'):  # Session Disconnect/Reconnect
                    act.update({
                        'SourceIP': v.get('SourceIP'),
                        'SourceHost': v.get('SourceHostname'),
                        'TargetUser': v['TargetUser'],
                        'ConnectionName': v.get('ConnectionName')
                    })
                elif v['EventID'] in ('23', '24'):  # 23 (Session logoff succeeded) / 24 (Session has been disconnected)
                    # Skip the second of two consecutive logoff events. When logging off, 23 comes first and then 24 may appear. When start -> disconnect, 24 may come before 23
                    if not insession and self.__difTimestamp__(v["TimeCreated"], aux_end) < 5:  # 5 seconds is a compromise time range
                        start_time = end_time = core_ts_start = core_ts_end = rcm_start = aux_end = ''
                        insession = False
                        continue
                    elif not insession and not act['Reason']:
                        act['Comment'] = 'Possible timeout'
                    if v['EventID'] == '23' and not act.get('Reason'):
                        act['Reason'] = 'Session logoff succeeded'
                    insession = False
                    act.update({
                        'Logoff': v['TimeCreated'],
                        'TargetUser': v['TargetUser'],
                        'SourceIP': act['SourceIP'] or v.get('SourceIP', ''),  # Despite event 24 has IP data, this value is not as reliable as other events
                        'Outcome': 'success',
                        'SessionID': v.get('SessionID')
                    })
                    if start_time:
                        act['Logon'] = start_time
                    elif core_ts_start:
                        act['Logon'] = core_ts_start
                        act['Comment'] = 'Session start time not reliable'
                    elif rcm_start:
                        act['Logon'] = rcm_start
                        act['Comment'] = 'Session start time not reliable'
                    else:
                        act['Logon'] = '-'
                    act['Duration'] = get_duration(act['Logon'], act['Logoff'])
                    results.append(act.copy())
                    completed = True
                    success = False
                    act = empty_result.copy()
                    start_time = end_time = core_ts_start = core_ts_end = rcm_start = aux_end = ''
                    aux_end = v['TimeCreated']

            # Handle abnormal end of ActivityID scenarios
            # 1. No formal "LocalSessionManager" end
            if start_time:
                act['Logon'] = start_time
                act['Reason'] = act['Reason'] or 'Unknown'
                if (end_time and end_time > start_time):  # Unknown disconnection reason
                    act['Logoff'] = end_time
                elif (core_ts_end and core_ts_end > start_time):   # Unexpected "RemoteDesktopServices-RdpCoreTS" end
                    act['Logoff'] = core_ts_end
                    act['Comment'] = "No formal end to the session"
                else:   # Session still running
                    act['Logoff'] = '-'
                    act['Reason'] = ''
                    act['Comment'] = 'Active session'
                act['Duration'] = get_duration(act['Logon'], act['Logoff'])
                results.append(act.copy())
            # 2. Session with no successful start
            elif end_time:
                # Previous data exists in "TerminalServices-LocalSessionManager".
                if completed:  # Sometimes event 40 is recorded after 24. This means the session formally ends with 24 but no actual connection was stablished since event 40
                    continue
                # No previous data in "TerminalServices-LocalSessionManager"
                act['Logoff'] = end_time
                act['Outcome'] = 'success'
                act['Comment'] = 'Session start time not reliable'
                if (core_ts_start and core_ts_start < end_time):  # Previous data in "RdpCoreTS"
                    act['Logon'] = core_ts_start
                elif (rcm_start and rcm_start < end_time):  # Previous data in "RemoteConnectionManager"
                    # Usually those records last longer, but the event time will be of the first connection, ignoring recoonections
                    act['Logon'] = rcm_start
                else:   # No previous data at all
                    act['Logon'] = '-'
                act['Duration'] = get_duration(act['Logon'], act['Logoff'])
                results.append(act.copy())
            # 3. "RdpCoreTS" sessions with no "TerminalServices-LocalSessionManager" events
            elif core_ts_end and not completed:
                act['Logoff'] = core_ts_end
                act['Outcome'] = 'success' if success else 'failure'
                if (core_ts_start and core_ts_start < core_ts_end):
                    act['Logon'] = core_ts_start
                elif (rcm_start and rcm_start < end_time):
                    act['Logon'] = rcm_start
                    act['Outcome'] = 'unknown'
                else:
                    act['Logon'] = '-'
                act['Duration'] = get_duration(act['Logon'], act['Logoff'])
                results.append(act.copy())
            # 4. Only an event 1149
            elif rcm_start:
                act['Logon'] = rcm_start
                act['Outcome'] = 'unknown'
                act['Logoff'] = '-'
                act['Duration'] = get_duration(act['Logon'], act['Logoff'])
                results.append(act.copy())

        # Sort results
        sort_module = base.job.load_module(self.config, 'base.mutations.SortResults', extra_config={'fields': 'Logon Logoff', 'ignore_empty': True}, from_module=results)
        results_sorted = list(sort_module.run())
        # Output results in CSV and JSON
        save_csv(results_sorted, config=None,
                 outfile=os.path.join(os.path.dirname(self.myconfig('outfile')), 'rdp_incoming.csv'),
                 file_exists='OVERWRITE')
        save_md_table(results_sorted, config=None,
                      outfile=os.path.join(os.path.dirname(self.myconfig('outfile')), 'rdp_incoming.md'),
                      file_exists='OVERWRITE')

    def _find_closest_date(self, loginfo, openssh):
        """ Get values for IP and port given OpenSSH events"""
        login = None
        logoff = None
        if 'Login (UTC)' in loginfo.keys():
            login = datetime.datetime.strptime(loginfo['Login (UTC)'], "%Y-%m-%d %H:%M:%S")
        if 'Logoff (UTC)' in loginfo.keys():
            logoff = datetime.datetime.strptime(loginfo['Logoff (UTC)'], "%Y-%m-%d %H:%M:%S")

        for ev in openssh:
            if 'Login (UTC)' in loginfo.keys() and 'Logoff (UTC)' in loginfo.keys():
                if loginfo['Login (UTC)'] <= ev['TimeCreated'][:19] <= loginfo['Logoff (UTC)']:
                    return ev['SourceIP'], ev['SourcePort']
            elif 'Login (UTC)' not in loginfo.keys():  # if Security events are not long enough
                if ev['TimeCreated'][:19] <= loginfo['Logoff (UTC)']:
                    dte = datetime.datetime.strptime(ev['TimeCreated'][:19], "%Y-%m-%d %H:%M:%S")
                    if (logoff - dte).total_seconds() < 5:
                        return ev['SourceIP'], ev['SourcePort']
            elif 'Logoff (UTC)' not in loginfo.keys():  # if session is still active
                if loginfo['Login (UTC)'] <= ev['TimeCreated'][:19]:
                    dte = datetime.datetime.strptime(ev['TimeCreated'][:19], "%Y-%m-%d %H:%M:%S")
                    if (dte - login).total_seconds() < 5:
                        return ev['SourceIP'], ev['SourcePort']
        return "", ""

    def extractLogon8(self, logID, openssh):
        """ Only events 4624 and 4634 with LogonType 8 (ClearPassword) and events 4 of OpenSSH """

        results = []
        event_types = {'4624': 'Login (UTC)', '4634': 'Logoff (UTC)'}
        logons = defaultdict(dict)
        openssh = sorted(openssh, key=lambda d: d['TimeCreated'])

        for eventlist in logID.values():
            for e, v in enumerate(eventlist):
                if v['EventID'] not in ["4624", "4634"]:
                    continue
                if not v['LogonType'] == "8":
                    continue
                logon_id = v['LogonID']
                event_type = event_types[v['EventID']]
                logons[logon_id][event_type] = date_to_iso(v['TimeCreated'], sep=' ', timespec='seconds', hide_tz=True, logger=self.logger())
                logons[logon_id]['User'] = v['TargetUser']
                logons[logon_id]['LogonType'] = v['LogonTypeStr']
                # The following information is only available in 4624 events
                if v['EventID'] == "4624":
                    logons[logon_id]['SourceIP'] = v.get('SourceIP')
                    logons[logon_id]['SourcePort'] = v.get('SourcePort')
                    logons[logon_id]['ProcessName'] = v['ProcessName']
                    logons[logon_id]['AuthenticationPackage'] = v['AuthenticationPackageName']
        for logid in logons.keys():
            if 'Login (UTC)' in logons[logid] and 'Logoff (UTC)' in logons[logid]:
                logons[logid]['Duration'] = get_duration(logons[logid]['Login (UTC)'], logons[logid]['Logoff (UTC)'], date_format="%Y-%m-%d %H:%M:%S")
            if logons[logid].get('SourceIP') in ('', '-', '::') and logons[logid]['ProcessName'] == 'C:\\Windows\\System32\\OpenSSH\\sshd.exe':
                # Complete the missing source IP information with events 8 from OpenSSH
                logons[logid]['SourceIP'], logons[logid]['SourcePort'] = self._find_closest_date(logons[logid], openssh)

        results = [logon for logon in logons.values()]
        sort_module = base.job.load_module(self.config, 'base.mutations.SortResults', extra_config={'fields': '"Login (UTC)" "Logoff (UTC)"', 'ignore_empty': True}, from_module=results)
        results_sorted = list(sort_module.run())

        save_csv(results_sorted, config=None,
                 outfile=os.path.join(os.path.dirname(self.myconfig('outfile')), 'logons_cleartext.csv'),
                 fieldnames="['Login (UTC)', 'Logoff (UTC)', 'Duration', 'User', 'SourceIP', 'SourcePort', 'LogonType', 'ProcessName', 'AuthenticationPackage']",
                 file_exists='OVERWRITE')
        save_md_table(results_sorted, config=None,
                      outfile=os.path.join(os.path.dirname(self.myconfig('outfile')), 'logons_cleartext.md'),
                      fieldnames="['Login (UTC)', 'Logoff (UTC)', 'Duration', 'User', 'SourceIP', 'SourcePort', 'LogonType', 'ProcessName', 'AuthenticationPackage']",
                      backticks_fields='User',
                      date_fields="['Login (UTC)', 'Logoff (UTC)']",
                      file_exists='OVERWRITE')

        # Generates a table using OpenSSH events
        # There is no identifier to discriminate sessions. 'SourcePort' is the next best thing
        results = []
        temporal_dict = {}
        for ev in openssh:
            if 'logoff' not in ev['ConnType'] and 'logon' not in ev['ConnType']:
                continue
            s_port = ev['SourcePort']
            if ev['Description'].startswith("Received"):
                to_be_popped = []
                for k in temporal_dict:
                    if 'Login (UTC)' in temporal_dict[k] and temporal_dict[k]['Login (UTC)'] < ev['TimeCreated']:
                        temporal_dict[k]['Logoff (UTC)'] = ev['TimeCreated']
                        temporal_dict[k]['Duration'] = get_duration(temporal_dict[k]['Login (UTC)'], ev['TimeCreated'])
                        results.append(temporal_dict[k])
                        to_be_popped.append(k)
                for p in to_be_popped:
                    temporal_dict.pop(p)
                continue
            if s_port not in temporal_dict.keys():  # New login
                if ev['ConnType'] == 'logoff':  # Misses logon event
                    results.append({'Logoff (UTC)': ev['TimeCreated'], 'User': ev['User'], 'IP': ev['SourceIP'], 'Port': s_port})
                elif ev['ConnType'] == 'logon':
                    temporal_dict[s_port] = {'Login (UTC)': ev['TimeCreated'], 'User': ev['User'], 'IP': ev['SourceIP'], 'Port': s_port}
            else:
                if ev['ConnType'] == 'logoff':
                    temporal_dict[s_port]['Logoff (UTC)'] = ev['TimeCreated']
                    temporal_dict[s_port]['Duration'] = get_duration(temporal_dict[k]['Login (UTC)'], ev['TimeCreated'])
                    results.append(temporal_dict[s_port])
                    temporal_dict.pop(s_port)
                elif ev['ConnType'] == 'logon':  # Two consecutives logon events
                    temporal_dict[s_port] = {'Login (UTC)': ev['TimeCreated'], 'User': ev['User'], 'IP': ev['SourceIP'], 'Port': s_port}

        for k in temporal_dict:
            results.append(temporal_dict[k])

        sort_module = base.job.load_module(self.config, 'base.mutations.SortResults', extra_config={'fields': '"Login (UTC)" "Logoff (UTC)"', 'ignore_empty': True}, from_module=results)
        results_sorted = list(sort_module.run())
        save_csv(results_sorted, config=None,
                 outfile=os.path.join(os.path.dirname(self.myconfig('outfile')), 'openssh_sessions.csv'),
                 fieldnames="['Login (UTC)', 'Logoff (UTC)', 'Duration', 'User', 'IP', 'Port']",
                 file_exists='OVERWRITE')
        save_md_table(results_sorted, config=None,
                      outfile=os.path.join(os.path.dirname(self.myconfig('outfile')), 'openssh_sessions.md'),
                      fieldnames="['Login (UTC)', 'Logoff (UTC)', 'Duration', 'User', 'IP', 'Port']",
                      backticks_fields='User',
                      date_fields="['Login (UTC)', 'Logoff (UTC)']",
                      file_exists='OVERWRITE')


class RDPIncoming(base.job.BaseModule):
    """ Extracts events related to incoming RDP connections """

    def run(self, path=None):
        """
        Attrs:
            path (str): Absolute path to the parsed Security.xml
        """

        self.check_params(path, check_path=True, check_path_exists=True)

        # Events will be categorized by their associated ActivityID. Each key contains a list of events
        aID = {}
        # Get poweron and poweroff events to manage unfinished sessions
        # eID 12: The operating system started
        # eID 13: The operating system is shutting down
        power_ev = []

        for event in self.from_module.run(path):
            ev = dict()
            ev['EventID'] = event.get('event.code', '')
            ev['TimeCreated'] = event.get('event.created', '')

            if ev['EventID'] in ("12", "13"):
                power_ev.append(ev)
                continue

            ev['User'] = event.get('destination.user.name', '')
            ev['SessionID'] = event.get('data.SessionID', '')
            ev['SourceAddress'] = event.get('source.address', '')
            ev['ActivityID'] = event.get('data.ActivityID', ev['SessionID'])
            if ev['ActivityID'] not in aID.keys():
                aID[ev['ActivityID']] = []
            aID[ev['ActivityID']].append(ev)

        for result in self.extractRDP(aID, sorted(power_ev, key=lambda k: k['TimeCreated'])):
            yield result

    def extractRDP(self, aID, power_ev):

        for activity_id, eventlist in aID.items():
            empty_result = {
                'Logon': '-',
                'Logoff': '-',
                'SourceAddress': '',
                'User': '',
                'Comments': '',
                'ActivityID': activity_id
            }
            act = empty_result.copy()
            written = True
            length = len(eventlist) - 1

            for e, v in enumerate(sorted(eventlist, key=lambda k: k['TimeCreated'])):

                if written:  # New login
                    if v['EventID'] in ('21', '22', '25'):
                        if act['SourceAddress'] == '':
                            act['SourceAddress'] = v.get('SourceAddress', '')
                        act['User'] = v.get('User', '')
                        act['Logon'] = v['TimeCreated']
                        written = False
                        if v['EventID'] == '25':
                            act['Comments'] += "Reconnection."

                else:
                    if v['EventID'] in '21':  # Open session without previous logoff
                        dt, reason = self.find_poweroff(act['Logon'], v['TimeCreated'], power_ev)
                        act['Logoff'] = dt
                        if reason == 'poweroff':
                            act['Comments'] += "Poweroff or restart."
                        elif reason == 'poweron':
                            act['Comments'] += "Start event, possibly caused by an unexpected poweroff"
                        else:
                            act['Comments'] += "Unknown date"
                        written = True
                        yield act
                        act = empty_result.copy()

                    elif v['EventID'] in ('23', '24'):
                        act['Logoff'] = v['TimeCreated']
                        yield act
                        act = empty_result.copy()
                        written = True

                if length == e and not written:
                    # Session started but log has ended
                    yield act

    def find_poweroff(self, previous_time, actual_time, power_ev):
        """ Finds date of poweroff or poweron as logout date """

        for ev in power_ev:
            if actual_time > ev['TimeCreated'] > previous_time:
                if ev['EventID'] == "13":
                    return (ev['TimeCreated'], 'poweroff')
                else:
                    return (ev['TimeCreated'], 'poweron')
        return (actual_time, 'unknown')


class RDPGateway(base.job.BaseModule):
    """ Extracts events related to incoming RDP connections """

    def run(self, path=None):
        """
        Attrs:
            path (str): Absolute path to the parsed Security.xml
        """

        self.check_params(path, check_path=True, check_path_exists=True)

        ev = dict()
        users_date = dict()
        user = ''
        for v in sorted(self.from_module.run(path), key=lambda k: k['event.created']):
            ev['EventID'] = v.get('event.code', '')
            ev['TimeCreated'] = v.get('event.created', '')
            ev['User'] = v.get('UserData', {}).get('EventInfo', {}).get('Username', '')
            ev['Protocol'] = v.get('UserData', {}).get('EventInfo', {}).get('ConnectionProtocol', '')
            ev['SourceAddress'] = v.get('UserData', {}).get('EventInfo', {}).get('IpAddress', '')
            ev['SessionDuration'] = v.get('UserData', {}).get('EventInfo', {}).get('SessionDuration', '')
            ev['DestinationAddress'] = v.get('UserData', {}).get('EventInfo', {}).get('Resource', '')
            user = ev['User']

            if ev['EventID'] in ('302'):
                users_date[user] = ev['TimeCreated']

            elif ev['EventID'] in ('303') and users_date.get(user, '-') != '-':
                ev['LogoffDate'] = ev['TimeCreated']
                if str(ev['SessionDuration']) == '0':
                    continue
                yield {
                    'LoginDate': users_date.get(user, '-'),
                    'LogoffDate': ev.get('LogoffDate', '-'),
                    'User': ev.get('User', ''),
                    'SourceAddress': ev.get('SourceAddress', ''),
                    'SessionDuration': ev.get('SessionDuration', ''),
                    'Protocol': ev.get('Protocol', ''),
                    'DestinationAddress': ev.get('DestinationAddress', '')
                }

                users_date[user] = '-'
                ev['LogoffDate'] = '-'
                ev['User'] = ''
                ev['SourceAddress'] = ''


class OutgoingLogon(base.job.BaseModule):
    """ Extracts events related to outgoing RDP connections:
        - 1024, 1025, 1026, 1027, 1029, 1102, 1105 (Microsoft-Windows-TerminalServices-ClientActiveXCore)
        - 4648 (Security)
    """

    def read_config(self):
        super().read_config()
        self.set_default_config('outfile_md', os.path.join(self.myconfig('analysisdir'), 'events', 'rdp_outgoing.md'))

    def run(self, path=None):
        """
        Attrs:
            path (str): Absolute path to the parsed Security.xml
        """
        self.check_params(path, check_path=True, check_path_exists=True)

        # RDP Outgoing events display only user SID. Get user name
        # TODO: events.json should have a way to identify partition
        partition = None
        os_info = CharacterizeWindows(config=self.config)
        users_sid = os_info.get_users_names(partition=partition)

        actID = {}
        self.events_4648 = []
        self.b64_hash_users = {}
        self.servers = defaultdict(list)    # key: IP, values: (hostname, first_occurrence_datetime)
        self.all_addresses = set()
        users_4648 = set()
        hash_version = ''

        for event in self.from_module.run(path):
            # Skip event 4648 if it is an incoming or local authentication
            if event.get('event.code', '') == "4648":
                if (event.get('data.TargetServerName', '') == 'localhost') or (event.get('destination.user.name', '').endswith('$')):
                    continue
            # Get the hash algorithm for the destination user (only one time):
            # https://www.aon.com/cyber-solutions/aon_cyber_labs/remote-desktop-event-log-analysis_variations-in-logging-for-event-id-1029/
            if not hash_version and event.get('event.code', '') == "1029":
                hash_length = len(event.get('data.Base64Hash', '').rstrip('-'))
                # Consider either single or dual hash
                if hash_length in (28, 57):
                    hash_version = 'v1'
                elif hash_length in (44, 89):
                    hash_version = 'v2'

            # Main output structure
            ev = {
                'TimeCreated': event.get('event.created', ''),
                'EventID': event.get('event.code', ''),
                'Description': event.get('message', ''),
                'ActivityID': event.get('data.ActivityID', ''),
                'SourceUser': '',
                'user.id': event.get('user.id', ''),
                'Address': event.get('destination.address', ''),                            # Events 1024, 1102, 4648
                'B64Hash': event.get('data.Base64Hash', ''),                                # Event 1029
                'DestinationUser': event.get('destination.user.name', ''),                  # Event 4648
                'DestinationPort': event.get('destination.port', ''),                       # Event 4648
                'DestinationHost': event.get('data.TargetServerName', ''),                  # Event 4648
                'DestinationDomain': event.get('destination.domain', ''),                   # Events 1027, 4648
                'ReasonCode': event.get('data.Reason'),                                     # Event 1026
                'Reason': event.get('data.ReasonStr') or event.get('data.Reason')           # Event 1026
            }
            if ev['EventID'] == "4648":
                ev['SourceUser'] = event.get('source.user.name', '')
                self.events_4648.append(ev)
            else:
                ev['SourceUser'] = users_sid.get(event.get('user.id', ''), event.get('user.id', ''))

            if ev['ActivityID'] and not ev['EventID'] == "1027":
                if ev['ActivityID'] not in actID.keys():
                    actID[ev['ActivityID']] = []
                actID[ev['ActivityID']].append(ev)
            yield ev

        # Calculate expected b64_hash values
        hash_version = hash_version or 'v2'
        for ev in self.events_4648:
            if ev['DestinationUser'] in users_4648:
                continue
            self.b64_hash_users[self.b64_hash(ev['DestinationUser'], version=hash_version)] = ev['DestinationUser']
            users_4648.add(ev['DestinationUser'])

        # Associate IP with Hostname
        for ev_auth in self.events_4648:
            if ev_auth['Address'] and ev_auth['Address'] != '-':
                found_hostname = False
                if ev_auth['Address'] not in self.servers:
                    self.servers[ev_auth['Address']].append((ev_auth['DestinationHost'], datetime.datetime.strptime(ev_auth['TimeCreated'][:19], "%Y-%m-%d %H:%M:%S")))
                else:
                    for dest_hostname in self.servers[ev_auth['Address']]:
                        if dest_hostname[0] == ev_auth['DestinationHost']:
                            found_hostname = True
                            break
                    if not found_hostname:
                        self.servers[ev_auth['Address']].append((ev_auth['DestinationHost'], datetime.datetime.strptime(ev_auth['TimeCreated'][:19], "%Y-%m-%d %H:%M:%S")))

        # Calculate RDP outgoing sessions
        results = self.extractRDP(actID)
        sort_module = base.job.load_module(self.config, 'base.mutations.SortResults', extra_config={'fields': '"LoginDate" "LogoffDate"', 'ignore_empty': True}, from_module=results)
        results_sorted = list(sort_module.run())
        save_md_table(results_sorted, config=None,
                      outfile=self.myconfig('outfile_md'),
                      date_fields="['LoginDate', 'LogoffDate']",
                      file_exists='OVERWRITE')
        save_csv(results_sorted, config=None,
                 outfile=self.myconfig('outfile_md')[:-2] + 'csv',
                 file_exists='OVERWRITE')

    def b64_hash(self, username, version='v2'):
        """ Calculate the base64 of the HASH of a username/domain
            v1: (Windows 7 / Server 2012 R2) --> sha1
            v2: (Windows 10 / WS 2016) --> sha256
        """
        if version.lower() not in ['v1', 'v2']:
            return ''
        hash_algorithm = {'v1': hashlib.sha1, 'v2': hashlib.sha256}
        username = username.encode('utf-16le')
        hash = hash_algorithm[version.lower()](username).digest()
        return base64.b64encode(hash).decode()

    def _search_authentication(self, event, address):
        """ Get extra information (DestinationUsername and DestinationHostname) from event 4648
            Arguments:
                - **event**: Event 1029 data enriched with same ActivityID events
                - **address**: Set of IPs/Hostnames for the current session
        """
        target_user, target_server = ('', '')
        # Get target server
        for addr in address:
            if addr not in self.all_addresses:
                self.all_addresses.add(addr)
            if addr in self.servers:  # Check if previously calculated
                for server in self.servers[addr]:
                    hostname, first_occurrence = server
                    # Get the last hostname associated with IP given an event time
                    if datetime.datetime.strptime(event['TimeCreated'][:19], "%Y-%m-%d %H:%M:%S") > first_occurrence:
                        target_server = hostname
                if not target_server:
                    target_server = self.servers[addr][0][0]  # Assume the first one after the event is the valid one
                    break
        # Get target user
        b64_hashes = event['B64Hash'].rstrip('-')
        if len(b64_hashes) in (57, 89):  # Dual hash
            for ind_hash in b64_hashes.split('-'):
                if self.b64_hash_users.get(ind_hash):
                    target_user = self.b64_hash_users[ind_hash]
        else:  # Single hash
            target_user = self.b64_hash_users.get(b64_hashes, '')
        return target_user, target_server

    def extractRDP(self, actID):

        for activity_ID, eventlist in actID.items():
            act = {
                'LoginDate': '-',
                'LogoffDate': '-',
                'Address': '',
                'SourceUser': '-',
                'SID': '',
                'B64Hash': '',
                'DestinationUser': '',
                'DestinationHost': '',
                'Status': 'Unknown',
                'Duration': '',
                'ActivityID': activity_ID,
                'Message': ''
            }
            written = True
            success = False
            started = False
            ended = False
            destination_address = set()

            for v in sorted(eventlist, key=lambda k: k['TimeCreated']):
                if not act['SID']:  # Get SID and user from first event
                    act['SID'] = v['user.id']
                    act['SourceUser'] = v['SourceUser']
                if v['EventID'] in ('1024', '1102'):
                    destination_address.add(v['Address'])  # Sometimes IP, sometimes hostname
                    act['LoginDate'] = v['TimeCreated']
                    started = True
                if v['EventID'] == '1102':
                    success = True
                elif v['EventID'] == '1025':  # Login successful
                    act['LoginDate'] = v['TimeCreated']
                    written = False  # Signal there is information yet to be yielded
                    started = True
                    success = True
                elif v['EventID'] == '1029' and not act['B64Hash']:
                    act['B64Hash'] = v.get('B64Hash', '')
                    act['DestinationUser'], act['DestinationHost'] = self._search_authentication(v, destination_address)
                    started = True
                elif v['EventID'] == '1105' and not ended and not success:
                    act['LogoffDate'] = v['TimeCreated']  # Store it in case there is no later event 1026
                    ended = True
                elif v['ReasonCode'] in ['263', '519', '1289', '1801']:  # These events are part of the connection process and do not indicate a session end
                    continue
                elif v['EventID'] == '1026':  # Logoff
                    act['LogoffDate'] = v['TimeCreated']
                    act['Address'] = '/'.join(destination_address)
                    act['Status'] = 'Success' if success else 'Failure'
                    act['Message'] = v.get('Reason', '')
                    act['Duration'] = get_duration(act['LoginDate'], act['LogoffDate'])
                    yield act
                    written = True
                    ended = True
                    # Reset times, for reconnection cases where ActivityID is conserved
                    act['LoginDate'] = '-'
                    act['LogoffDate'] = '-'
                    started = False
                    success = False
            if not written and not ended:  # Unfinished session
                act['Address'] = '/'.join(destination_address)
                act['Status'] = 'Success' if success else 'Failure'
                act['Duration'] = get_duration(act['LoginDate'], act['LogoffDate'])
                yield act
            elif not written and not success:  # Failure or the start took place before available event logs
                act['Address'] = '/'.join(destination_address)
                act['Status'] = 'Failure' if started else 'Success'
                act['Duration'] = get_duration(act['LoginDate'], act['LogoffDate'])
                yield act


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
        unexpected = []
        self.path = path

        for event in self.from_module.run(path):
            ev = dict()
            ev['TimeCreated'] = event.get('event.created', '')
            ev['EventID'] = event.get('event.code', '')
            ev['message'] = event.get('message', '')
            ev['Reason'] = event.get('ReasonStr', '')
            eventlist.append(ev)
            if ev['EventID'] == '41':
                temp = datetime.datetime.strptime(ev['TimeCreated'][:19], '%Y-%m-%d %H:%M:%S')
                temp -= datetime.timedelta(minutes=1)
                unexpected.append(temp.strftime('%Y-%m-%d %H:%M:%S'))
            yield ev
        if len(unexpected) > 0:
            for g in self.guess_poweroff(sorted(unexpected)):
                ev = {'TimeCreated': g,
                      'EventID': '',
                      'message': 'Possible unexpected poweroff',
                      'Reason': ''}
                eventlist.append(ev)
                yield ev
        # self.extractPower(sorted(eventlist, key=lambda d: d['TimeCreated']))

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
                    act = {}
                inpower = True
                act['t0'] = ev['TimeCreated']
                act['d0'] = 'Sleep'
            elif ev['EventID'] == '12':
                if not inpower:
                    results.append([act.get('t0', '-'), 'Boot', act.get('t1', '-')])
                    act = {}
                inpower = True
                act['t0'] = ev['TimeCreated']
                act['d0'] = 'StartBoot'
            elif ev['EventID'] == '13':
                inpower = False
                act['t1'] = ev['TimeCreated']
                act['d1'] = 'Shutdown'
                results.append([act.get('t0', '-'), 'Shut down', act.get('t1', '-')])
                act = {}
            elif ev['EventID'] == '':
                if not inpower:
                    results.append([act.get('t0', '-'), 'Unexpected shutdown', '-'])
                    act = {}
                inpower = True
                act['t0'] = ev['TimeCreated']
                act['d0'] = 'Unexpected reboot'
            elif ev['EventID'] == '42':
                results.append([act.get('t0', '-'), 'Sleeping', act.get('t1', '-')])
                inpower = False
                act['t1'] = ev['TimeCreated']
                act['d1'] = 'Sleeping'
                act = {}

    def guess_poweroff(self, unexpected):
        guess = [""]
        m = len(unexpected)
        i = 0
        import subprocess

        cmd = f"grep -o '\"event.created\": \"20..-..-.....:..:..' {self.path}|sort -u|cut -b 19-"
        output = subprocess.check_output(cmd, shell=True).decode()
        for line in output.split('\n'):
            if unexpected[i] > line:
                guess[i] = line
            else:
                i += 1
                if i == m:
                    return guess
                guess.append(line)


class Hash(base.job.BaseModule):
    """ Extracts events containing file hashes """

    def run(self, path=None):
        """
        Attrs:
            path (str): Absolute path to the parsed events.json
        """

        # self.check_params(path, check_path=True, check_path_exists=True)

        for event in self.from_module.run(path):
            if event['event.code'] == '2050' and event['event.provider'] == 'Microsoft-Windows-Windows Defender':
                event_name = self.get_event_name(event['event.code'], event['event.provider'])
                yield {
                    '@timestamp': event['event.created'],
                    'artifact': event_name,
                    'path': event['EventData']['Filename'],
                    'file_birth': '',
                    'file_modified': '',
                    'hash': event['EventData']['Sha256']
                }

            if event['event.provider'] == 'Microsoft-Windows-AppLocker':
                if event['event.code'] in ['8002', '8004', '8005']:
                    event_name = self.get_event_name(event['event.code'], event['event.provider'])
                    yield {
                        '@timestamp': event['event.created'],
                        'artifact': event_name,
                        'path': event['UserData']['RuleAndFileData']["FullFilePath"],
                        'file_birth': '',
                        'file_modified': '',
                        'hash': event['UserData']['RuleAndFileData']['FileHash']
                    }

            if event['event.provider'] == 'Microsoft-Windows-Sysmon':
                event_name = self.get_event_name(event['event.code'], event['event.provider'])
                if event['event.code'] in ['1']:
                    string_hashes = event['EventData']['Hashes']
                    hash_value = self.get_dict_hashes(string_hashes)

                    yield {
                        '@timestamp': event['event.created'],
                        'artifact': event_name,
                        'path': event['EventData']['Image'],
                        'file_birth': '',
                        'file_modified': '',
                        'hash': hash_value
                    }

                if event['event.code'] in ['6']:
                    string_hashes = event['EventData']['Hashes']
                    hash_value = self.get_dict_hashes(string_hashes)

                    yield {
                        '@timestamp': event['event.created'],
                        'artifact': event_name,
                        'path': event['EventData']['ImageLoaded'],
                        'file_birth': '',
                        'file_modified': '',
                        'hash': hash_value
                    }

                if event['event.code'] in ['15']:
                    string_hashes = event['EventData']['Hash']
                    hash_value = self.get_dict_hashes(string_hashes)

                    yield {
                        '@timestamp': event['event.created'],
                        'artifact': event_name,
                        'path': event['EventData']['TargetFilename'],
                        'file_birth': event['event.created'],
                        'file_modified': '',
                        'hash': hash_value
                    }

    def get_dict_hashes(self, string_hashes):
        hash_pairs = string_hashes.split(",")
        hash_dict = {}
        for hash_pair in hash_pairs:
            algorithm, hash_value = hash_pair.split('=')
            hash_dict[algorithm] = hash_value

        if "SHA256" in hash_dict.keys():
            hash_value = hash_dict["SHA256"]
        elif "MD5" in hash_dict.keys():
            hash_value = hash_dict["MD5"]
        else:
            hash_value = string_hashes

        return hash_value

    def get_event_name(self, event_code, event_provider):

        return "event-" + str(event_code) + "-" + str(event_provider.split("-")[2])


class WLAN(base.job.BaseModule):
    """ Extracts events related with wireless networking (WLAN)

    Events should be sorted
    """

    def run(self, path=None):
        """
        Attrs:
            path (str): Absolute path to events.json, the parsed Microsoft-Windows-WLAN-AutoConfig%4Operational.evtx
        """

        self.check_params(path, check_path=True, check_path_exists=True)

        net_up = []
        net_down = []

        selected_fields = {"event.created": "Created",
                           "event.code": "Code",
                           "data.SSID": "SSID",
                           "data.BSSID": "BSSID",
                           "data.ConnectionId": "ConnectionId",
                           "data.ProfileName": "ProfileName",
                           "data.PHYType": "PHYType",
                           "data.AuthenticationAlgorithm": "AuthenticationAlgorithm",
                           "data.Reason": "Reason"}
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
                      outfile=os.path.join(os.path.dirname(self.myconfig('outfile')), 'wlan.md'),
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
    """ Extracts events related with USB plugs """

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


class USBDevice(object):

    def __init__(self, vendor, model, deviceID, serialN, capacity, volume=''):
        self.Vendor = vendor
        self.Model = model
        self.DeviceID = deviceID
        self.SerialNumber = serialN
        self.Capacity = capacity
        self.VolumeName = volume

    def __eq__(self, other):
        if isinstance(other, self.__class__):
            return (self.DeviceID == other.DeviceID or self.Model == other.Model) and self.SerialNumber == other.SerialNumber
        else:
            return False

    def __ne__(self, other):
        return not self.__eq__(other)

    def __str__(self):
        return str(self.SerialNumber) + self.Model

    def __hash__(self):
        return hash(str(self))

    def to_dict(self):
        return {'Vendor': self.Vendor, 'Model': self.Model, 'DeviceID': self.DeviceID, 'SerialNumber': self.SerialNumber, 'Capacity': self.Capacity}


class USBPlugs2(base.job.BaseModule):
    """ Extracts logon and rdp artifacts """

    def run(self, path=None):
        """
        Extracts information about disk plugs
        """

        self.check_params(path, check_path=True, check_path_exists=True)

        plugs = {}
        devices = []

        for event in self.from_module.run(path):
            ev = dict()
            ev['TimeCreated'] = event.get('event.created', '')
            device = USBDevice(event.get('data.DeviceVendor', ''), event.get('data.DeviceModel', '').rstrip().lstrip(), event.get('data.DeviceID', ''), event.get('data.DeviceSerialNumber', ''), event.get('data.capacity', ''), event.get('data.DeviceVolumeName', ''))
            ev['Description'] = event.get('message', '')
            ev['action'] = event.get('event.action', '')
            ev['VolumeName'] = event.get('data.DeviceVolumeName', '')
            if device not in devices:  # device to put in list
                devices.append(device)
                plugs[device] = []
            else:
                index = devices.index(device)  # sometimes, capacity value is 0
                if devices[index].Capacity == '' or str(devices[index].Capacity) == "0":
                    devices[index].Capacity = event.get('data.capacity', '')
            plugs[device].append({'TimeCreated': ev['TimeCreated'], 'action': ev['action'], 'VolumeName': ev['VolumeName']})

        results = self.get_plugs(plugs)
        sort_module = base.job.load_module(self.config, 'base.mutations.SortResults', extra_config={'fields': 'plugged_in plugged_off', 'ignore_empty': True}, from_module=results)
        results_sorted = list(sort_module.run())
        save_md_table(results_sorted, config=None,
                      outfile=os.path.join(os.path.dirname(self.myconfig('outfile')), 'usb_plugs2.md'),
                      fieldnames='plugged_in plugged_off Vendor Model SerialNumber VolumeName',
                      file_exists='OVERWRITE')
        devices2 = []
        for dev in devices:
            devices2.append(dev.to_dict())
        save_md_table(devices2, config=None,
                      outfile=os.path.join(os.path.dirname(self.myconfig('outfile')), 'usb_info.md'),
                      fieldnames='DeviceID Vendor Model SerialNumber Capacity',
                      backticks_fields='DeviceID',
                      file_exists='OVERWRITE')
        return results

    def get_plugs(self, usb_dict):

        for device in usb_dict.keys():
            usb_id = sorted(usb_dict[device], key=lambda d: d['TimeCreated'])
            flag = False
            plugged_in = '-'
            volume = ''
            for item in usb_id:
                if item['action'] == '':  # event with volume information
                    volume = item['VolumeName']
                elif item['action'] == 'device-connected':
                    if flag:
                        yield {'plugged_in': plugged_in, 'plugged_off': '-', 'Vendor': device.Vendor, 'Model': device.Model, 'SerialNumber': device.SerialNumber, 'VolumeName': volume}
                    flag = True
                    plugged_in = item['TimeCreated']
                else:
                    if not flag:
                        plugged_in = '-'
                    flag = False
                    yield {'plugged_in': plugged_in, 'plugged_off': item['TimeCreated'], 'Vendor': device.Vendor, 'Model': device.Model, 'SerialNumber': device.SerialNumber, 'VolumeName': volume}


class TGT_attack(base.job.BaseModule):
    """ Extracts possible TGT attacks """

    def run(self, path=None):
        """
        Attrs:
            path (str): Absolute path to the parsed Security.xml
        """

        self.check_params(path, check_path=True, check_path_exists=True)

        ev = {'tgt': {}, 'tgs': {}, 'renew': {}}
        eventlist = {'4768': 'tgt', '4769': 'tgs', '4770': 'renew'}

        for event in self.from_module.run(path):
            if event['destination.user.name'] not in ev[eventlist[event['event.code']]].keys():
                ev[eventlist[event['event.code']]][event['destination.user.name']] = []
            ev[eventlist[event['event.code']]][event['destination.user.name']].append({
                'event.created': event['event.created'],
                'service.name': event['service.name'],
                'TicketEncryptionType': event['data.TicketEncryptionType'],
                'ip': event['source.ip'],
                'TicketOptions': event['data.TicketOptions'],
                'status': event.get('data.Error', '')})

        tgt = {}
        tgs = {}
        renew = {}
        self.startdate = '2099-01-01 00:00:00'

        # Obtain first TGT or TGS event date
        # Different alerts will be generated when possible expected events may happen before 'startdate'
        for k in ev['tgt']:
            tgt[k] = sorted(ev['tgt'][k], key=lambda l: l['event.created'])
            aux_date = tgt[k][0]['event.created']
            if aux_date < self.startdate:
                self.startdate = aux_date
        for k in ev['tgs']:
            tgs[k] = sorted(ev['tgs'][k], key=lambda l: l['event.created'])
            aux_date = tgs[k][0]['event.created']
            if aux_date < self.startdate:
                self.startdate = aux_date
        for k in ev['renew']:
            renew[k] = sorted(ev['renew'][k], key=lambda l: l['event.created'])
            aux_date = renew[k][0]['event.created']
            if aux_date < self.startdate:
                self.startdate = aux_date
        del ev
        self.startdate = datetime.datetime.strptime(self.startdate[:19], "%Y-%m-%d %H:%M:%S")

        for result in self.check_tgs_encryption(tgs):
            yield result
        for result in self.check_tgt_before_ticket(tgt, tgs):
            yield result
        for result in self.check_tgt_before_ticket(tgt, renew):
            yield result

    def check_tgs_encryption(self, tgs):
        """
        Find TGS with RC4-HMAC encryption with Ticket Options 0x40810000, or TGS with DES encryption.

        Computer accounts are filtered to reduce the amount of 4769 events
        """

        for user in tgs.keys():
            for ticket in tgs[user]:
                if (ticket['TicketEncryptionType'].startswith('DES-CBC')) or (ticket['TicketEncryptionType'] == 'RC4-HMAC' and ticket['TicketOptions'] == '0x40810000' and not user.split('@')[0].endswith('$')):
                    yield {
                        'TGS Time': ticket['event.created'],
                        'User': user,
                        'IP': ticket['ip'],
                        'Encryption': ticket['TicketEncryptionType'],
                        'Service': ticket['service.name'],
                        'Status': ticket['status'],
                        'Message': f'Possible kerberoast attack'
                    }

    def check_tgt_before_ticket(self, tgt, tgs, hours=10):
        """
        Find if there are TGT tickets before TGS. Otherwise, alert
        """

        result = {}
        for user in tgs.keys():
            for tgs_ticket in tgs[user]:
                valid = False
                same_ip = False
                tgt_user = user.split('@')[0]
                last_tgt = ''
                tgs_created = datetime.datetime.strptime(tgs_ticket['event.created'][:19], "%Y-%m-%d %H:%M:%S")
                # Consider when events may ocurr before available data
                outside_range = False
                if (tgs_created - self.startdate).total_seconds() < 3600 * hours:
                    outside_range = True

                if tgt_user in tgt.keys():
                    for tgt_ticket in tgt[tgt_user]:
                        if tgt_ticket['ip'] != tgs_ticket['ip']:  # Compare only same IP source and user
                            continue
                        same_ip = True
                        tgt_created = datetime.datetime.strptime(tgt_ticket['event.created'][:19], "%Y-%m-%d %H:%M:%S")
                        if tgt_created > tgs_created:  # Events are sorted in time. Don't look after TGS event
                            break
                        last_tgt = tgt_ticket['event.created']
                        # Expected situation: TGT before TGS
                        if tgt_created <= tgs_created and (tgs_created - tgt_created).total_seconds() < 3600 * hours:
                            valid = True
                            break
                    if not same_ip or (not last_tgt):
                        message = 'No previous TGT ticket for this user and IP address' + (f'. First available security events at {self.startdate}' if outside_range else '')
                    elif same_ip and not valid:
                        message = f'Previous TGT ticket was created more than {hours} hours before' + (f'. First available security events at {self.startdate}' if outside_range else '')
                    else:
                        continue
                    result = {
                        'TGS Time': tgs_ticket['event.created'],
                        'User': tgt_user,
                        'IP': tgs_ticket['ip'],
                        'Encryption': tgs_ticket['TicketEncryptionType'],
                        'Service': tgs_ticket['service.name'],
                        'Status': tgs_ticket['status'],
                        'Last TGT': last_tgt,
                        'Message': message
                    }
                    yield result

                else:
                    result = {
                        'TGS Time': tgs_ticket['event.created'],
                        'User': tgt_user,
                        'IP': tgs_ticket['ip'],
                        'Encryption': tgs_ticket['TicketEncryptionType'],
                        'Service': tgs_ticket['service.name'],
                        'Status': tgs_ticket['status'],
                        'Last TGT': '',
                        'Message': 'No previous TGT ticket for this user' + (f'. First available security events at {self.startdate}' if outside_range else '')
                    }
                    yield result


class EDR_PaloAlto(base.job.BaseModule):
    """ Extracts specific fields from Palo Alto events """

    def run(self, path=None):
        """
        Attrs:
            path (str): Absolute path to the parsed events.json
        """
        self.check_params(path, check_path=True, check_path_exists=True)

        # TODO: add more specific events
        eventlist = ["88", "85"]

        for event in self.from_module.run(path):
            if event["EventID"] in eventlist:
                try:
                    message_list = ast.literal_eval(event["Message"])
                    extra_data = ast.literal_eval(message_list[5])

                    event["Object"] = extra_data.get("filePath", "")
                    if "fileHash" in extra_data:
                        event["Hash"] = extra_data["fileHash"].get("sha256", "")
                    if extra_data.get("verdict", 0) == 1:
                        event["Level"] = "Potentially harmful"

                    if "yaraDetails" in extra_data.keys():
                        event_rules = extra_data["yaraDetails"]["rules"][0]
                        event["Level"] = event_rules["severity"]
                        event["Action"] = event_rules["action"]
                        event["Message"] = event_rules["description"]
                    else:
                        event["Message"] = ""
                except Exception:
                    pass
            yield event


class EDR_Sophos(base.job.BaseModule):
    """ Extracts specific fields from Sophos events """

    def run(self, path=None):
        """
        Attrs:
            path (str): Absolute path to the parsed events.json
        """
        self.check_params(path, check_path=True, check_path_exists=True)

        for event in self.from_module.run(path):
            if event["EventID"] == "42" and event["event.provider"] == "Sophos System Protection":
                message_list = ast.literal_eval(event["data.#text"])
                event["Object"] = message_list[1]
                event["Threat"] = message_list[2]
                file_data = json.loads(message_list[4])
                event["Hash"] = file_data.get("sha256FileHash")
                event["Size"] = file_data.get("fileSize")

            if event["EventID"] == "52" and event["event.provider"] == "Sophos System Protection":
                message_list = ast.literal_eval(event["data.#text"])
                event["Object"] = message_list[1]
                event["Message"] += f" {message_list[2]}"

            yield event


class EDR_Symantec(base.job.BaseModule):
    """ Extracts specific fields from Symantec events """

    def run(self, path=None):
        """
        Attrs:
            path (str): Absolute path to the parsed events.json
        """
        self.check_params(path, check_path=True, check_path_exists=True)

        # Regex for event 51
        prog_action = re.compile(r'Action:([\w\s]*)\.')
        prog_actionDescription = re.compile(r'Action Description:([\w\s]*)\.')
        prog_file = re.compile(r'File:\s*(\S*)')

        # Regex for event 45
        prog_action_45 = re.compile(r'Action\staken:([\s\w]*)')
        prog_file_45 = re.compile(r'File:\s+(.*?)\\r\\n')

        for event in self.from_module.run(path):
            string_data = event["Message"]
            event["Message"] = event["Message"].strip("[']")

            if event["EventID"] == "51":
                match_action = prog_action.search(string_data)
                if match_action:
                    event["Action"] = match_action.group(1) + ", "

                match_actionDescription = prog_actionDescription.search(string_data)
                if match_actionDescription:
                    event["Action"] = event.get("Action", "") + match_actionDescription.group(1)

                match_file = prog_file.search(string_data)
                if match_file:
                    event["Object"] = match_file.group(1)

            if event["EventID"] == "45":
                match_action = prog_action_45.search(string_data)
                if match_action:
                    event["Action"] = match_action.group(1)

                match_file = prog_file_45.search(string_data)
                if match_file:
                    event["Object"] = match_file.group(1)

            yield event


class KasperskyEndpoint(base.job.BaseModule):
    """ Parse the KasperskyEndpoint Message windows events """

    def run(self, path=None):
        prog_path = re.compile(r'(Application\spath|Ruta\sde\sla\saplicación):\s?(.*?)\\r')
        prog_name = re.compile(r'(Name|Nombre):\s?(.*?)\\r')
        prog_user = re.compile(r'(User|Usuario):\s?(.*?)\\r')

        for event in self.from_module.run(path):
            message = event["Message"]

            match_path = prog_path.search(message)
            if match_path:
                path = match_path.groups(default='')[1]
                event["Object"] = path

            match_namefile = prog_name.search(message)
            if match_namefile:
                namefile = match_namefile.groups(default='')[1]
                event["Object"] = event.get("Object", "") + "\\" + namefile

            match_user = prog_user.search(message)
            if match_user:
                user = match_user.groups(default='')[1]
                event["User"] = user

            yield event


class KasperskySecurity(base.job.BaseModule):
    """ Parse the Kaspersky Security Windows events """

    def run(self, path=None):

        for event in self.from_module.run(path):
            # Relevant EventIds identified: 3203, 5203, 64, 6006, 6041
            # They may change with Kaspersky version and therefore will not be filtered by EventID
            if event["event.dataset"] == "Kaspersky Security":
                try:
                    message_list = event["EventData"]["Data"]["#text"]
                    event["Object"] = message_list[0]
                    base_index = next((i for i, s in enumerate(message_list) if 'Real-Time File Protection' in s), -1)
                    if base_index == -1:
                        continue
                    event["User"] = message_list[base_index + 1]
                    event["Process"] = message_list[base_index + 4]
                    if base_index == 2:
                        event["Threat"] = message_list[1]
                    yield event
                except Exception:
                    continue


class MSSQL(base.job.BaseModule):
    """ Extracts events related with MSSQL """

    def run(self, path=None):
        """
        Attrs:
            path (str): Absolute path to the parsed Application.evtx
        """

        self.check_params(path, check_path=True, check_path_exists=True)

        regex = re.compile(r"CLIENT.?: (.*)\]")

        for event in self.from_module.run(path):

            if event['event.code'] == '18456':
                event['reason'] = event['reason'][1:]
                temp_address = regex.search(event['source.address'])
                event['source.address'] = temp_address.group(1)
            yield event


class Powershell(base.job.BaseModule):
    """ Analyzes the Powershell commands for suspicious activity """

    def run(self, path=None):

        for event in self.from_module.run(path):
            command = event.get("data.Command", "")
            if len(command) < 1:
                command = event.get("data.ScriptBlockText", "")
            if len(command) > 1:
                count = self.special_chars(command)
                count += self.suspicious_functions_score(self.sanitize(command))
                event["data.Suspicious"] = count
            yield event

    def sanitize(self, command):
        """ sanitizes command to simplify analysis """

        command = command.lower()
        command = re.sub(' +', ' ', command)  # replaces multiples empty spaces to one
        command = re.sub('\n+', '\n', command)  # replaces multiples new lines to one
        command = re.sub(r'["\'][ ]?\+[ ]?["\']', '', command)  # concatenation
        command = re.sub('[`^"\']', '', command)  # delete quotes, caret interruptions ... related with ofuscation

        return command

    def special_chars(self, command):
        """ return the number of special chars """

        n = 0
        n += command.count('`')
        n += 2 * command.count('^')

        if n < 2:
            return 0
        elif n < 5:
            return 1
        elif n < 10:
            return 5
        else:
            return 10

    def suspicious_functions_score(self, command):
        """ return value depending on functions and strings """

        tmpdict = load_fields(os.path.join(self.config.config['windows']['plugindir'], 'ps_list.json'), default_regex="(.*):(.*)\n")
        regex = {}
        for k, v in tmpdict.items():
            if k.startswith("["):
                regex[re.compile(k.replace("[", "\\[").replace("]", "\\]"))] = v
            else:
                regex[re.compile(rf'\W{k}\W')] = v

        n = 0
        for k, v in regex.items():
            if k.search(command):
                n += int(v)
        return n
