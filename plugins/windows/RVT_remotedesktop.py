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

import datetime
import re
import os
import ast
import dateutil.parser
import xmltodict
import base64
import base.job
from base.utils import check_folder, get_windows_user_from_path, date_to_iso, get_duration


class Teamviewer_connections(base.job.BaseModule):
    """ Extracts teamviewer connections information """

    def run(self, path=None):
        """
        Attrs:
            path (str): Absolute path to the Connections_incoming.txt or Connections.txt file
        """

        self.check_params(path, check_path=True, check_path_exists=True)
        # Induce "partition" and "user" from "path". If path is in Program Files, no user is assigned
        user = get_windows_user_from_path(path, logger=self.logger())
        partition = ''
        srch = re.search(r'/(p\d{1,2})/', path)
        if srch:
            partition = srch.group(1)

        # Connections_incoming.txt sample
        # 1360640847      somehost   14-05-2024 11:10:19     14-05-2024 11:12:40     someuser    FileTransfer   {377a2576-043e-45f3-b3d5-8571a758a766}
        # Connections.txt sample (outgoing)
        # 1352189396                      14-05-2024 11:10:19             14-05-2024 11:12:40             vmwin                           RemoteControl                   {377a2576-043e-45f3-b3d5-8571a758a766}
        srch = re.compile(r'^(?P<tvid>\d+)\s+(?P<shost>\S+)?\s*(?P<startdate>\d{2}-\d{2}-\d{4} \d{2}:\d{2}:\d{2})\s+(?P<enddate>\d{2}-\d{2}-\d{4} \d{2}:\d{2}:\d{2})\s+(?P<loguser>\S+)\s+(?P<mode>\w+)\s+\{(?P<connid>.*)\}')

        with open(path, 'r') as fin:
            for line in fin:
                if len(line) < 2:
                    continue
                match = srch.search(line)
                if not match:
                    self.logger().warning(f'Unable to parse line: {line}')
                    continue

                if match.group('shost'):
                    s_host = match.group('shost').strip()
                else:
                    s_host = ''
                # loguser id the Logged In User on PC where log resides (or hostname where log resides)
                if path.endswith('incoming.txt'):
                    incoming_loguser = match.group('loguser')
                    outgoing_loguser = ''
                else:
                    incoming_loguser = ''
                    outgoing_loguser = match.group('loguser')
                yield {
                    'StartDate': date_to_iso(match.group('startdate'), logger=self.logger()),  # Dates in UTC by default
                    'EndDate': date_to_iso(match.group('enddate'), logger=self.logger()),
                    'SourceTeamViewerID': match.group('tvid'),  # This ID is associated to the Teamviewer user initiating the connection. A single host machine may have several TeamViewerIDs
                    'SourceHost': s_host,  # Will be the hostname if no TeamViewer user account is used. Otherwise it will be the incoming user account
                    'SourceLoggedUser': outgoing_loguser,
                    'DestinationLoggedUser': incoming_loguser,
                    'ConnectionMode': match.group('mode'),
                    'SessionID': match.group('connid'),
                    'User': user,
                    'Partition': partition
                }


class Teamviewer(base.job.BaseModule):
    """ Extracts information about Teamviewer log """

    def run(self, path=None):
        """
        Attrs:
            path (str): Absolute path to TeamViewer*_Logfile.log file
        """
        # TeamViewer15_Logfile.log samples
        # 2024/05/10 04:10:21.228  9600       7164 S0   TcpConnectorv4[2]::ConnectEndpoint(): Connecting to endpoint 213.227.186.140:5938
        # 2024/05/10 04:10:37.565  3476       1272 D1   AuthenticationPasswordLogin_Passive::RunAuthenticationMethod: authentication using dynamic password was successful
        # 2024/05/10 04:10:38.617  1828       9224 G1   VoIP: Sender: Added session 2061489654. Meeting id is username (1 360 640 847). Our participant id is "WINDEVEVAL (1 352 189 396)" [1352189396,2061489654]
        # 2024/05/10 04:03:04.666  1828       7920 G1!! LoginOutgoing: ConnectFinished - error: UnknownSupportSessionID
        # 2024/05/10 03:49:45.910  9600       7436 S0   Login::Identify::ManageLogin(): ID: 1352189396 IC -1614066306 MIDv2
        prog_log = re.compile(r'^(?P<date>\d{4}\/\d{2}\/\d{2}\s\d{2}:\d{2}:\d{2}(?:\.\d{3})?)\s+(?P<pid>\d+)\s+(?P<tid>\d+)\s(.+?)\s+(?P<message>.*)')
        filename = os.path.basename(path)
        count_lines = 0
        prev_line_dict = {}

        for line in self.from_module.run(path):
            match = prog_log.match(line)
            if match:
                if count_lines != 0:
                    count_lines = 0
                    yield prev_line_dict
                count_lines = 1

                log_entry_dict = {
                    "Time": match.group('date'),  # WARNING: local time
                    "Message": match.group('message').strip(),
                    "ProcessID": match.group('pid'),
                    "LogFilename": filename
                }
                prev_line_dict = log_entry_dict

            else:
                # Some events extend more than one line. Append them to the previous event
                prev_line_dict["Message"] = prev_line_dict.get("Message", "") + line

        if len(prev_line_dict) != 0:
            yield prev_line_dict


class Anydesk_connection_trace(base.job.BaseModule):
    """ Extracts information about Anydesk_connection_trace logs """

    def run(self, path=None):
        """
        Attrs:
            path (str): Absolute path to AnyDesk/connection_trace.txt file
        """
        prog_log = re.compile(r'(\w+)\s+(\d{4}-\d{2}-\d{2},\s\d{2}:\d{2})\s+(.+?)\s+(\d+)\s+(\d+)')
        # connection_trace.txt sample
        # Incoming    2024-05-16, 09:41    User                             1108841617    1108841617

        for line in self.from_module.run(path):
            prog_match = prog_log.match(line)
            if prog_match:
                conn_type, timestamp_str, user, id_anydesk, _ = prog_match.groups(default='')
                timestamp = datetime.datetime.strptime(timestamp_str, "%Y-%m-%d, %H:%M").isoformat()
                log_dict = {
                    "Time": timestamp,
                    "Type": conn_type,
                    "User": user,
                    "SessionID": id_anydesk
                }
                yield log_dict


class Anydesk(base.job.BaseModule):
    """ Extracts information about Anydesk logs """

    def run(self, path=None):
        """
        Attrs:
            path (str): Absolute path to the ad.trace file
        """

        self.check_params(path, check_path=True, check_path_exists=True)
        base_path = self.myconfig('outdir')
        check_folder(base_path)
        self.filename = os.path.basename(path).strip()

        # Induce "partition" and "user" from "path". If path is in ProgramData, no user is assigned
        self.partition = ''
        srch = re.search(r'/(p\d{1,2})/', path)
        if srch:
            self.partition = srch.group(1)
        self.user = get_windows_user_from_path(path, self.logger())

        yield from self._process_anydesk_log(path)

    def _process_anydesk_log(self, path):
        # Get only significant events and skip the rest
        # Log sample lines
        #    info 2024-05-16 08:11:22.842       gsvc   2884   7984   36                anynet.any_socket - Logged in from 75.57.44.51:54589 on relay 821c07e6.
        #    info 2024-05-16 09:41:00.317       gsvc   2884   7984  107                      app.service - Connected to 12920 (backend:1).
        #    info 2024-05-16 08:00:30.206       lsvc   1584   9956    7            anynet.connection_mgr - New user data. Client-ID: 1313284576.
        #    info 2024-05-16 08:12:30.802      front  10056  12788               app.local_file_transfer - Download finished.
        ip_regex = re.compile(r'Logged\sin\sfrom\s((?:[0-9]{1,3}[\.]){3}[0-9]{1,3}).*')
        anydesk_regex = re.compile(
            r'\s*(?P<level>[^\s]+)\s+'
            r'(?P<date>\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2}(?:\.\d{3})?)\s+'
            r'(?P<appname>[^\s]+)\s+'
            r'(?P<ppid>\d{4,5})\s+'
            r'(?P<pid>\d{4,5})\s+'
            r'(?:(?P<unknown>\d+))?\s*'
            r'(?P<logger>anynet.relay_conn|anynet.connection_mgr|anynet.any_socket|app.local_file_transfer|app.prepare_task|app.ctrl_clip_comp|app.backend_session|app.ft_src_session|app.ctrl_clip_comp|app.session)\s-\s'
            r'(?P<message>.*)'
        )
        # alt_regex = re.compile(r'(External address|anynet.connection_mgr|Incoming session|Sending a connection request|Client-ID|app.prepare_task|Files|Logged|Connecting to|Accept request from|New user data|Session closed)')

        for line in self.from_module.run(path):
            hit = anydesk_regex.search(line)
            if not hit:
                continue
            ip_match = ip_regex.match(hit.group('message'))
            result = {
                'Time': hit.group('date'),  # Logs are in UTC by default
                'Application': hit.group('appname'),
                'Logger': hit.group('logger'),
                'Message': hit.group('message'),
                'IP': ip_match.group(1) if ip_match else "",
                'User': self.user,
                'Partition': self.partition,
                "LogFilename": self.filename
            }
            yield result


class Supremo(base.job.BaseModule):
    """ Extracts information about Supremo logs """

    def run(self, path=None):
        """
        Attrs:
            path (str): Absolute path to any Supremo.00.*.log file
        """
        prog_log = re.compile(r'\[(?P<version>.*?)\]\s*(?P<date>\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2}[:\.,]\d{3})\s+\[TID\s*(?P<thread>\d+)\s*\]\s*\[(?P<level>.*?)\]\s*(?P<message>.*)\s*\[(?P<logfile>.+)\]$')
        # Incoming.log sample
        # [4.11.0.2490    ] 2024-04-30 02:20:25:654  [TID 1764    ][INFO      ] WinDev (874019637) has terminated a remote control session [Incoming]
        # FileTransfer.log sample
        # [4.11.0.2490    ] 2024-04-30 02:19:13:602  [TID 1764    ][INFO      ] Received File: "C:\Users\User\Desktop\hello" (0 bytes) [FileTransfer]
        # Client.log sample
        # [4.11.0.2490    ] 2024-05-22 04:31:02:760  [TID 7392    ][INFO      ] Opened Remote Control Session from "874019637" to "WinDevEval" (409045347) [Client]
        # ReportsQueue.log sample
        # [4.11.0.2490    ] 2024-04-30 02:36:25:923  [TID 1764    ][INFO      ] ADDED TDeviceReport Report: Id: 874019637409045347, Start: 4/30/2024 2:36:25 AM [ReportsQueue]

        filename = os.path.basename(path).strip()

        for line in self.from_module.run(path):
            match = prog_log.match(line)
            if match:
                milliseconds_separator = match.group('date')[-4]
                iso_date = datetime.datetime.strptime(match.group('date'), f"%Y-%m-%d %H:%M:%S{milliseconds_separator}%f").isoformat()
                log_entry_dict = {
                    "Time": iso_date,
                    "Message": match.group('message').strip(),
                    "Level": match.group('level').strip().lower(),
                    "Version": match.group('version').strip(),
                    "ThreadID": match.group('thread').strip(),
                    "LogFilename": filename
                }
                yield log_entry_dict


class GoogleChromeRemoteDesktop(base.job.BaseModule):
    """ Extracts information about GoogleChromeRemoteDesktop logs """

    def run(self, path=None):
        """
        Attrs:
           path (str): Absolute path to the parsed Windows event logs already filtered by source (chromoting)
        """
        self.user_session_pattern = re.compile(r"\[?'?(?P<user>[^'/]+)(?:/(?P<other>[^']+))?'?\]?")
        # EventID 4 "data.text" sample
        # "['user@domain.es/chromoting_ftl_0523e78a-4a7c-4466-9fd5-5df9be1c656a', 'unknown', '10.7.192.38:22205', '', 'relay']"

        for event in self.from_module.run(path):
            if event["event.code"] == '4':  # Channel IP for client
                message_dict = ast.literal_eval(event["data.text"])
                event["User"], event["SessionID"] = self.user_session_from_client(message_dict[0])
                if message_dict[1].lower() == 'unknown':
                    event["IP"] = ''
                else:
                    event["IP"] = message_dict[1]
                event["HostIP"] = message_dict[2]
                # event["Channel"] = message_dict[3]
                event["ConnectionType"] = message_dict[4]

            elif event["event.code"] in ('1', '2', '5'):
                message_dict = ast.literal_eval(event["data.text"])
                event["User"], event["SessionID"] = self.user_session_from_client(message_dict[0])

            yield event

    def user_session_from_client(self, client):
        # Event store a client field containing both user and session
        match = self.user_session_pattern.match(client)
        user, session_id = ('', None)
        if match:
            user = match.group(1)
            session_id = match.group(2)
        return user, session_id


class DWAgent(base.job.BaseModule):
    """ Extracts information about DWAgent logs """

    def run(self, path=None):
        """
        Attrs:
            path (str): Absolute path to dwagent.log
        """
        # dwagent.log sample
        # 2024-05-03 02:12:02,746 INFO Task_9 Open session (id: phqBBUtOywjQb37vaKBk4DyMfDIJev, ip: 29.154.50.190, node: node421704.dwservice.net)
        pattern_log = re.compile(r'(?P<date>\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2}(?:,\d{3})?)\s(?P<level>\w+)\s(?P<thread>\S+)\s?(?P<message>.*)')
        pattern_ip = re.compile(r'.*ip:\s((?:\d+\.?){4}).*')

        filename = os.path.basename(path)

        for line in self.from_module.run(path):
            log_match = pattern_log.match(line)
            if log_match:
                log_entry_dict = {
                    "Time": log_match.group('date'),
                    "Message": log_match.group('message').strip(),
                    "Level": log_match.group('level').strip().lower(),
                    "Application": log_match.group('thread').strip(),
                    "LogFilename": filename.strip()
                }

                ip_match = pattern_ip.match(log_match.group('message').strip())
                if ip_match:
                    ip = ip_match.group(1)
                    log_entry_dict["IP"] = ip

                yield log_entry_dict

            else:
                self.logger().warning("Regex pattern failed parsing: " + line)


class Splashtop(base.job.BaseModule):
    """ Extracts information about Splashtop logs """

    def run(self, path=None):
        """
        Attrs:
            path (str): Absolute path to any Splashtop log file
        """
        self.path = path
        self.filename = os.path.basename(path).strip()

        # Parse FTCLog.txt
        if self.filename == "FTCLog.txt":
            yield from self.parse_ftc_log()

        # Parse SPLog and agent_log
        if self.filename != "FTCLog.txt":
            yield from self.parse_other_splashtop_log()

    def parse_ftc_log(self):
        # FTCLog sample
        # 2024-05-13 03:21:22     C:\Users\vmwin\Desktop\Kaspersky Event Log.evtx     0.0 KB  Upload  Completed       myuser (19.156.40.190)
        ft_log = re.compile(r'^(?P<date>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+(?P<object>.*?)\s+(?P<size>\d+\.\d+ \wB)\s+(?P<message>.*?)\s+(?P<user>\S+)\s+\((?P<ip>.*?)\)')

        for line in self.from_module.run(self.path):
            ft_match = ft_log.match(line)
            if ft_match:
                log_dict = {
                    "Time": ft_match.group('date'),
                    "Message": ft_match.group('message').strip(),
                    "Object": ft_match.group('object'),
                    "User": ft_match.group('user'),
                    "Size": ft_match.group('size'),
                    "IP": ft_match.group('ip'),
                    "LogFilename": self.filename
                }
                yield log_dict
            else:
                self.logger().warning("Regex pattern failed parsing: " + line)

    def parse_other_splashtop_log(self):
        # SPLog samples
        # <1>May13 01:59:28.489 SM_04784[Auth-L] ok, client (MYMACHINE) can connect to AV serve
        # <1>Sep  1 11:42:12 [SM_04020]:[File] FileStreamSendDataHandler run start
        # <9>May24 02:52:06.804 AP_092522024-05-24 02:50:11  C:\Users\vmwin\Desktop\WindowsSensor.LionLanner.exe  0.0 KB  Upload  Completed   user@mail.com (75.50.47.51)
        # agent_log sample
        # <1>May13 01:59:28.889    06440[App] event WM_WTSSESSION_CHANGE session: 7  id:1
        other_log = re.compile(r'^<(?P<level>\d+)>(?P<date>\w{3}\s*\d{1,2}\s\d{2}:\d{2}:\d{2}(?:\.\d{3})?)\s+(?:\w+\[(?P<appname>\S+)\]\s)?(?P<message>.+)$')
        alt_log = re.compile(r'^<(?P<level>\d+)>(?P<date>\w{3}\s*\d{1,2}\s\d{2}:\d{2}:\d{2}(?:\.\d{3})?)\s+\[(?P<unknown>\S+)\]:\[(?P<appname>\S+)\]\s(?P<message>.+)$')
        get_date_log = re.compile(r'<\d+>(\w{3}\s*\d{1,2})\s\d{2}:\d{2}:\d{2}.*')

        # As the logs (SPLog and agent_log) don't save the year, get it from file modification time
        # Iterate the log and check the year span
        # WARNING: Year won't be adequately parsed if there are year gaps in activity. Example:
        #          Log file is modified in 2024, and there is activity from 2024 and 2022, but not from 2023 ->
        #          The parser will associate the events of 2022 as if they ocurred in 2023
        m_time_year = datetime.datetime.fromtimestamp(os.path.getmtime(self.path)).year
        aux_year = 0
        aux_date = datetime.datetime(1900, 1, 1)
        with open(self.path, 'r') as file:
            for line in file:
                date_match = get_date_log.match(line)
                if not date_match:
                    continue
                date_str = date_match.group(1)
                if len(date_str) > 5:
                    date_str = date_str[0:3] + date_str[-2:]
                timestamp = datetime.datetime.strptime(date_str, "%b%d")
                if timestamp < aux_date:
                    aux_year += 1
                aux_date = timestamp

        aux_date = datetime.datetime(1900, 1, 1)
        for line in self.from_module.run(self.path):
            other_match = other_log.match(line)
            if not other_match:
                other_match = alt_log.match(line)
            if not other_match:
                self.logger().warning("Regex pattern failed parsing: " + line)
                continue
            if other_match:
                level = self.getLevel(int(other_match.group('level')))
                timestamp = dateutil.parser.parse(other_match.group('date'))
                actual_date = datetime.datetime(1900, timestamp.month, timestamp.day)

                if actual_date < aux_date:
                    aux_year -= 1
                aux_date = actual_date

                timestamp = timestamp.replace(year=m_time_year - aux_year)
                log_dict = {
                    "Time": timestamp,
                    "Message": other_match.group('message').strip(),
                    "Application": other_match.group('appname'),
                    "Level": level,
                    "LogFilename": self.filename
                }
                yield log_dict

    def getLevel(self, level_int):
        if level_int == 0:
            return "error"
        elif level_int == 1:
            return "info"
        else:
            return level_int


class Zoho(base.job.BaseModule):
    """ Extracts information about Zoho logs """

    def run(self, path=None):
        """
        Attrs:
            path (str): Absolute path to any Zoho log file
        """
        # Log Headers
        date_pattern = re.compile(r'^\s*Logging [sS]tarted from:\s?\[(.*?)\].*')
        product_pattern = re.compile(r'^\s*(Product|Application) Name\s*?:\s?(.*)')
        version_pattern = re.compile(r'^\s*Version\s*?:\s?(.*)')

        # Up to 5 different event patterns have been identified (samples provided):
        # Values "pid" (ProcessID) and "tid" (ThreadID) haven't been verified and can't be trusted
        main_log_pattern = re.compile(r'^(?P<date>\d{4}[/-]\d{2}[/-]\d{2} \d{2}:\d{2}:\d{2}(?:\.\d{1,3})?)\s+(?P<id>\d+)\s+(?P<pid>\d+)\s+\[(?P<level>\S*?)\]\s+\[(?P<appname>\S+)"\sL:\s\d+\]\s+(?P<message>.+)$')
        # LogFile.log
        # 2024/05/15 07:05:46 533794 1936   [CRITICAL] [agent.cpp" L: 752]        Connection utils Log path C:\ProgramData\ZohoMeeting
        # FileTransferWindowAppLog.log
        # 2024/05/07 01:12:07 17041935 6036   [CRITICAL] [assistagentuiadapter.cpp" L: 4959]      AssistAgentDialog::Starting file transfer dialog
        # CrashLog.log
        # 2024/05/07 01:17:53 672155036 8832   [CRITICAL] [crashhandler.cpp" L: 331]      Process teminated:1,Er:5

        uiapp_log_pattern = re.compile(r'^(?P<date>\d{4}[/-]\d{2}[/-]\d{2} \d{2}:\d{2}:\d{2}(?:\.\d{1,3})?)\s+(?P<id>\d+)\s+(?P<pid>\d+)\s+\d+\s+(?P<level>\S*?)\s+(?P<message>.+)$')
        # UIApp.log
        # 2024/05/07 01:06:43 2972063 11208 1 INFO MainWindow CallCtorDelegate Creating app mutex NewAgentUI6751562403SYSTEMATTENDEE

        socket_log_pattern = re.compile(r'^(?P<date>\d{4}[/-]\d{2}[/-]\d{2} \d{2}:\d{2}:\d{2}(?:\.\d{1,3})?)\s+(?P<appname>\S+):\s+(?P<message>.+)$')
        # WsAsyncSocketLog.log
        # 2024-05-07 03:44:41 SockUtilLogger: WSSyncSocket: Proxy Information - Proxy Host: , Proxy Port: -1, Proxy Credentials:  :
        # SockUtil.log
        # 2024-05-07 01:06:41 SockUtilLogger: dcWebSocket::initialize - Initializing Secure ClientSession es20.zohoassist.com:443

        peer_log_pattern = re.compile(r'^(?P<tid>\d+\s+)?(?P<date>\d{4}[/-]\d{2}[/-]\d{2} \d{2}:\d{2}:\d{2}(?:\.\d{1,3})?)\s+(?P<level>\w*)\s+(?:\[(?P<pid>\d+)\])?\s*\[(?P<appname>\S+?)::(?P<details>\S+)\]\s+(?P<message>.*)$')
        # PeerConnection.log
        # 4996 2024-05-07 01:06:45.613 INFO  [9440] [SocketUtils::ClientSocket::initialize_plog@77] CPeerConnection::initialize - Log opened
        # IPCClientLog.log
        # 3888 2024-05-07 01:38:39.055 INFO  [9932] [NamedPipeForClient::OpenServerConnection@65] Pipe Connection Success
        # /ACServer.log
        # 4996 2024-05-07 01:06:40.074 FATAL [5800] [Agent::StartAudioClient@1320] Starting audio client in directory: C:\Program Files (x86)\ZohoMeeting\ZAAudioClient.exe

        no_date_pattern = re.compile(r'^(?:(?P<tid>\d+)\s+)?(?P<date>\d{2}:\d{2}:\d{2}(?:[\.:,]\d{1,3})?)\s+(?:\[(?P<level>\S*?)\])?\s*(?:(?P<appname>\S+?)::)?(?P<message>.*)$')
        # ToolsSys.log
        # 10660 01:09:25:725  AsyncWsHandler::Initialize: Initializing AsyncSocket with context - 0, logger path log\ToolsWsAsyncSocket.log
        # 10660 01:11:25:655  [INFO] Csysmanager::jsonRequestHandler : Response of length: 931 sent successfully
        # 10660 01:17:40:248  SYSMANAGER validation passed
        # servicelog.log
        # 10828 01:06:35:991  ZService::ServiceCrticalActionThreadSpawner:: MaliciousFileDetectionThread creation failed with error:183
        # 10828 01:06:37:60  ReadJsonSharedMemory : Got w_dir - C:\Program Files (x86)\ZohoMeeting  :  C:\Program Files (x86)\ZohoMeeting

        date_to_yield = ""
        product_to_yield = ""
        version_to_yield = ""
        filename = os.path.basename(path).strip()

        for line in self.from_module.run(path):
            try:
                # Get info from headers to later fill events information
                date_match = date_pattern.match(line)
                if date_match:
                    date_to_yield = date_match.group(1)
                    continue
                name_match = product_pattern.match(line)
                if name_match:
                    product_to_yield = name_match.group(2)
                    continue
                version_match = version_pattern.match(line)
                if version_match:
                    version_to_yield = version_match.group(1)
                    continue

                # Try all patterns
                for pattern in [no_date_pattern, main_log_pattern, uiapp_log_pattern, peer_log_pattern, socket_log_pattern]:
                    match = pattern.match(line)
                    if not match:
                        continue
                    if pattern == no_date_pattern:
                        only_time = match.group('date')
                        if only_time.count(':') < 3:
                            only_time = only_time + ':000'
                        date = datetime.datetime.strptime(date_to_yield + ' ' + only_time, "%d-%m-%Y %H:%M:%S:%f").isoformat()
                    else:
                        date = dateutil.parser.parse(match.group('date'))
                    log_level = match.groupdict().get('level', '')
                    if log_level is not None:
                        log_level = log_level.lower()
                    else:
                        log_level = ''
                    log_dict = {
                        "Time": date,
                        "Message": match.group('message').strip(),
                        "Application": match.groupdict().get('appname', ''),
                        "Level": log_level,
                        "ProcessID": match.groupdict().get('pid', ''),
                        "ThreadID": match.groupdict().get('tid', ''),
                        "Version": version_to_yield,
                        "Product": product_to_yield,
                        "LogFilename": filename
                    }
                    yield log_dict
                    break
            except Exception as exc:
                self.logger().warning(exc)
                self.logger().warning("Regex pattern failed parsing: " + line)
                continue


class RemoteDesktopApp(base.job.BaseModule):
    """ Extracts information about remotedesktop app """

    def run(self, path=None):
        """
        Attrs:
            path (str): Absolute path to the Users/<user>/AppData/Local/Packages/Microsoft.RemoteDesktop_8wekyb3d8bbwe folder
        """

        # TODO: parse LocalState/Logs

        self.check_params(path, check_path=True, check_path_exists=True)
        base_path = self.myconfig('outdir')
        check_folder(base_path)

        # Induce "partition" and "user" from "path".
        user = get_windows_user_from_path(path, logger=self.logger())
        partition = ''
        srch = re.search(r'/(p\d{1,2})/', path)
        if srch:
            partition = srch.group(1)

        folders = [
            os.path.join(path, 'LocalState', 'RemoteDesktopData', 'JumpListConnectionArgs'),
            os.path.join(path, 'LocalState', 'RemoteDesktopData', 'credentials'),
            os.path.join(path, 'LocalState', 'RemoteDesktopData', 'LocalWorkspace', 'connections')
        ]
        field_list = [
            ['a:ConnectionId', 'a:Description', 'a:LastLaunch', 'a:DisplayName', 'a:ConnectionType'],
            ['a:FriendlyName', 'a:PasswordVaultResourceID', 'a:Username'],
            ['a:CredentialsId', 'a:FriendlyName', 'a:HostName']
        ]

        # CredentialsId in connections relates to LogFilename in credentials folder
        # ConnectionID in JumpListConnectionArgs relates to LogFilename in connections folder
        connections = {}
        log_filenames = {}
        for folder, fields in zip(folders, field_list):
            for result in self._process_files(folder, fields):
                log_filename = os.path.basename(result['LogFilename']).split('.')[0]
                if log_filename not in log_filenames:
                    log_filenames[log_filename] = {}
                log_filenames[log_filename].update(result)
                if 'ConnectionId' in result:
                    if result['ConnectionId'] not in connections:
                        connections[result['ConnectionId']] = {}
                    connections[result['ConnectionId']].update(result)

        for c in connections:
            if c in log_filenames:
                connections[c].update(log_filenames[c])
                if connections[c]['CredentialsId'] in log_filenames:
                    connections[c].update(log_filenames[connections[c]['CredentialsId']])
            connections[c]['User'] = user
            connections[c]['Partition'] = partition

        for i in connections.values():
            yield i

        self._process_thumbnails(os.path.join(path, 'LocalState', 'RemoteDesktopData', 'RemoteResourceThumbnails'), base_path)

    def _process_files(self, dirpath, fields):
        if os.path.isdir(dirpath):
            for fname in os.listdir(dirpath):
                if not fname.endswith('.model'):
                    continue
                b = ''
                with open(os.path.join(dirpath, fname), 'r') as fin:
                    b = fin.read()
                b = xmltodict.parse(b)
                result = {'LogFilename': fname}
                for field in fields:
                    result[field[2:]] = b['SerializableModel'].get(field, '')
                yield result

    def _process_thumbnails(self, thumbnailpath, outpath):
        outdir = os.path.join(outpath, 'RemoteDesktopApp_Thumbnails')
        check_folder(outdir)
        if os.path.isdir(thumbnailpath):
            for fname in os.listdir(thumbnailpath):
                if not fname.endswith('.model'):
                    continue
                b = ''
                with open(os.path.join(thumbnailpath, fname), 'r') as fin:
                    b = fin.read()
                b = xmltodict.parse(b)
                if len(b) > 0 and 'a:EncodedThumbnail' in b['SerializableModel'].keys():
                    with open(os.path.join(outdir, f"thumb_{fname[:-6]}.jpg"), 'wb') as fout:
                        fout.write(base64.b64decode(b['SerializableModel']['a:EncodedThumbnail']))


class Summary(base.job.BaseModule):
    """ Search for the connections and makes the summary table of remotedesktop """

    def run(self, path=None):
        """
        Attrs:
            path (str): Absolute path to the trace file
        """
        filename = os.path.basename(path)

        Teamviewer_inc_con = os.path.basename(self.myconfig('Teamviewer_inc_con'))
        Teamviewer_out_con = os.path.basename(self.myconfig('Teamviewer_out_con'))
        Anydesk_logs = os.path.basename(self.myconfig('Anydesk_logs'))
        Anydesk_inc_con = os.path.basename(self.myconfig('Anydesk_in_con'))
        Supremo = os.path.basename(self.myconfig('Supremo'))
        Dwagent = os.path.basename(self.myconfig('Dwagent'))
        Zoho = os.path.basename(self.myconfig('Zoho'))
        Splashtop = os.path.basename(self.myconfig('Splashtop'))
        Chrome = os.path.basename(self.myconfig('Chrome'))
        Screenconnect = os.path.basename(self.myconfig('Screenconnect'))
        RemoteDesktopApp = os.path.basename(self.myconfig('RemoteDesktopApp'))

        if filename == Teamviewer_inc_con:
            for line in self.from_module.run(path):
                yield {
                    "Type": "Incoming",
                    "Start": line.get("StartDate", ""),
                    "End": line.get("EndDate", ""),
                    "Duration": get_duration(line.get("StartDate", ""), line.get("EndDate", ""), date_format="%Y-%m-%dT%H:%M:%S%z"),
                    "User": line.get("DestinationLoggedUser", ""),
                    "SessionID": line.get("SessionID", ""),
                    "Hostname": line.get("SourceHost", ""),
                    "Mode": line.get("ConnectionMode", ""),
                    "Partition": line.get("Partition", ""),
                    "Program": "TeamViewer",
                    "LogFilename": filename.strip()
                }
        elif filename == Teamviewer_out_con:
            for line in self.from_module.run(path):
                yield {
                    "Type": "Outgoing",
                    "Start": line.get("StartDate", ""),
                    "End": line.get("EndDate", ""),
                    "Duration": get_duration(line.get("StartDate", ""), line.get("EndDate", ""), date_format="%Y-%m-%dT%H:%M:%S%z"),
                    "SessionID": line.get("SessionID", ""),
                    "Hostname": line.get("SourceLoggedUser", ""),
                    "User": line.get("User", ""),
                    "Mode": line.get("ConnectionMode", ""),
                    "Partition": line.get("Partition", ""),
                    "Program": "TeamViewer",
                    "LogFilename": filename.strip()
                }
        elif filename == Anydesk_inc_con:
            for line in self.from_module.run(path):
                yield {
                    "Type": line.get("Type", ""),
                    "Start": line.get("Time", ""),
                    "User": line.get("User", ""),
                    "SessionID": line.get("SessionID", ""),
                    "Program": "AnyDesk",
                    "LogFilename": filename.strip()
                }
        elif filename == Anydesk_logs:
            yield from self.anyDeskMatch(path, filename)
        elif filename == Supremo:
            yield from self.supremo(path, filename)
        elif filename == Dwagent:
            yield from self.dwagent(path, filename)
        elif filename == Zoho:
            yield from self.zoho(path, filename)
        elif filename == Splashtop:
            yield from self.splashtop(path, filename)
        elif filename == Chrome:
            yield from self.chrome(path, filename)
        elif filename == Screenconnect:
            yield from self.screenconnect(path, filename)
        elif filename == RemoteDesktopApp:
            for line in self.from_module.run(path):
                yield {
                    "Type": "Incoming",
                    "Start": line.get("LastLaunch", ""),
                    "User": line.get("FriendlyName", ""),
                    "SessionID": line.get("ConnectionId", ""),
                    "Hostname": line.get("HostName", ""),
                    "Mode": line.get("ConnectionType", ""),
                    "Partition": line.get("Partition", ""),
                    "Program": "RemoteDesktopApp",
                    "LogFilename": filename.strip()
                }

    def screenconnect(self, path, filename):
        data_inc = {}
        for line in self.from_module.run(path):
            event_id = int(line.get("EventID"))
            if event_id == 100:
                if data_inc:
                    yield data_inc
                    data_inc = {}
                data_inc["Type"] = "Incoming"
                data_inc["Start"] = line.get("Time", "")
                data_inc["Program"] = "Screenconnect"
                data_inc["LogFilename"] = filename.strip()
            elif event_id == 101:
                data_inc["End"] = line.get("Time", "")
                data_inc["Duration"] = get_duration(data_inc.get("Start", ""), data_inc["End"], date_format="%Y-%m-%dT%H:%M:%S.%f%z")
                data_inc["Type"] = "Incoming"
                data_inc["Program"] = "Screenconnect"
                data_inc["LogFilename"] = filename.strip()
                yield data_inc
                data_inc = {}
        if data_inc:
            yield data_inc

    def chrome(self, path, filename):
        data_inc = {}

        for line in self.from_module.run(path):
            event_id = line.get("EventID", "")

            if event_id == "1":
                if data_inc:
                    yield data_inc
                    data_inc = {}
                data_inc["Type"] = "Incoming"
                data_inc["Start"] = line.get("Time", "")
                data_inc["Program"] = "ChromeRD"
                data_inc["LogFilename"] = filename.strip()
                data_inc["User"] = line.get("User", "")
                data_inc["SessionID"] = line.get("SessionID", data_inc["User"])
                # data_inc["SessionID"] = line.get("SessionID", "")

            elif event_id == "4":
                ip_str = line.get("IP")
                ip = ip_str.split(":", 1)[0]
                host_ip_str = line.get("HostIP")
                host_ip = host_ip_str.split(":", 1)[0]
                if (data_inc.get("User", "") == line.get("User") and data_inc.get("SessionID", "") == line.get("SessionID")):
                    data_inc["IP"] = data_inc.get("IP", "") + "[IP: " + ip + " HostIP: " + host_ip + "]"
                elif data_inc.get("SessionID", "") == line.get("User"):
                    data_inc["IP"] = data_inc.get("IP", "") + "[IP: " + ip + " HostIP: " + host_ip + "]"

            elif event_id == "2":
                if data_inc.get("Type", "") == "":
                    data_inc["Type"] = "Incoming"
                    data_inc["Program"] = "ChromeRD"
                    data_inc["LogFilename"] = filename.strip()
                data_inc["End"] = line.get("Time", "")
                data_inc["Duration"] = get_duration(data_inc.get("Start", ""), data_inc["End"], date_format="%Y-%m-%dT%H:%M:%S.%f%z")
                yield data_inc
                data_inc = {}
        if data_inc:
            yield data_inc

    def splashtop(self, path, filename):
        start_can_connect = re.compile(r'ok,\sclient\s\((.*?)\)\scan\sconnect\sto\s.*')
        start_disp_name = re.compile(r'disp\sname\s(.*)')
        start_ip = re.compile(r'Got\sclient\s\d+\spublic\sIP\s(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
        stop_closed = re.compile(r'\[SRF\]\sClosed')
        data_inc = {}
        for line in self.from_module.run(path):
            message = line.get("Message")

            start_can_connect_match = start_can_connect.match(message)
            if start_can_connect_match:
                if data_inc:
                    yield data_inc
                    data_inc = {}
                data_inc["Type"] = "Incoming"
                data_inc["Start"] = line.get("Time", "")
                data_inc["Hostname"] = start_can_connect_match.group(1)
                data_inc["Program"] = "Splashtop"
                data_inc["LogFilename"] = filename.strip()
                continue

            inc_end_match_connect = start_disp_name.match(message)
            if inc_end_match_connect:
                data_inc["User"] = inc_end_match_connect.group(1)
                continue

            start_ip_match = start_ip.match(message)
            if start_ip_match:
                data_inc["IP"] = start_ip_match.group(1)
                continue

            stop_closed_match = stop_closed.match(message)
            if stop_closed_match:
                data_inc["Type"] = "Incoming"
                data_inc["End"] = line.get("Time", "")
                data_inc["Duration"] = get_duration(data_inc.get("Start", ""), data_inc["End"], date_format="%Y-%m-%dT%H:%M:%S.%f%z")
                data_inc["Program"] = "Splashtop"
                data_inc["LogFilename"] = filename.strip()
                yield data_inc
                data_inc = {}
        if data_inc:
            yield data_inc

    def zoho(self, path, filename):
        # Starting incoming connection events include "key" (SessionID) and "id" (ClientID)
        start = re.compile(r'.*initializeSocketHandler:\sCreating\sWebSocket\sConnection\s.*?key=(\d+).*')
        end = re.compile(r'.*Stop\sremote\ssession.*')

        data_inc = {}
        for line in self.from_module.run(path):
            message = line.get("Message")

            inc_start_match = start.match(message)
            if inc_start_match:
                if data_inc:
                    yield data_inc
                    data_inc = {}
                data_inc["Type"] = "Incoming"
                data_inc["Start"] = line.get("Time", "")
                data_inc["SessionID"] = str(inc_start_match.group(1))
                data_inc["Program"] = "Zoho"
                data_inc["LogFilename"] = filename.strip()
                continue

            if line.get('Application', '') == 'agentprotocolhandler.cpp':
                inc_end_match = end.match(message)
                if inc_end_match:
                    if data_inc:
                        data_inc["End"] = line.get("Time", "")
                        data_inc["Duration"] = get_duration(data_inc.get("Start", ""), data_inc["End"], date_format="%Y-%m-%dT%H:%M:%S%z")
                        yield data_inc
                        data_inc = {}
                    else:
                        data_inc["Type"] = "Incoming"
                        data_inc["End"] = line.get("Time", "")
                        data_inc["Duration"] = get_duration(data_inc.get("Start", ""), data_inc["End"], date_format="%Y-%m-%dT%H:%M:%S%z")
                        data_inc["Program"] = "Zoho"
                        data_inc["LogFilename"] = filename.strip()
                        yield data_inc
                        data_inc = {}
        if data_inc:
            yield data_inc

    def dwagent(self, path, filename):
        start = re.compile(r'Open\ssession\s\(id:\s(\S+?),\sip:\s(\d+\.\d+\.\d+\.\d+),\s.*')
        end = re.compile(r'Close\ssession\s\(id:\s(\S+?),\sip:\s(\d+\.\d+\.\d+\.\d+),\s.*')
        data_inc = {}
        for line in self.from_module.run(path):
            message = line.get("Message")

            inc_start_match = start.match(message)
            if inc_start_match:
                if data_inc:
                    yield data_inc
                    data_inc = {}
                data_inc["Type"] = "Incoming"
                data_inc["Start"] = line.get("Time", "")
                data_inc["SessionID"] = inc_start_match.group(1)
                data_inc["Program"] = "Dwagent"
                data_inc["LogFilename"] = filename.strip()
                data_inc["IP"] = line.get("IP", "") if line.get("IP", "") != "" else inc_start_match.group(2)
                continue

            inc_end_match = end.match(message)
            if inc_end_match:
                if data_inc.get("SessionID", "") == inc_end_match.group(1):
                    data_inc["End"] = line.get("Time", "")
                    data_inc["Duration"] = get_duration(data_inc.get("Start", ""), data_inc["End"], date_format="%Y-%m-%dT%H:%M:%S.%f%z")
                else:
                    if data_inc:
                        yield data_inc
                        data_inc = {}
                    else:
                        data_inc["Type"] = "Incoming"
                        data_inc["End"] = line.get("Time", "")
                        data_inc["Duration"] = get_duration(data_inc.get("Start", ""), data_inc["End"], date_format="%Y-%m-%dT%H:%M:%S.%f%z")
                        data_inc["SessionID"] = inc_end_match.group(1)
                        data_inc["Program"] = "Dwagent"
                        data_inc["IP"] = line.get("IP", "") if line.get("IP", "") != "" else inc_end_match.group(2)
                        data_inc["LogFilename"] = filename.strip()
                        yield data_inc
                        data_inc = {}
        if data_inc:
            yield data_inc

    def supremo(self, path, filename):
        inc_start = re.compile(r'(\S+)\s\((\d+)\)\shas\sstarted\sa\sremote\scontrol\ssession.*')
        inc_end = re.compile(r'(\S+)\s\((\d+)\)\shas\sterminated\sa\sremote\scontrol\ssession.*')
        out_start = re.compile(r'Opened\sRemote\sControl\sSession\sfrom\s"(\d+)"\sto\s"(.*?)"\s\((\d+)\).*')
        out_end = re.compile(r'Closed\sRemote\sControl\sSession\sfrom\s"(\d+)"\sto\s"(.*?)"\s\((\d+)\).*')
        data_inc, data_out = {}, {}
        for line in self.from_module.run(path):
            message = line.get("Message")

            inc_start_match = inc_start.match(message)
            if inc_start_match:
                if data_inc:
                    yield data_inc
                    data_inc = {}
                data_inc["Type"] = "Incoming"
                data_inc["Start"] = line.get("Time", "")
                data_inc["Hostname"] = inc_start_match.group(1)
                data_inc["SessionID"] = inc_start_match.group(2)
                data_inc["Program"] = "Supremo"
                data_inc["LogFilename"] = filename.strip()
                continue

            inc_end_match = inc_end.match(message)
            if inc_end_match:
                if data_inc.get("SessionID", "") == inc_end_match.group(2):
                    data_inc["End"] = line.get("Time", "")
                    data_inc["Duration"] = get_duration(data_inc.get("Start", ""), data_inc["End"], date_format="%Y-%m-%dT%H:%M:%S.%f%z")
                else:
                    if data_inc:
                        yield data_inc
                        data_inc = {}
                    else:
                        data_inc["Type"] = "Incoming"
                        data_inc["End"] = line.get("Time", "")
                        data_inc["Duration"] = get_duration(data_inc.get("Start", ""), data_inc["End"], date_format="%Y-%m-%dT%H:%M:%S.%f%z")
                        data_inc["Hostname"] = inc_end_match.group(1)
                        data_inc["SessionID"] = inc_end_match.group(2)
                        data_inc["Program"] = "Supremo"
                        data_inc["LogFilename"] = filename.strip()
                        yield data_inc
                        data_inc = {}
                continue

            out_start_match = out_start.match(message)
            if out_start_match:
                if data_out:
                    yield data_out
                    data_out = {}
                data_out["Type"] = "Outgoing"
                data_out["Start"] = line.get("Time", "")
                data_out["Hostname"] = out_start_match.group(2)
                data_out["FromTo"] = out_start_match.group(1) + " -> " + out_start_match.group(3)
                data_out["SessionID"] = out_start_match.group(3)
                data_out["Program"] = "Supremo"
                data_out["LogFilename"] = filename.strip()
                continue

            out_end_match = out_end.match(message)
            if out_end_match:
                if data_out.get("FromTo", "") == (out_end_match.group(1) + " -> " + out_end_match.group(3)):
                    data_out["End"] = line.get("Time", "")
                    data_out["Duration"] = get_duration(data_out.get("Start", ""), data_out["End"], date_format="%Y-%m-%dT%H:%M:%S.%f%z")
                else:
                    if data_out:
                        yield data_out
                        data_out = {}
                    else:
                        data_out["Type"] = "Outgoing"
                        data_out["End"] = line.get("Time", "")
                        data_out["Duration"] = get_duration(data_out.get("Start", ""), data_out["End"], date_format="%Y-%m-%dT%H:%M:%S.%f%z")
                        data_out["Hostname"] = out_end_match.group(2)
                        data_out["FromTo"] = out_end_match.group(1) + " -> " + out_end_match.group(3)
                        data_out["SessionID"] = out_end_match.group(3)
                        data_out["Program"] = "Supremo"
                        data_out["LogFilename"] = filename.strip()
                        yield data_out
                        data_out = {}

        if data_out:
            yield data_out
        if data_inc:
            yield data_inc

    def anyDeskMatch(self, path, filename):
        inc_req = re.compile(r'Accept\srequest\sfrom\s(\d+).*')
        out_conn = re.compile(r'Connecting\sto\s(\d+).*')
        inc_out_ip = re.compile(r'Logged\sin\sfrom\s(.*?):.*')
        inc_out_end = re.compile(r'Session closed.*')
        data_inc, data_out = {}, {}
        for line in self.from_module.run(path):
            message = line.get("Message")
            inc_req_match = inc_req.match(message)
            if inc_req_match:
                if data_inc:
                    yield data_inc
                    data_inc = {}
                data_inc["Type"] = "Incoming"
                data_inc["Start"] = line.get("Time", "")
                data_inc["User"] = line.get("User", "")
                data_inc["Hostname"] = inc_req_match.group(1)
                data_inc["Program"] = "AnyDesk"
                data_inc["LogFilename"] = filename.strip()
                continue

            out_conn_match = out_conn.match(message)
            if out_conn_match:
                if data_out:
                    yield data_out
                    data_out = {}
                data_out["Type"] = "Outgoing"
                data_out["Start"] = line.get("Time", "")
                data_out["User"] = line.get("User", "")
                data_out["Hostname"] = out_conn_match.group(1)
                data_out["Program"] = "AnyDesk"
                data_out["LogFilename"] = filename.strip()
                continue

            inc_out_end_match = inc_out_end.match(message)
            if inc_out_end_match:
                if data_inc and data_out:
                    date_obj_inc = date_to_iso(data_inc["Start"], logger=self.logger())
                    date_obj_out = date_to_iso(data_out["Start"], logger=self.logger())
                    if date_obj_inc > date_obj_out:
                        data_inc["End"] = line.get("Time", "")
                        data_inc["Duration"] = get_duration(data_inc.get("Start", ""), data_inc["End"], date_format="%Y-%m-%dT%H:%M:%S.%f%z")
                        yield data_inc
                        data_inc = {}
                    else:
                        data_out["End"] = line.get("Time", "")
                        data_out["Duration"] = get_duration(data_out.get("Start", ""), data_out["End"], date_format="%Y-%m-%dT%H:%M:%S.%f%z")
                        yield data_out
                        data_out = {}
                elif data_inc:
                    data_inc["End"] = line.get("Time", "")
                    data_inc["Duration"] = get_duration(data_inc.get("Start", ""), data_inc["End"], date_format="%Y-%m-%dT%H:%M:%S.%f%z")
                    yield data_inc
                    data_inc = {}
                elif data_out:
                    data_out["End"] = line.get("Time", "")
                    data_out["Duration"] = get_duration(data_out.get("Start", ""), data_out["End"], date_format="%Y-%m-%dT%H:%M:%S.%f%z")
                    yield data_out
                    data_out = {}

            inc_out_ip_match = inc_out_ip.match(message)
            if inc_out_ip_match:
                if data_inc and data_out:
                    date_obj_inc = date_to_iso(data_inc["Start"], logger=self.logger())
                    date_obj_out = date_to_iso(data_out["Start"], logger=self.logger())
                    if date_obj_inc > date_obj_out:
                        data_inc["IP"] = inc_out_ip_match.group(1)
                    else:
                        data_out["IP"] = inc_out_ip_match.group(1)
                elif data_inc:
                    data_inc["IP"] = inc_out_ip_match.group(1)
                elif data_out:
                    data_out["IP"] = inc_out_ip_match.group(1)
        if data_out:
            yield data_out
        if data_inc:
            yield data_inc

