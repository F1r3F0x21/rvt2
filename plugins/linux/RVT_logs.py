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
import re
import pandas as pd
import base.job
import datetime
import dateutil.parser
from base.utils import check_folder, date_to_iso, get_partition
from base.commands import yield_command
from plugins.linux.RVT_os_info import CharacterizeLinux


class LinuxStandardLog(base.job.BaseModule):
    """ Extract the Logfile

    Module description:
        - **from_module**: Data dict.
        - **yields**: The updated dict data.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.path = ''

    def read_config(self):
        super().read_config()

    def run(self, path=None):
        # Syslog may come in different formats. RFC5424 and RFC3164 are the standard, but they can be customized
        # Try several patterns, from most specific to most general

        # VMware ESXi syslog. With optional log level, no hostname and strict processid
        esxi = re.compile(
            r'^(?:<(?P<pri>\d|\d{2}|1[1-8]\d|19[01])>\s*(?P<version>\d+)\s+)?'
            # r'(?:(?P<timestamp>[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}|[-+0-9T:.Z]+))?\s+'
            r'(?P<timestamp>[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}|[-+0-9T:.Z]+)\s+'
            r'(?:(?P<level>debug|verbose|info|informational|notice|warn|warning|alert|error|critical|emergency|(De|In|No|Wa|Al|Cr|Em|Er)\(\d+\))\s+)?'
            r'(?P<appname>[^\[\s]+)'
            r'\[(?P<procid>[A-F0-9]+)\]\s?:?\s+'
            r'(?P<structured_data>\[.*?\])?'
            r'(?P<message>.*)'
        )
        # Standard RFC5424. No `:` used. No `,` in some fields to avoid general messages
        rfc5424 = re.compile(
            r'^(?:<(?P<pri>\d|\d{2}|1[1-8]\d|19[01])>\s*(?P<version>\d+)\s+)?'
            r'(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2}))\s+'
            r'(?P<hostname>[^\s\:\,]+)\s+'
            r'(?P<appname>[^\s\:]+)\s+'
            r'(?P<procid>[^\s\:]+)\s+'
            r'(?P<msgid>[^\s\:\,]+)\s+'
            r'(?:(?P<structured_data>-|(\[.+?\]))\s*)?'
            r'(?P<message>.+)'
        )
        # RFC3164 (BSD)
        rfc3164 = re.compile(
            r'^(?:<(?P<pri>\d|\d{2}|1[1-8]\d|19[01])>\s*(?P<version>\d+)\s+)?'
            # r'(?:(?P<timestamp>[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}|[-+0-9T:.Z]+))?\s+'
            r'(?P<timestamp>[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}|[-+0-9T:.Z]+)\s+'
            r'(?:(?P<hostname>[^\s]+)\s+)?'
            r'(?P<appname>[^\[\s]+)'
            r'(?:\[(?P<procid>[^\]\s]+)\])?\s?:\s+'
            r'(?P<message>.*)'
        )
        # General syslog match with no headers other than timestamp
        syslog_pattern = re.compile(
            r'^(?:<(?P<pri>\d|\d{2}|1[1-8]\d|19[01])>\s*(?P<version>\d+)\s+)?\[?'
            r'(?P<timestamp>[-+0-9T:.Z]{10,}|[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\]?\s+'
            r'(?P<message>.*)'
        )

        filename = os.path.basename(path)
        count_lines = 0
        previous_line_dict = {}
        fields_translate = {
            "timestamp": "@timestamp",
            "level": "log.level",
            "hostname": "host.name",
            "appname": "log.syslog.appname",
            "procid": "log.syslog.procid",
            "msgid": "log.syslog.msgid",
            "structured_data": "log.syslog.structured_data",
            "message": "message"
        }

        self.aux_date = datetime.datetime(1901, 1, 1)
        for line in self.from_module.run(path):
            for i, pattern in enumerate([esxi, rfc5424, rfc3164, syslog_pattern]):
                match = pattern.match(line)
                if match:
                    count_lines += 1
                    log_entry_dict = {new_field: match.groupdict().get(field, '') for field, new_field in fields_translate.items()}

                    # If date does not include the year, try to obtain it by file modification time
                    if not log_entry_dict.get("@timestamp", "2024").startswith('20'):
                        log_entry_dict["@timestamp"] = self.induce_year(log_entry_dict["@timestamp"], path)
                    log_entry_dict.update({'log.file.path': filename})
                    if count_lines > 1:
                        yield previous_line_dict
                        count_lines = 1
                    previous_line_dict = log_entry_dict
                    break
            else:
                # If no pattern matches, assume it is the continuation of the previous message in a new line
                # WARNING: If some unknown pattern is found after a first valid hit, all messages will be appended to the last valid one
                # WARNING: if lines are provided in reverse order, this lines may be mistaken with the contents of the following event
                if count_lines >= 1:
                    count_lines += 1
                    previous_line_dict["message"] = previous_line_dict.get("message", '') + '\n' + line
                else:
                    self.logger().warning(f"Regex pattern failed at the start with line {line}")
                    count_lines = 0

        if len(previous_line_dict) != 0:
            yield previous_line_dict

    def count_leading_spaces(self, line):
        count = 0
        for char in line:
            if char == ' ':
                count += 1
            else:
                break  # Stop counting when a non-space character is encountered
        return count

    def induce_year(self, timestamp, path):
        """ Induce the year of a log entry given the file modification time.

        Linux logs are incremental. First entry is always the oldest.
        Entries should be feeded to this job in reverse order, so first line is the newest.
        """
        # Reset file modification time and the accumulated year substraction if new path is provided
        self._update_log_data(path)

        t = dateutil.parser.parse(timestamp)  # If no year is provided, dateutil takes the present year
        present_date = t.replace(year=1900)  # Compare dates against a fixed year, such as 1900

        # Sometimes log times may experience a short delay. Admit up to 30 minutes before assuming is the previous year
        if present_date - self.aux_date > datetime.timedelta(seconds=1800):
            self.years_to_substract += 1
        self.aux_date = present_date

        # Set the new calculated year
        t = t.replace(year=self.mod_time.year - self.years_to_substract)

        # Localtime to UTC
        t = date_to_iso(t, input_timezone=self.local_tz, logger=self.logger())
        return t

    def _update_log_data(self, path):
        """ Update file modification time and years to substract only if a new path is provided """

        if not path:
            self.mod_time = datetime.datetime.today()
            self.years_to_substract = 0
            self.local_tz = 'UTC'
        elif self.path != path:
            self.years_to_substract = 0
            partition = get_partition(path, self.myconfig('mountdir'))
            os_info = CharacterizeLinux(config=self.config)
            self.local_tz = os_info.get_timezone(partition)
            if os.path.exists(path):
                self.mod_time = datetime.datetime.fromtimestamp(os.path.getmtime(path))
                self.path = path
            else:
                self.mod_time = datetime.datetime.today()


class ESXiStandardLog(base.job.BaseModule):

    """ Extract the Logfile

    Module description:
        - **from_module**: Data dict.
        - **yields**: The updated dict data.
    """

    def read_config(self):
        super().read_config()

    def run(self, path=None):
        esxilog = re.compile(r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.?\d*Z)\s(\S*)\s(\S*)\s\[(.*?)\]\s*(.*)')
        filename = os.path.basename(path)
        prev_line_dict = {}
        first_message = ""

        for line in self.from_module.run(path):
            match = esxilog.match(line)
            if match:
                if prev_line_dict and "Time" in prev_line_dict:
                    yield prev_line_dict
                    prev_line_dict = {}
                timestamp, level, process, details, message = match.groups(default='')
                prev_line_dict = {
                    "Time": timestamp,
                    "Message": first_message + message.strip(),
                    "Level": level,
                    "process.name": process,
                    "details": details,
                    "LogFilename": filename
                }
                first_message = ""
            else:
                if prev_line_dict.get("Message", "") == "":
                    first_message = line
                else:
                    prev_line_dict["Message"] = f'{prev_line_dict.get("Message", "")}\n{line}'
        if prev_line_dict:
            yield prev_line_dict


class ESXiShellSyslogLog(base.job.BaseModule):

    """ Extract the Logfile

    Module description:
        - **from_module**: Data dict.
        - **yields**: The updated dict data.
    """

    def read_config(self):
        super().read_config()

    def run(self, path=None):
        esxilog = re.compile(r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.?\d*Z)\s*(.*?):\s*(.*)')
        filename = os.path.basename(path)
        prev_line_dict = {}
        for line in self.from_module.run(path):
            match = esxilog.match(line)
            if match:
                if prev_line_dict:
                    yield prev_line_dict
                    prev_line_dict = {}
                timestamp, process, message = match.groups(default='')
                prev_line_dict = {
                    "Time": timestamp,
                    "Message": message.strip(),
                    "process.name": process,
                    "LogFilename": filename
                }
            else:
                if prev_line_dict.get("Message", "") != "":
                    prev_line_dict["Message"] = f'{prev_line_dict.get("Message", "")}\n{line}'
                else:
                    self.logger().warning(f"Regex pattern failed with some logline input {line}")
        if prev_line_dict:
            yield prev_line_dict


class JournalLogs(base.job.BaseModule):
    """ Extract from the Binaries Journal Logfile

    Module description:
        - **from_module**: Data dict.
        - **yields**: The updated dict data.
    """

    def read_config(self):
        super().read_config()

    def run(self, path=None):
        out_dir = self.myconfig('outdir')
        check_folder(out_dir)

        command = f"journalctl --directory {path} -o short-iso"
        env = {'TZ': "UTC"}  # Return journalctl results in UTC instead of localtime
        process_regex = re.compile(r'(?P<appname>[^\[\s\:]+)(?:\[(?P<procid>[^\]\s]+)\])?\s?:?')
        self.logger().info("Extracting Journal logs. It might take some time")

        previous_data = {}
        try:
            for line in yield_command(command, logger=self.logger(), env=env):
                # Expected output format sample:
                # 2024-04-18T12:12:17+0200 MACHINENAME systemd[2961]: Started Application launched by gnome-shell.
                # All lines start with either a timestamp, a long space or a message like '-- Boot 451452577fbb4666a278f4b8ba8b9c2a --'
                output_splitted = line.rstrip().split(" ", maxsplit=3)
                if output_splitted[0] and not output_splitted[0].startswith('--'):
                    if previous_data:
                        yield previous_data
                        previous_data = {}
                    process_match = process_regex.match(output_splitted[2])
                    appname = process_match.groupdict().get('appname') if process_match else output_splitted[2]
                    procid = process_match.groupdict().get('procid') if process_match else ''
                    data = {
                        '@timestamp': output_splitted[0],
                        'host.name': output_splitted[1],
                        'log.syslog.appname': appname,
                        'log.syslog.procid': procid,
                        'message': output_splitted[3]
                    }
                    previous_data = data
                else:
                    previous_data["message"] = f'{previous_data.get("message", "")}\n{output_splitted[3]}'
        except Exception:
            import json
            for root, dirs, files in os.walk(path):
                for fname in files:
                    if fname.endswith('.journal'):
                        for line in yield_command(f"go-journalctl cat {os.path.join(root, fname)}", logger=self.logger(), env=env):
                            data = json.loads(line)
                            yield {'@timestamp': data['System']['Timestamp'],
                                   'host.name': data['System']['_HOSTNAME'],
                                   'log.syslog.appname': data['EventData']['SYSLOG_IDENTIFIER'],
                                   'log.syslog.procid': str(data['System']['_PID']),
                                   'message': data['EventData'].get("MESSAGE", "")}
        if len(previous_data) != 0:
            yield previous_data


class AnalysisLinuxSshLog(base.job.BaseModule):
    """ Analysis the Ssh log

    Module description:
        - **from_module**: Data dict.
        - **yields**: The updated dict data.
    """

    def read_config(self):
        super().read_config()

    def run(self, path=None):
        df_sshlogin_aux = pd.DataFrame()
        aux_list_pids = []

        p_prog_accepted = re.compile(r'.*Accepted\s([^\s]+)\sfor\s(\S+)\sfrom\s([\d\.]+)\sport\s(\d+).*')
        p_prog_closed = re.compile(r'.*pam_unix\(sshd:session\):\ssession\sclosed\sfor\suser\s(\S+).*')

        for line in self.from_module.run(path):
            line_pid = line["log.syslog.procid"]
            match_p_accepted = p_prog_accepted.match(line["message"].strip())

            if match_p_accepted:
                method, user_name, ut_host, port = match_p_accepted.groups()
                data = {'pid': line_pid,
                        'user.name': user_name,
                        'method': method,
                        'ut_host': ut_host,
                        'port': port,
                        '@timestamp': line['@timestamp'],
                        'ut_time_to': '',
                        'ut_time_total': ''
                        }
                new_row_df = pd.DataFrame([data])
                df_sshlogin_aux = pd.concat([df_sshlogin_aux, new_row_df], ignore_index=True)
            else:
                match_p_closed = p_prog_closed.match(line["message"].strip())
                if match_p_closed:
                    if "pid" not in df_sshlogin_aux.columns:
                        data = {'pid': line_pid,
                                'user.name': str(match_p_closed.groups()[0]),
                                'method': 'Uknown',
                                'ut_host': 'Uknown',
                                'port': 'Uknown',
                                '@timestamp': line['@timestamp'],
                                'ut_time_to': '',
                                'ut_time_total': 'Uknown - Session Closed '
                                }
                        yield data
                    else:
                        pid_in_df_sshlogin = df_sshlogin_aux.loc[df_sshlogin_aux['pid'] == line_pid]
                        if not pid_in_df_sshlogin.empty:
                            # it can be two or more sessions with the same pid
                            index_lists = [index_value for index_value in pid_in_df_sshlogin.index.values if index_value not in aux_list_pids]
                            index = index_lists[0]
                            aux_list_pids.append(index)

                            df_sshlogin_aux.at[index, "ut_time_to"] = line['@timestamp']
                            datetime_from = dateutil.parser.parse(df_sshlogin_aux.at[index, "@timestamp"])
                            datetime_to = dateutil.parser.parse(line['@timestamp'])

                            negative = ""
                            time_difference = datetime_to - datetime_from
                            if str(time_difference).startswith("-"):
                                time_difference = datetime_from - datetime_to
                                negative = "-"
                            total_seconds = int(time_difference.total_seconds())
                            hours, remainder = divmod(abs(total_seconds), 3600)
                            minutes, seconds = divmod(remainder, 60)
                            formatted_result = f"{negative}{hours:02}:{minutes:02}:{seconds:02}"

                            df_sshlogin_aux.at[index, "ut_time_total"] = formatted_result
                            yield df_sshlogin_aux.loc[index, ['@timestamp', 'user.name', 'method', 'ut_host', 'port', 'ut_time_to', 'ut_time_total']].to_dict()
                        else:
                            data = {'pid': line_pid,
                                    'user.name': str(match_p_closed.groups()[0]),
                                    'method': 'Uknown',
                                    'ut_host': 'Uknown',
                                    'port': 'Uknown',
                                    '@timestamp': line['@timestamp'],
                                    'ut_time_to': '',
                                    'ut_time_total': 'Uknown - Session Closed '
                                    }
                            yield data
