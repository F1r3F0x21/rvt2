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
import re
import ast
import pandas as pd
import base.job
from datetime import datetime
from base.utils import check_directory, date_to_iso, save_csv
from plugins.linux import get_timezone


class LinuxStandardLog(base.job.BaseModule):
    
    """ Extract the Logfile

    Module description:
        - **from_module**: Data dict.
        - **yields**: The updated dict data.

    Configuration:
        - **logtemplate**:  (String): String-based Template of the configuration logfile, usually: rsyslog.conf. Default RSYSLOG_TraditionalFileFormat
    """

    def read_config(self):
        super().read_config()
        self.set_default_config('logtemplate', 'RSYSLOG_TraditionalFileFormat')

    def run(self, path=None):
        if self.myconfig('logtemplate') == "RSYSLOG_TraditionalFileFormat" :
            pattern = r'(\w+\s+\d+\s\d+:\d+:\d+)\s([\w.-]+)\s(.*)?'
            prog = re.compile(pattern)
            filename = os.path.basename(path)
            
            for line in self.from_module.run(path):
                match = prog.match(line)
                if match:
                    timestamp, host, process_command = match.groups()
                    process, command = process_command.split(":", maxsplit=1)
                    log_entry_dict = {
                        "@timestamp": timestamp,
                        "host.hostname": host,
                        "process.name": process,
                        "process.command_line": command,
                        "filename": filename
                    }
                    yield log_entry_dict

                else:
                    self.logger().warning("Regex pattern failed with some logline input " + line)
        else:
            self.logger().warning("Logtemplete " + self.myconfig('logtemplate') + " Not supported yet")


class LinuxDpkgLog(base.job.BaseModule):
    
    """ Extract the Dpkg

    Module description:
        - **from_module**: Data dict.
        - **yields**: The updated dict data.
    """

    def read_config(self):
        super().read_config()

    def run(self, path=None):
        pattern = r'(\d+-\d+-\d+\s\d+:\d+:\d+)\s(.*)'
        tz = get_timezone(self.myconfig('mountdir'))
        prog = re.compile(pattern)
        filename = os.path.basename(path)
        
        for line in self.from_module.run(path):
            match = prog.match(line)
            if match:
                timestamp, action = match.groups()
                log_entry_dict = {
                    "@timestamp": timestamp,
                    "action": action,
                    "filename": filename
                }
                actual_date = datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")
                 # Parse the timestamp and convert it to ISO format
                output_string_utc = date_to_iso(actual_date, input_timezone=tz, output_timezone="UTC")
                log_entry_dict['@timestamp'] = output_string_utc

                yield log_entry_dict

            else:
                self.logger().warning("Regex pattern failed with some logline input " + line)


class LinuxAptHistoryLog(base.job.BaseModule):
    
    """ Extract the Dpkg

    Module description:
        - **from_module**: Data dict.
        - **yields**: The updated dict data.
    """

    def read_config(self):
        super().read_config()

    def run(self, path=None):
        aux_dict = {}
        for line in self.from_module.run(path):
            if line:
                linesplited = line.split(":", 1)
                if linesplited[0] == "Start-Date":
                    aux_dict = {}
                    timestamp = linesplited[1].strip()
                    localdate = datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")
                    isodate = date_to_iso(localdate, input_timezone = get_timezone(self.myconfig('mountdir')))
                    aux_dict["@timestamp"] = isodate
                elif linesplited[0] == "End-Date":
                        timestamp = linesplited[1].strip()
                        localdate = datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")
                        isodate = date_to_iso(localdate, input_timezone = get_timezone(self.myconfig('mountdir')))
                        aux_dict[linesplited[0]] = isodate
                        yield aux_dict
                elif linesplited[0] == "Commandline":
                    aux_dict[linesplited[0]] = linesplited[1]
                else:
                    if "action" in aux_dict:
                        aux_list =  list(aux_dict["action"])
                        aux_list.append({linesplited[0]:linesplited[1]})
                        aux_dict["action"] = aux_list
                    else:
                        aux_dict["action"] = [{linesplited[0]:linesplited[1]}]


class AnalysisLinuxSshLog(base.job.BaseModule):
    """ Analisis the Ssh log

    Module description:
        - **from_module**: Data dict.
        - **yields**: The updated dict data.
    """
    def read_config(self):
        super().read_config()
    
    def run(self, path=None):
        df_sshlogin_aux = pd.DataFrame()
        aux_list_pids = []
        pid_pattern = r'.*\[(\d+)\]'
        pid_prog = re.compile(pid_pattern)

        p_pattern_accepted = r'Accepted\s(\w+)\sfor\s(\S+)\sfrom\s([\d\.]+)\sport\s(\d+).*'
        p_prog_accepted = re.compile(p_pattern_accepted)

        p_pattern_closed = r'pam_unix\(sshd:session\):\ssession\sclosed\sfor\suser\s.*'
        p_prog_closed = re.compile(p_pattern_closed)

        
        for line in self.from_module.run(path):
            #print(line)
            line_pid = pid_prog.match(line["process.name"]).group(1)
            match_p_accepted = p_prog_accepted.match(line["process.command_line"].strip())

            #print(line["process.command_line"])
            if match_p_accepted:
                method, user_name, ut_host, port = match_p_accepted.groups()
                data = {'pid': line_pid,
                        'host.hostname': line['host.hostname'], 
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
                match_p_closed = p_prog_closed.match(line["process.command_line"].strip())
                if match_p_closed:
                    pid_in_df_sshlogin = df_sshlogin_aux.loc[df_sshlogin_aux['pid'] == line_pid]
                    if not pid_in_df_sshlogin.empty:
                        # it can be two or more sessions with the same pid
                        index_lists = [index_value for index_value in pid_in_df_sshlogin.index.values if index_value not in aux_list_pids]
                        index = index_lists[0]
                        aux_list_pids.append(index)

                        df_sshlogin_aux.at[index, "ut_time_to"] = line['@timestamp']

                        # time conversion
                        time_format = "%b %d %H:%M:%S"
                        time_from = df_sshlogin_aux.at[index, "@timestamp"]
                        time_to = line['@timestamp']

                        datetime_from = datetime.strptime(time_from, time_format)
                        datetime_to = datetime.strptime(time_to, time_format)

                        time_difference = datetime_to - datetime_from
                        total_minutes = int(time_difference.total_seconds()/ 60)
                        hours, minutes = divmod(abs(total_minutes), 60)
                        hours *= -1 if total_minutes < 0 else 1
                        formatted_result = f"{'-' if hours == 0 and total_minutes < 0  else ''}{hours:02}:{minutes:02}"

                        df_sshlogin_aux.at[index, "ut_time_total"] = formatted_result
                        yield df_sshlogin_aux.loc[index, ['@timestamp', 'host.hostname','user.name', 'method', 'ut_host', 'port', 'ut_time_to', 'ut_time_total']].to_dict()


class AnalysisLinuxAptHistoryLog(base.job.BaseModule):
    """ Analisis the Ssh log

    Module description:
        - **from_module**: Data dict.
        - **yields**: The updated dict data.
    """
    def read_config(self):
        super().read_config()
    
    def run(self, path=None):
        pkg_pattern = r'([\w\.-]+):(.+)\s\(([\d\~\w\.-]*).*\)'
        pkg_prog = re.compile(pkg_pattern)
        upgrade_list = []
        remove_list = []
        purge_list = []

        for line in self.from_module.run(path):
            user_responsible = '' 
            action_list = ast.literal_eval(line["action"])
            if any("Requested-By" in x for x in action_list):
                user_responsible = [x["Requested-By"] for x in action_list if "Requested-By" in x]

            for action in action_list:
                package_action, package = list(action.items())[0]
                if not package_action == "Requested-By":
                    for package_name in package.split("),"):
                        if not str(package_name).endswith(")"):
                            package_name += ")"
                        match_pkg = pkg_prog.match(package_name.strip())
                        if match_pkg:
                            package_name, package_architecture, package_version = match_pkg.groups()
                            data_dict = {
                                '@timestamp': line['@timestamp'],
                                'package.name' : package_name,
                                'package.architecture' : package_architecture,
                                'package.version' : package_version,
                                'username' : user_responsible
                            }

                            if package_action == "Install":
                                yield data_dict
                            elif package_action == "Upgrade":
                                upgrade_list.append(data_dict)
                            elif package_action == "Remove":
                                remove_list.append(data_dict)
                            elif package_action == "Purge":
                                purge_list.append(data_dict)
                        else:
                            self.logger().warning("Regex pattern failed with some package name: " + package_name)

        # Save upgraded, removed and purged packages in diferent csv
        analysisdir = self.myconfig('analysisdir')
        check_directory(analysisdir, create=True)

        if upgrade_list:
            csv_upgrade_out = os.path.join(analysisdir, 'apt_packages_upgraded.csv')
            save_csv(upgrade_list, outfile=csv_upgrade_out)
        
        if remove_list:
            csv_remove_out = os.path.join(analysisdir, 'apt_packages_removed.csv')
            save_csv(remove_list, outfile=csv_remove_out)

        if purge_list:
            csv_purge_out = os.path.join(analysisdir, 'apt_packages_purged.csv')
            save_csv(purge_list, outfile=csv_purge_out)