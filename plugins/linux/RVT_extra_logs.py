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
import pandas as pd
import base.job
from datetime import datetime
from base.utils import date_to_iso

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
                        yield df_sshlogin_aux.loc[index].to_dict()

        # Saving table
        txt_out = os.path.join(self.myconfig('analysisdir'), 'logins_summary_ssh.md')
        data = df_sshlogin_aux.to_markdown()
        with open(txt_out, 'w') as file:
            file.write(data)






''' 
class LinuxStandardLog2(base.job.BaseModule):
    
    """ Extract the Auth.Log file

    Module description:
        - **from_module**: Data dict.
        - **yields**: The updated dict data.
    """

    def read_config(self):
        super().read_config() 

    def run(self, path=None):
        self.logger().warning("Please note that reading " + os.path.basename(path) + " could take some time")

        pattern = r'(\w+\s+\d+\s\d+:\d+:\d+)\s([\w.-]+)\s(\S+):(\s.*)?'
        prog = re.compile(pattern)
        tz = get_timezone(self.myconfig('mountdir'))


        prev_date_str = "Jan 1 00:00:00"
        prev_date = datetime.strptime(prev_date_str, "%b %d %H:%M:%S")
        year_passed = 0

        result = subprocess.run(["exiftool", "-ModifyDate", path], capture_output=True, text=True, check=True)
        print(result.stdout)


        modification_time = os.path.getmtime(path)
        year = time.localtime(modification_time).tm_year

        filename = os.path.basename(path)

        for line in self.from_module.run(path):
            match = prog.match(line)
            if match:
                timestamp, host, process, command = match.groups()
                log_entry_dict = {
                    "@timestamp": timestamp,
                    "host.hostname": host,
                    "process.name": process,
                    "process.command_line": command,
                    "filename": filename

                }
                actual_date = datetime.strptime(timestamp, "%b %d %H:%M:%S")
                if ((prev_date.month, prev_date.day) > (actual_date.month, actual_date.day)):
                    year_passed += 1
                prev_date = actual_date

                log_timestamp_with_year = f"{year + year_passed} {log_entry_dict['@timestamp']}"

                # Parse the timestamp and convert it to ISO format
                parsed_timestamp = datetime.strptime(log_timestamp_with_year, "%Y %b %d %H:%M:%S")     
                output_string_utc = date_to_iso(parsed_timestamp, input_timezone=tz, output_timezone="UTC")
                log_entry_dict['@timestamp'] = output_string_utc
                yield log_entry_dict

            else:
                self.logger().warning("Regex pattern failed with some logline input " + line)

class CSVReaderReversed(base.job.BaseModule):
    """ Yields every line in a CSV file.

    Configuration:
        - **encoding** (String): The encoding to use. Defaults to "utf-8"
        - **delimiter** (String): The delimiter to use. Use `AUTO` to dinamically find out. Defaults to ;
        - **quotechar** (String): The quotechar. Defaults to \"
        - **restkey** (String): The restkey of the DictReader. Defaults to "extra".
        - **restval** (String): The restval of the DictReader. Defaults to the empty string.
        - **fieldnames**: A space separated list of header names. If None, use the first line.
          Warning: If provided, the first line will be considered data unless ignore_lines is set to >0
        - **ignore_lines** (int): Ignore this number of initial lines. If fieldnames is provided, the first line is also ignored.
        - **progress.disable** (Boolean): If True, disable the progress bar.
        - **progress.cmd** (String): The shell command to run to estimate the number of lines in the file.
        - **check_path_exists** (Boolean): If True and provided path does not exist, raise an error. I False, just warn and continue
    """

    def read_config(self):
        super().read_config()
        self.set_default_config('encoding', 'utf-8')
        self.set_default_config('delimiter', ';')
        self.set_default_config('quotechar', '"')
        self.set_default_config('restkey', 'extra')
        self.set_default_config('restval', '')
        self.set_default_config('fieldnames', '')
        self.set_default_config('ignore_lines', '0')
        self.set_default_config('progress.disable', 'False')
        self.set_default_config('progress.cmd', 'cat "{path}" | wc -l')
        self.set_default_config('field_size_limit', sys.maxsize)  # Default csv max is 131072
        self.set_default_config('check_path_exists', True)


    def run(self, path):
        """ Read CSV file in the path. from_module is ignored """
        try:
            self.check_params(path, check_path=True, check_path_exists=True)
        except base.job.RVTErrorNotExistingPath as exc:
            if not self.myflag('check_path_exists'):
                self.logger().warning(exc)
                return []
            raise exc
        csv.field_size_limit(int(self.myconfig('field_size_limit')))
        with open(path, 'r', encoding=self.myconfig('encoding')) as infile:
            ignore_lines = int(self.myconfig('ignore_lines'))
            fieldnames = self.myarray('fieldnames', None)
            for i in range(0, ignore_lines):
                infile.readline()
            if self.myconfig('delimiter') == 'AUTO':
                delimiter = csv.Sniffer().sniff(infile.readline()).delimiter
                infile.seek(0)
            else:
                delimiter = self.myconfig('delimiter')
            reader = csv.DictReader(
                infile,
                fieldnames=fieldnames,
                restval=self.myconfig('restval'), restkey=self.myconfig('restkey'),
                delimiter=delimiter, quotechar=self.myconfig('quotechar'))
            # progress management
            total_iterations = estimate_iterations(path, self.myconfig('progress.cmd'))
            # if fieldnames is None, the first line is header. Add one to progress
            if fieldnames:
                initial_progress = ignore_lines
            else:
                initial_progress = ignore_lines + 1
            # main loop
            for data in tqdm(reversed(list(reader)), total=total_iterations,
                             initial=initial_progress,
                             desc='Reading {}'.format(os.path.basename(path)),
                             disable=self.myflag('progress.disable')):
                yield data

class AllLinesInFileReversed(base.job.BaseModule):
    """ Yields every line in a file as a string

    Configuration:
        - **encoding** (String): The encoding to use. Defaults to utf-8
        - **progress.disable** (Boolean): If True, disable the progress bar.
        - **progress.cmd** (String): The shell command to run to estimate the number of lines in the file. """

    def read_config(self):
        super().read_config()
        self.set_default_config('encoding', 'utf-8')
        self.set_default_config('progress.disable', 'False')
        self.set_default_config('progress.cmd', 'cat "{path}" | wc -l')

    def run(self, path):
        """ Read all lines from the path. from_module is ignored """
        self.check_params(path, check_path=True, check_path_exists=True)
        total_iterations = base.commands.estimate_iterations(path, self.myconfig('progress.cmd'))
        with open(path, 'r', encoding=self.myconfig('encoding')) as infile:
            for line in tqdm(reversed(list(infile)), total=total_iterations,
                             desc='Reading {}'.format(os.path.basename(path)),
                             disable=self.myflag('progress.disable')):
                yield line.strip()

class YearLinuxStandardLog2(base.job.BaseModule):
    """ Extract the Auth.Log file

    Module description:
        - **from_module**: Data dict.
        - **yields**: The updated dict data.
    """

    def read_config(self):
        self.set_default_config('log_files', None)
        super().read_config() 
    
    def run(self, path=None):
        log_files = self.myconfig('log_files')
        list_log_files = glob.glob(log_files, recursive=self.myflag('recursive'))
        list_log_files_sorted = sorted(list_log_files)


        tz = get_timezone(self.myconfig('mountdir'))
        prev_date_str = "Jan 1 00:00:00"
        prev_date = datetime.strptime(prev_date_str, "%b %d %H:%M:%S")
        year_passed = 0

        modification_time = os.path.getmtime(list_log_files_sorted[0])
        year = time.localtime(modification_time).tm_year

        for line in self.from_module.run(path):
            # Read a single line
            log_entry_dict = {
                "@timestamp": line["@timestamp"],
                "host.hostname": line["host.hostname"],
                "process.name": line["process.name"],
                "process.command_line": line["process.command_line"]
            }
            actual_date = datetime.strptime(line["@timestamp"], "%b %d %H:%M:%S")
            if ((prev_date.month, prev_date.day) < (actual_date.month, actual_date.day)):
                year_passed -= 1
            prev_date = actual_date

            log_timestamp_with_year = f"{year + year_passed} {log_entry_dict['@timestamp']}"

            #Parse the timestamp and convert it to ISO format
            parsed_timestamp = datetime.strptime(log_timestamp_with_year, "%Y %b %d %H:%M:%S")     
            output_string_utc = date_to_iso(parsed_timestamp, input_timezone=tz, output_timezone="UTC")
            log_entry_dict['@timestamp'] = output_string_utc
            yield log_entry_dict
'''