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


import datetime
import re
import os
import ast
import base.job
from base.utils import check_folder, save_csv

class Teamviewer_connections(base.job.BaseModule):
    """ Extracts teamviewer connections information """

    def run(self, path=None):
        """
        Attrs:
            path (str): Absolute path to the Connections_incoming.txt or Connections.txt file
        """

        self.check_params(path, check_path=True, check_path_exists=True)

        partition = ''
        user = ''

        srch = re.search(r'/(p\d{1,2})/', path)
        if srch:
            partition = srch.group(1)
        srch = re.search(r'/p\d{1,2}/Users/([^/]*)/', path)
        if srch:
            user = srch.group(1)

        lfields = False

        if path.endswith('incoming.txt'):
            srch = re.compile(r'^(\d+)\s+([^\t]+)\s+(\d{2}-\d{2}-\d{4} \d{2}:\d{2}:\d{2})\s+(\d{2}-\d{2}-\d{4} \d{2}:\d{2}:\d{2})\s+(\S+)\s+(\w+)')
            lfields = True
        else:
            srch = re.compile(r'^(\d+)\s+(\d{2}-\d{2}-\d{4} \d{2}:\d{2}:\d{2})\s+(\d{2}-\d{2}-\d{4} \d{2}:\d{2}:\d{2})\s+(\S+)\s+(\w+)')

        with open(path, 'r') as fin:
            for line in fin:
                if len(line) < 2:
                    continue
                fields = srch.search(line)
                if not fields:
                    self.logger().warning(f'Unable to parse line: {line}')
                    continue
                if lfields:
                    yield {
                           'startdate': str(datetime.datetime.strptime(fields.group(3), "%d-%m-%Y %H:%M:%S")),
                           'enddate': str(datetime.datetime.strptime(fields.group(4), "%d-%m-%Y %H:%M:%S")),
                           'teamviewer.hostname': fields.group(2).strip(),
                           'id_connection': fields.group(1),
                           'machine.hostname': fields.group(5),
                           'mode': fields.group(6),
                           'partition': partition}
                else:
                    yield {
                           'startdate': str(datetime.datetime.strptime(fields.group(2), "%d-%m-%Y %H:%M:%S")),
                           'enddate': str(datetime.datetime.strptime(fields.group(3), "%d-%m-%Y %H:%M:%S")),
                           'machine.hostname': fields.group(4),
                           'id.connection': fields.group(1),
                           'mode': fields.group(5),
                           'partition': partition,
                           'winuser': user}
                    

class Teamviewer(base.job.BaseModule):
    """ Extracts information about Teamviewer log """

    def run(self, path=None):
        """
        Attrs:
            path (str): Absolute path to the trace file
        """
        prog_log = re.compile(r'^(\d{4}\/\d{2}\/\d{2}\s\d{2}:\d{2}:\d{2}\.\d{3})\s+\d+\s+\d+\s.+?\s+(.*)')
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
                timestamp, message = match.groups()

                log_entry_dict = {
                    "Time": timestamp,
                    "Message": message.strip(),
                    "LogFilename": filename
                }

                prev_line_dict = log_entry_dict
            else:
                prev_line_dict["Message"] = prev_line_dict["Message"] + line

        if len(prev_line_dict) != 0:
            yield prev_line_dict


class Anydesk_connection_trace(base.job.BaseModule):
    """ Extracts information about DWAgent logs """

    def run(self, path=None):
        """
        Attrs:
            path (str): Absolute path to the trace file
        """
        prog_log = re.compile(r'(\w+)\s+(\d{4}-\d{2}-\d{2},\s\d{2}:\d{2})\s+(.+?)\s+(\d+)\s+(\d+)')
        for line in self.from_module.run(path):
            prog_match = prog_log.match(line)
            if prog_match:
                conn_type, timestamp_str, alias, id_anydesk, id_anydesk2 = prog_match.groups(default='')
                timestamp = datetime.datetime.strptime(timestamp_str, "%Y-%m-%d, %H:%M")
                log_dict = {
                    "Time": timestamp ,
                    "Type": conn_type,
                    "Alias": alias,
                    "ID": id_anydesk
                }
                yield log_dict


class Anydesk(base.job.BaseModule):
    """ Extracts information about anydesk logs """

    def run(self, path=None):
        """
        Attrs:
            path (str): Absolute path to the ad.trace file
        """

        self.check_params(path, check_path=True, check_path_exists=True)
        base_path = self.myconfig('outdir')
        check_folder(base_path)

         # Induce "partition" and "user" from "path". If path is in ProgramData, no user is assigned
        partition = ''
        user = ''
        srch = re.search(r'/(p\d{1,2})/', path)
        if srch:
            partition = srch.group(1)
        srch = re.search(r'/p\d{1,2}/Users/([^/]*)/', path)
        if srch:
            user = srch.group(1)
        outfile = os.path.join(base_path, 'anydesk_{}{}.csv'.format(partition, f'_{user}' if user else ''))
        save_csv(self._process_anydesk_log(path), outfile=outfile, file_exists='OVERWRITE', quoting=0)

    def _process_anydesk_log(self, path):
        # Get only significant events and skip the rest
        regex = re.compile(r'(External address|anynet.connection_mgr|Incoming session|Sending a connection request|Client-ID|app.prepare_task|Files|Logged|Connecting to|Accept request from|New user data)')
        ip_regex = re.compile(r'Logged\sin\sfrom\s((?:[0-9]{1,3}[\.]){3}[0-9]{1,3}).*')
        result = {}
        with open(path, 'r') as fin:
            for line in fin:
                if regex.search(line):
                    result['log.level'] = line[:8].strip()
                    result['@timestamp'] = line[8:31]
                    result['log.syslog.appname'] = line[31:42].strip()
                    #result['id1'] = line[43:49].strip()
                    #result['id2'] = line[50:56].strip()
                    result['log.logger'] = line[56:94].strip()
                    result['message'] = line[97:].strip()
                    ip_match = ip_regex.match(result['message'])
                    if ip_match:
                        result['IP'] =  ip_match.group(1)
                    else:
                        result['IP'] = ""
                    yield result


class Supremo(base.job.BaseModule):
    """ Extracts information about supremo logs """

    def run(self, path=None):
        """
        Attrs:
            path (str): Absolute path to the trace file
        """
        pattern_log = r'\[(.*?)\]\s*(\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2}:\d{3})\s+\[(TID\s*\d+)\s*\]\s*\[(.*?)\]\s*(.*)$'
        prog_log = re.compile(pattern_log)
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
                version, timestamp, thread, level, message = match.groups()
                date_object = datetime.datetime.strptime(timestamp.strip(), "%Y-%m-%d %H:%M:%S:%f")
                # Format the datetime object into ISO format
                iso_date = date_object.isoformat()

                log_entry_dict = {
                    "Time": iso_date,
                    "Message": message.strip(),
                    "Level": level.strip(),
                    "Version": version.strip(),
                    "Thread": thread.strip(),
                    "LogFilename": filename.strip()
                }

                prev_line_dict = log_entry_dict
            else:
                prev_line_dict["Message"] = prev_line_dict["Message"] + line

        if len(prev_line_dict) != 0:
            yield prev_line_dict


class GoogleChromeRemoteDesktop(base.job.BaseModule):
    """ Extracts information about GoogleChromeRemoteDesktop logs """

    def run(self, path=None):
        """
        Attrs:
            path (str): Absolute path to the trace file
        """
        for event in self.from_module.run(path):
            if event["event.code"] == '4':
                message_dict = ast.literal_eval(event["data.text"])
                event["Client"] = message_dict[0]
                event["IP"] = message_dict[1]
                event["HostIP"] = message_dict[2]
                event["Channel"] = message_dict[3]
                event["Connection"] = message_dict[4]
            
            if event["event.code"] == '1':
                 message_dict = ast.literal_eval(event["data.text"])
                 event["Client"] = message_dict[0]

            if event["event.code"] == '5':
                 message_dict = ast.literal_eval(event["data.text"])
                 event["Client"] = message_dict[0]

            if event["event.code"] == '2':
                 message_dict = ast.literal_eval(event["data.text"])
                 event["Client"] = message_dict[0]
            
            yield event
    

class DWAgent(base.job.BaseModule):
    """ Extracts information about DWAgent logs """

    def run(self, path=None):
        """
        Attrs:
            path (str): Absolute path to the trace file
        """
        pattern_log = r'(\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2},\d{3})\s(\w+)\s(\S+)\s?(.*)'
        prog_log = re.compile(pattern_log)

        pattern_ip = r'.*ip:\s((?:\d+\.?){4}).*'
        prog_ip = re.compile(pattern_ip)

        filename = os.path.basename(path)

        for line in self.from_module.run(path):
            log_match = prog_log.match(line)
            if log_match:
                timestamp, level, thread, message = log_match.groups()
                log_entry_dict = {
                    "Time": timestamp,
                    "Message": message.strip(),
                    "Level": level.strip(),
                    "Thread": thread.strip(),
                    "LogFilename": filename.strip()
                }

                ip_match = prog_ip.match(message)
                if ip_match:
                    ip = ip_match.group(1)
                    log_entry_dict["IP"] = ip

                yield log_entry_dict
            
            else:
                self.logger().warning("Regex pattern failed parsering: " + line)
            

class Splashtop(base.job.BaseModule):
    """ Extracts information about DWAgent logs """

    def run(self, path=None):
        """
        Attrs:
            path (str): Absolute path to the trace file
        """
        ft_log = re.compile(r'^(\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2})\t(.*?)\t(.*?)\t(\w*\t\w*)\t(\S*)\s\((.*?)\)')
        other_log = re.compile(r'^<(\d+)>(\w{3}\d{1,2}\s\d{2}:\d{2}:\d{2}\.\d{3})\s+\w+\[(\S+)\]\s(.+)$')
        get_date_log = re.compile(r'<\d+>(\w{3}\d{1,2})\s\d{2}:\d{2}:\d{2}\.\d{3}.*')
        filename = os.path.basename(path)
        
        m_time_year = datetime.datetime.fromtimestamp(os.path.getmtime(path)).year
        aux_year = 0

        # As the logs don't save the year, check if corresponds to different years
        if filename != "FTCLog.txt":
            aux_date = datetime.datetime(1900, 1, 1)
            with open(path, 'r') as file:
                for line in file:
                    date_match = get_date_log.match(line)
                    if date_match:
                        timestamp = datetime.datetime.strptime(date_match.group(1), "%b%d")
                        if timestamp < aux_date:
                            aux_year += 1
                        aux_date = timestamp

        aux_date = datetime.datetime(1900, 1, 1)
        for line in self.from_module.run(path):
            if filename == "FTCLog.txt":
                ft_match = ft_log.match(line)
                if ft_match:
                    timestamp, object, size, message, user, ip = ft_match.groups(default='')
                    log_dict = {
                        "Time": timestamp ,
                        "Message": message.strip(),
                        "Object": object,
                        "User": user,
                        "Size": size,
                        "IP": ip,
                        "LogFilename": filename.strip()
                    }
                    yield log_dict
                else:
                    self.logger().warning("Regex pattern failed parsering: " + line)
            else:
                other_match = other_log.match(line)
                if other_match:
                    level_int, timestamp_str, process, message = other_match.groups(default='')

                    level = self.getLevel(int(level_int))
                    timestamp = datetime.datetime.strptime(timestamp_str, "%b%d %H:%M:%S.%f")
                    actual_date = datetime.datetime(1900, timestamp.month, timestamp.day)

                    if actual_date < aux_date:
                        aux_year -= 1
                    aux_date = actual_date
                    
                    timestamp = timestamp.replace(year=m_time_year - aux_year)

                    log_dict = {
                        "Time": timestamp ,
                        "Message": message.strip(),
                        "Process": process,
                        "Level": level,
                        "LogFilename": filename
                    }
                    yield log_dict
                else:
                    self.logger().warning("Regex pattern failed parsering: " + line)
    
    def getLevel(self, level_int):
        if level_int == 0:
            return "Error"
        elif level_int == 1:
            return "Informational"
        else:
            return level_int


class Zoho(base.job.BaseModule):
    """ Extracts information about DWAgent logs """

    def run(self, path=None):
        """
        Attrs:
            path (str): Absolute path to the trace file
        """
        prog_con_date = re.compile(r'Logging started from:\s?\[(.*?)\].*')
        prog_con_name = re.compile(r'Product Name:(.*)')
        prog_con_version = re.compile(r'Version:(.*)')
        log_1 = re.compile(r'^\d*\s*(\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2}\.?\d*)\s*(\w*)\s*\[?\d*\]?\s*\[(\S*?)\]\s*(.*)$')
        log_2 = re.compile(r'^(\d{4}\/\d{2}\/\d{2}\s\d{2}:\d{2}:\d{2}\.?\d*)\|?\s*\d*\|?\s*\d*\s*\d*\s*\[?(\w*)\]?(.*)')
        log_3 = re.compile(r'^(\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2}\.?\d*)(.*)')
        log_4 =re.compile(r'(\d*)\s(\d{1,2}:\d{1,2}:\d{1,2}):?\d*\s*(.*)')
        log_5 = re.compile(r'^(\d{2}\/\d{2}\/\d{4}\s\d{2}:\d{2}:\d{2}):?\d*\s*\|\d*\|\s*\[?(\w*)\]?(.*)')

        date_to_yield = ""
        product_to_yield = ""
        version_to_yield = ""

        filename = os.path.basename(path)

        for line in self.from_module.run(path):
            date_match = prog_con_date.match(line)
            name_match = prog_con_name.match(line)
            version_match = prog_con_version.match(line)
            log4_match = log_4.match(line)
            log3_match = log_3.match(line)
            log2_match = log_2.match(line)
            log5_match = log_5.match(line)
            log1_match = log_1.match(line)

            if date_match:
                date_to_yield = date_match.group(1)

            elif name_match:
                product_to_yield = name_match.group(1)

            elif version_match:
                version_to_yield = version_match.group(1)
            
            elif log4_match:
                thread, time, message = log4_match.groups(default='')
                iso_date = datetime.datetime.strptime(date_to_yield + " " + time, "%d-%m-%Y %H:%M:%S").isoformat()
                log_dict = {
                    "Time": iso_date ,
                    "Message": message.strip(),
                    "Thread": thread.strip(),
                    "Version": version_to_yield,
                    "Product": product_to_yield,
                    "LogFilename": filename.strip()
                }
                yield log_dict
            
            elif log3_match:
                timestamp, message = log3_match.groups(default='')
                log_dict = {
                    "Time": timestamp ,
                    "Message": message.strip(),
                    "Version": version_to_yield,
                    "Product": product_to_yield,
                    "LogFilename": filename.strip()
                }
                yield log_dict
            
            elif log2_match:
                print(line)
                timestamp, level, message = log2_match.groups(default='')
                log_dict = {
                    "Time": timestamp ,
                    "Message": message.strip(),
                    "Level": level.strip(),
                    "Version": version_to_yield,
                    "Product": product_to_yield,
                    "LogFilename": filename.strip()
                }
                yield log_dict
            
            elif log5_match:
                timestamp, level, message = log5_match.groups(default='')
                iso_date = datetime.datetime.strptime(timestamp, "%d/%m/%Y %H:%M:%S").isoformat()
                log_dict = {
                    "Time": timestamp ,
                    "Message": message.strip(),
                    "Level": level.strip(),
                    "Version": version_to_yield,
                    "Product": product_to_yield,
                    "LogFilename": filename.strip()
                }
                yield log_dict
            
            elif log1_match:
                timestamp, level, thread, message = log1_match.groups(default='')
                log_dict = {
                    "Time": timestamp ,
                    "Message": message.strip(),
                    "Thread": thread.strip(),
                    "Level": level.strip(),
                    "Version": version_to_yield,
                    "Product": product_to_yield,
                    "LogFilename": filename.strip()
                }
                yield log_dict