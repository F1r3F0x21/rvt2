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
            pattern = r'(\w+\s+\d+\s\d+:\d+:\d+)\s([\w.-]+)\s(\S+):(\s.*)?'
            prog = re.compile(pattern)
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