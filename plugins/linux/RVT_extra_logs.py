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
import time
import base.job
from base.utils import date_to_iso
from plugins.linux import get_timezone
from datetime import datetime


class AuthLog(base.job.BaseModule):
    
    """ Extract the Auth.Log file

    Module description:
        - **from_module**: Data dict.
        - **yields**: The updated dict data.
    """

    def read_config(self):
        super().read_config() 

    def run(self, path=None):
        self.logger().warning("Please note that reading " + os.path.basename(path) + " could take some time")

        pattern = r'(\w+\s+\d+\s\d+:\d+:\d+)\s([\w.-]+)\s(\S+):(\s.*)'
        prog = re.compile(pattern)
        tz = get_timezone(self.myconfig('mountdir'))


        prev_date_str = "Jan 1 00:00:00"
        prev_date = datetime.strptime(prev_date_str, "%b %d %H:%M:%S")
        year_passed = 0

        modification_time = os.path.getmtime(path)
        year = time.localtime(modification_time).tm_year
        
        for line in self.from_module.run(path):
            match = prog.match(line)
            if match:
                timestamp, host, process, command = match.groups()
                log_entry_dict = {
                    "@timestamp": timestamp,
                    "host.hostname": host,
                    "process.name": process,
                    "process.command_line": command
                }

                actual_date = datetime.strptime(timestamp, "%b %d %H:%M:%S")
                if (prev_date > actual_date):
                    year_passed += 1
                prev_date = actual_date

                AuthLog_timestamp_with_year = f"{year + year_passed} {log_entry_dict['@timestamp']}"

                # Parse the timestamp and convert it to ISO format
                parsed_timestamp = datetime.strptime(AuthLog_timestamp_with_year, "%Y %b %d %H:%M:%S")     
                output_string_utc = date_to_iso(parsed_timestamp, input_timezone=tz, output_timezone="UTC")
                log_entry_dict['@timestamp'] = output_string_utc
                yield log_entry_dict

            else:
                self.logger().warning("Regex pattern failed with some logline input " + line)