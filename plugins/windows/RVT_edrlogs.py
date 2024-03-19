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


class CortexLogs(base.job.BaseModule):
    
    """ Extract the Logfile

    Module description:
        - **from_module**: Data dict.
        - **yields**: The updated dict data.

    Configuration:
        - **logname**:  (String): Logfile name of Cortex logs
    """

    def read_config(self):
        super().read_config()
        self.set_default_config('logname', 'cortex-xdr-payload')


    def run(self, path=None):
        
        if self.myconfig('logname') == "cortex-xdr-payload":
            pattern = r'(.*)\|(.*)\|(.*)\|(.*)\|(.*)\|(.*)'
            prog = re.compile(pattern)
            filename = os.path.basename(path)
            count_lines = 0
            prev_line_dict = {}

            for line in self.from_module.run(path):
                match = prog.match(line)
                if match:

                    if count_lines != 0:
                        count_lines = 0
                        yield prev_line_dict

                    count_lines = 1
                    timestamp, type, process, action, thread, message = match.groups()

                    log_entry_dict = {
                        "@timestamp": timestamp.strip(),
                        "type": type.strip(),
                        "process.id": process.strip(),
                        "action": action.strip(),
                        "thread": thread.strip(),
                        "message": message.strip(),
                        "filename": filename.strip()
                    }

                    prev_line_dict = log_entry_dict
                else:
                    prev_line_dict["message"] = prev_line_dict["message"] + line

            if len(prev_line_dict) != 0:
                yield prev_line_dict
        
        elif self.myconfig('logname') == "trapsd":
            pattern = r'^(\S*)\s<(\S*)>\s(\S*)\s\[(\S*\s?\S*)\]\s*({[^}]*})(.*)$'
            prog = re.compile(pattern)

            filename = os.path.basename(path)
            count_lines = 0
            prev_line_dict = {}

            for line in self.from_module.run(path):
                match = prog.match(line)
                if match:

                    if count_lines != 0:
                        count_lines = 0
                        yield prev_line_dict

                    count_lines = 1
                    timestamp, severity, hostname, thread, context, message = match.groups(default='')

                    log_entry_dict = {
                        "@timestamp": timestamp.strip(),
                        "severity": severity.strip(),
                        "hostname": hostname.strip(),
                        "thread": thread.strip(),
                        "context": context.strip().strip('{}'),
                        "message": message.strip(),
                        "filename": filename.strip()
                    }
                    prev_line_dict = log_entry_dict
                
                else:
                    prev_line_dict["message"] = prev_line_dict["message"] + line

            if len(prev_line_dict) != 0:
                yield prev_line_dict
 
        else:
            self.logger().warning("Log file" + self.myconfig('logtemplate') + " Not supported yet")