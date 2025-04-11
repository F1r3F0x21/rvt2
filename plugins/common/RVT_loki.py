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

import re

import base.job


class Alerts(base.job.BaseModule):
    def run(self, path=None):
        # self.check_params(path, check_path=True, check_path_exists=True)

        match = False
        for d in self.from_module.run(path):
            if d['Level'] == "WARNING":
                if "replaced process" in d['Message']:
                    if len(re.findall(r"CMD+.+PATH", d['Message'])) >= 1:
                        process1 = re.findall(r"CMD+.+PATH", d['Message'])[0].replace(" PATH", "").replace('"', '')
                        process2 = re.findall(r"PATH+.+REPLACED", d['Message'])[0].replace(" REPLACED", "").replace("PATH: ", "")
                        # name = re.findall(r"NAME+.+OWNER", d['Message'])[0].replace("NAME: ", "").replace("OWNER", "").split(".")[0]
                        process2_str = ".".join(process2.split(".")[0:-1])
                        if process2_str.lower() not in process1.lower():
                            yield d
                            match = True
                elif "implanted process" in d['Message']:
                    if len(re.findall(r"CMD+.+PATH", d['Message'])) >= 1:
                        process1 = re.findall(r"CMD+.+PATH", d['Message'])[0].replace(" PATH", "").replace('"', '')
                        process2 = re.findall(r"PATH+.+IMPLANTED", d['Message'])[0].split(" PE")[0].replace(" IMPLANTED", "").replace("PATH: ", "")
                        # name = re.findall(r"NAME+.+OWNER", d['Message'])[0].replace("NAME: ", "").replace("OWNER", "").split(".")[0]
                        process2_str = ".".join(process2.split(".")[0:-1])
                        if process2_str.lower() not in process1.lower():
                            yield d
                            match = True
                else:
                    yield d
                    match = True

            if d['Level'] == "ALERT":
                yield d
                match = True
        if not match:
            self.logger().info("No results found in loki memory analysis")
