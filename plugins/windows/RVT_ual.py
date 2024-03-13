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
import subprocess
import base.job
from base.utils import check_directory, save_md_table
from base.commands import yield_command


class UAL(base.job.BaseModule):

    def read_config(self):
        super().read_config()
        self.set_default_config('ual_parser', os.path.join(self.myconfig('rvthome'), "plugins/external/KStrike/KStrike.py"))

    def run(self, path=""):
        """ Parses User Access Logs
        """

        # Parsing Tool: https://github.com/brimorlabs/KStrike
        # UAL forensic information: https://svch0st.medium.com/windows-user-access-logs-ual-9580f1100635

        self.parser = self.myconfig('ual_parser')

        self.check_params(path, check_path=True, check_path_exists=True)
        base_path = self.myconfig('outdir')
        check_directory(base_path, create=True)
        for file_in in os.listdir(path):
            if not file_in.lower().endswith('.mdb'):
                continue
            outfile_dump = os.path.join(base_path, "%s.txt" % file_in.split('.')[0])
            outfile_md = os.path.join(base_path, "%s.md" % file_in.split('.')[0])
            results = self.parse(os.path.join(os.path.abspath(path), file_in), outfile_dump)
            save_md_table(list(results), config=None, outfile=outfile_md, file_exists='OVERWRITE',
                          fieldnames='LastAccess InsertDate AuthenticatedUserName ConvertedAddress RoleName TotalAccesses')

        return []

    def parse(self, f_in, f_out):
        command = ['/usr/bin/python3', self.parser, f_in]
        i = 0
        with open(f_out, 'w') as fout:
            for line in yield_command(command, stderr=subprocess.DEVNULL, logger=self.logger()):
                line = line.replace('||', '|').replace('\x00', '')
                fout.write(line)
                i = i + 1
                if i == 1:  # skip headers line
                    continue
                data = {}
                line = line.split('|')
                # Expected headers: "RoleGuid (RoleName)|TenantId|TotalAccesses|InsertDate|LastAccess|RawAddress|ConvertedAddress (Correlated_HostName(s))|AuthenticatedUserName|DatesAndAccesses|"
                if len(line) != 10:
                    self.logger().warn(f'Unexpected output when parsing file {f_in}')
                    continue
                data['LastAccess'] = line[4]
                data['InsertDate'] = line[3]
                data['AuthenticatedUserName'] = line[7]
                data['ConvertedAddress'] = line[6]
                if line[6].endswith("(No Match for IP address found)"):
                    data['ConvertedAddress'] = line[6].split('(')[0].strip()
                data['RoleName'] = line[0].split('(')[1].strip(')')
                data['TotalAccesses'] = line[2]
                yield data
