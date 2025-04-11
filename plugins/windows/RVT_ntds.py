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
import ujson as json
import re
import base.job
from base.utils import check_directory
from base.commands import run_command, yield_command


class Parse(base.job.BaseModule):

    def run(self, path=""):
        """ Parses NTDS.dit
        """

        # https://github.com/janstarke/ntdsextract2

        self.check_params(path, check_path=True, check_path_exists=True)
        base_path = self.myconfig('outdir')
        ntdsxtract = self.myconfig('ntdsxtract')
        ntds_file = path
        check_directory(base_path, create=True)

        try:
            with open(os.path.join(base_path, 'bodyfile.csv'), 'w') as fout:
                run_command([ntdsxtract, ntds_file, 'timeline', '-q'], fout, stderr=subprocess.DEVNULL, logger=self.logger())
            with open(os.path.join(base_path, 'timeline.csv'), 'w') as fout:
                run_command(['mactime', "-b", os.path.join(base_path, 'bodyfile.csv'), "-m", "-y", "-d"], fout, stderr=subprocess.DEVNULL, logger=self.logger())
            os.remove(os.path.join(base_path, 'bodyfile.csv'))

            with open(os.path.join(base_path, 'tree.csv'), 'w') as fout:
                run_command([ntdsxtract, ntds_file, 'tree', '-q'], fout, stderr=subprocess.DEVNULL, logger=self.logger())

            with open(os.path.join(base_path, 'users.json'), 'w') as fout:
                for line in yield_command([ntdsxtract, ntds_file, 'user', '-F', 'json-lines'], stderr=subprocess.DEVNULL, logger=self.logger()):
                    fout.write(self.change_date_format(line))
            with open(os.path.join(base_path, 'groups.json'), 'w') as fout:
                for line in yield_command([ntdsxtract, ntds_file, 'group', '-F', 'json-lines'], stderr=subprocess.DEVNULL, logger=self.logger()):
                    fout.write(self.change_date_format(line))
            with open(os.path.join(base_path, 'computers.json'), 'w') as fout:
                for line in yield_command([ntdsxtract, ntds_file, 'computer', '-F', 'json-lines'], stderr=subprocess.DEVNULL, logger=self.logger()):
                    fout.write(self.change_date_format(line))
        except Exception:
            self.logger().error("Problems parsing {base_path} file")
        return []

    def change_date_format(self, data):
        data = json.loads(data)
        regex = re.compile(r"(\d\d)-(\d\d)-(\d{4})T([\d:]+)\+0000")
        for dte in data.keys():
            if dte in ("record_time", "when_created", "when_changed", "last_logon", "last_logon_time_stamp", "account_expires", "password_last_set", "bad_pwd_time"):
                if not data[dte]:
                    continue
                aux = regex.match(data.get(dte, ''))
                if aux:
                    data[dte] = f"{aux.group(3)}-{aux.group(2)}-{aux.group(1)} {aux.group(4)}Z"
        return json.dumps(data, escape_forward_slashes=False)
