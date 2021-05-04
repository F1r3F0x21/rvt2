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
from base.utils import check_directory
from base.commands import yield_command


class UAL(base.job.BaseModule):

    def run(self, path=""):
        """ Parses User Access Logs
        """

        # https://svch0st.medium.com/windows-user-access-logs-ual-9580f1100635
        # https://advisory.kpmg.us/blog/2021/digital-forensics-incident-response.html

        self.check_params(path, check_path=True, check_path_exists=True)
        base_path = self.myconfig('outdir')
        check_directory(base_path, create=True)
        for f_in in os.listdir(path):
            if f_in.lower().endswith('.mdb'):
                self.parse(os.path.join(os.path.abspath(path), f_in), os.path.join(base_path, "%s.md" % f_in.split('.')[0]))

        return []

    def parse(self, f_in, f_out):
        parser = self.myconfig('ual_parser')
        with open(f_out, 'w') as fout:
            for line in yield_command(['/usr/bin/python2', parser, f_in], stderr=subprocess.DEVNULL, logger=self.logger()):
                line = line.replace('||', '|').replace('\x00', '')
                fout.write(line)
