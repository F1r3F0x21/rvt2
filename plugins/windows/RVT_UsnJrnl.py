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

# based on https://github.com/PoorBillionaire/USN-Journal-Parser

import os
import re
import shlex
import csv

import base.job
from base.utils import check_folder, save_csv
from base.utils import windows_format_path
from base.commands import run_command


class UsnJrnl(base.job.BaseModule):

    def run(self, path=""):
        self.usn_path = self.myconfig('outdir')
        check_folder(self.usn_path)

        if not os.path.exists(path):
            raise base.job.RVTError('UsnJrnl file {} does not exist'.format(path))
        mft_file = path.replace("Extend/$UsnJrnl:$J", 'MFT')
        self.dump(path, mft_file)

        return []

    def dump(self, path, mft_file):
        """ Create output files of UsnJrnl """
        # Check file is not empty
        if os.stat(path).st_size == 0:
            self.logger().warning('UsnJrnl file {} is empty'.format(path))
            return []

        partition = os.path.basename(os.path.dirname(mft_file))

        # Create dump file
        self.logger().debug('Dumping parsed information from {}'.format(path))
        outdir = self.myconfig('outdir')
        tmp_outdir = os.path.join(outdir, 'tmp')

        cmd = self.myconfig('cmd')
        cmd_vars = {'windows_tool': self.myconfig('windows_tool'),
                    'executable': self.myconfig('executable'),
                    'path': path,
                    'outdir': tmp_outdir}
        cmd_args = shlex.split(cmd.format(**cmd_vars))
        cmd_args = shlex.split(cmd_args[0])

        self.logger().debug('Running command: {}'.format(str(cmd_args)))
        run_command(cmd_args)

        cmd2 = self.myconfig('cmd2')
        cmd2_vars = {'windows_tool': self.myconfig('windows_tool'),
                     'executable': self.myconfig('executable'),
                     'outdir': tmp_outdir,
                     'mft_file': mft_file}
        cmd2_args = shlex.split(cmd2.format(**cmd2_vars))
        cmd2_args = shlex.split(cmd2_args[0])

        self.logger().debug('Running command: {}'.format(str(cmd_args)))
        run_command(cmd2_args)

        usnjrnl_csv = ""
        mft_csv = ""
        for fname in os.listdir(tmp_outdir):
            if fname.endswith('MFT_Output.csv'):
                mft_csv = os.path.join(tmp_outdir, fname)
            elif fname.endswith('J_Output.csv'):
                usnjrnl_csv = os.path.join(tmp_outdir, fname)

        usnjrnl_rewind = self.myconfig('usnjrnl_rewind')

        cmd = ['python3', usnjrnl_rewind, '-m', mft_csv, '-u', usnjrnl_csv, tmp_outdir]
        self.logger().debug('Running command: {}'.format(str(cmd)))
        run_command(cmd)

        f_out = open(os.path.join(outdir, f'UsnJrnl_dump_{partition}.csv'), 'w')
        w = csv.writer(f_out, delimiter=";")
        f_out2 = open(os.path.join(outdir, f'UsnJrnl_{partition}.csv'), 'w')
        w2 = csv.writer(f_out2, delimiter=";")
        w.writerow(['Date', 'MFT Entry', 'MFT sequence', 'Parent MFT Entry', 'Parent MFT sequence', 'Filename', 'File Attributes', 'Reason'])
        w2.writerow(['Date', 'Filename', 'Full Path', 'File Attributes', 'Reason', 'MFT Entry', 'Parent MFT Entry'])

        regex = re.compile("(RenameNewName|RenameOldName|FileDelete|FileCreate).Close")

        relativedir = os.path.join(self.myconfig('source'), 'mnt', partition)

        with open(os.path.join(tmp_outdir, 'USNJRNL.fullPaths.csv'), 'r') as f_in:
            reader = csv.reader(f_in, delimiter=",")
            next(reader, None)
            for row in reader:
                w.writerow([row[8], row[2], row[3], row[4], row[5], row[0], row[10], row[9]])
                if regex.search(row[9]):
                    w2.writerow([row[8], row[0], os.path.join(relativedir, row[6].replace('\\', '/')[2:], row[0]), row[10], row[9], row[2], row[4]])
        f_out.close()
        f_out2.close()
        for fname in os.listdir(tmp_outdir):
            os.remove(os.path.join(tmp_outdir, fname))

        return []
