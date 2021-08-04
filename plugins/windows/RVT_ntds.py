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
import tempfile
import shutil
import base.job
from base.utils import check_directory
from base.commands import run_command, yield_command


class Parse(base.job.BaseModule):

    def run(self, path=""):
        """ Parses NTDS.dit
        """

        # https://github.com/csababarta/ntdsxtract

        self.check_params(path, check_path=True, check_path_exists=True)
        base_path = self.myconfig('outdir')
        tl_parser = self.myconfig('timeline_parser')
        users_parser = self.myconfig('users_parser')
        check_directory(base_path, create=True)
        esedbexport = self.config.config['plugins.common'].get('esedbexport', 'esedbexport')

        try:
            ntds_dir = tempfile.mkdtemp(suffix="_ntds")
            run_command([esedbexport, "-t", os.path.join(ntds_dir, "db"), path], stderr=subprocess.DEVNULL)
            ntds_dir_export = os.path.join(ntds_dir, "db.export")
            if not os.path.exists(ntds_dir_export):
                raise base.job.RVTError('esedbexport could not create db.export')

            datatable = ''
            linktable = ''
            for archive in os.listdir(ntds_dir_export):
                if archive.startswith('datatable'):
                    datatable = os.path.join(ntds_dir_export, archive)
                elif archive.startswith('link_table'):
                    linktable = os.path.join(ntds_dir_export, archive)

            with open(os.path.join(base_path, 'timeline.csv'), 'w') as fout:
                for line in yield_command(['/usr/bin/python2', tl_parser, datatable, ntds_dir_export, '--csv'], stderr=subprocess.DEVNULL, logger=self.logger()):
                    fout.write(line)

            with open(os.path.join(base_path, 'users.txt'), 'w') as fout:
                for line in yield_command(['/usr/bin/python2', users_parser, datatable, linktable, ntds_dir_export], stderr=subprocess.DEVNULL, logger=self.logger()):
                    fout.write(line)

        finally:
            shutil.rmtree(ntds_dir)
        return []
