# Copyright (C) DEFION.
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
import tempfile

from base.utils import check_directory
from base.commands import run_command

import base.job


class Clamav(base.job.BaseModule):
    """
    Scans files using clamav

    Configuration:
        - **clamdscan**: Path to the clamdscan
        - **onlyexe**: Scan only exe files
        - **user_folder**: Scan only files under user folders
        - **system**: Scan only files in Windows, Program Files, ProgramData and Perflogs folders
    """

    def read_config(self):
        super().read_config()
        self.set_default_config('clamdscan', '/usr/bin/clamdscan')
        self.set_default_config('onlyexe', False)
        self.set_default_config('user_folder', False)
        self.set_default_config('system', False)

    def run(self, path=None):
        """ The path is the absolute path to the imagefile or device. If not provided, search in imagedir for known extensions """
        self.clamdscan = self.myconfig('clamdscan')
        self.onlyexe = self.myconfig('onlyexe')
        self.user_folder = self.myconfig('user_folder')
        self.system = self.myconfig('system')

        # Prepare output directory
        self.outpath = self.myconfig('outdir')
        check_directory(self.outpath, create=True)

        all_folders = True

        if not self.user_folder and not self.system:
            self.logger().debug("Clamav will scan all directories")
        if self.user_folder:
            self.logger().debug("Clamav will scan Users directory")
            all_folders = False
        if self.system:
            self.logger().debug("Clamav will scan Windows, Program Files, ProgramData and Perflogs directories")
            all_folders = False
        if self.onlyexe:
            self.logger().debug("Only exe files will be scanned")

        self.logger().debug('Updating databases')
        run_command([self.clamdscan, '--reload'])

        if os.path.exists(os.path.join(self.outpath, 'clamav_results.txt')):
            os.remove(os.path.join(self.outpath, 'clamav_results.txt'))

        if not self.onlyexe:
            if all_folders:
                with open(os.path.join(self.outpath, 'clamav_results.txt'), 'a') as f_in:
                    f_in.write(f"\n*** Scanning {path} ***\n")
                try:
                    run_command([self.clamdscan, '--fdpass', '-l', os.path.join(self.outpath, 'clamav_results.txt'), path])
                except Exception:
                    self.logger().warning(f"Problems scanning {path}")
            if self.user_folder and not all_folders:
                for folder in os.listdir(path):
                    user_path = os.path.join(path, folder, 'Users')
                    if os.path.exists(user_path):
                        with open(os.path.join(self.outpath, 'clamav_results.txt'), 'a') as f_in:
                            f_in.write(f"\n*** Scanning {os.path.join(path, folder, 'Users')} ***\n")
                        try:
                            run_command([self.clamdscan, '--fdpass', '-l', os.path.join(self.outpath, 'clamav_results.txt'), user_path])
                        except Exception:
                            self.logger().warning(f"Problems scanning {user_path}")
            if self.system and not all_folders:
                s = ('windows', 'program files', 'program files (x64)', 'programdata', 'perflogs')
                for folder in os.listdir(path):
                    for sf in os.listdir(os.path.join(path, folder)):
                        if sf.lower() in s:
                            with open(os.path.join(self.outpath, 'clamav_results.txt'), 'a') as f_in:
                                f_in.write(f"\n*** Scanning {os.path.join(path, folder, sf)} ***\n")
                            try:
                                run_command([self.clamdscan, '--fdpass', '-l', os.path.join(self.outpath, 'clamav_results.txt'), os.path.join(path, folder, sf)])
                            except Exception:
                                self.logger().warning(f"Problems scanning {os.path.join(path, folder, sf)}")
        else:
            if all_folders:
                regex = re.compile("\.exe$", re.I)
            elif self.user_folder and not self.system:
                regex = re.compile("/p\d+/Users/.*\.exe$", re.I)
            elif self.system and not self.user_folder:
                regex = re.compile("/p\d+/(Windows|Perflogs|ProgramdData|Program Files|Program Files .x64.)/.*\.exe$", re.I)
            else:
                regex = re.compile("/p\d+/(Users|Windows|Perflogs|ProgramdData|Program Files|Program Files .x64.)/.*\.exe$", re.I)
            with tempfile.NamedTemporaryFile() as tmp:
                with open(tmp.name, 'w') as fout:
                    with open(os.path.join(self.myconfig('outputdir'), 'auxdir', 'alloc_files.txt'), 'r') as f_in:
                        for line in f_in:
                            if regex.search(line):
                                fout.write(f"{os.path.join(self.myconfig('casedir'), line)}")
                try:
                    run_command([self.clamdscan, '--fdpass', '-l', os.path.join(self.outpath, 'clamav_results.txt'), '-i', '-f', tmp.name])
                except Exception:
                    self.logger().warning("Problems scanning exe files")

        self.logger().debug("Clamav scan done!")
        return []
