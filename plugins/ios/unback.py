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

"""
This file gets the backup from the variable path and 'unbacks' it in the desired extract_path
"""

import shutil
import sqlite3
import os
import os.path
import subprocess
from tqdm import tqdm

import zipfile
import base.job
import plugins.ios
import base.utils


class Unback(plugins.ios.IOSModule):
    """
    Unback an iOS backup directory or zip file containing an iOS backup.

    In case of encrypted backups, an external unback command must be provided.


    Configuration:
        - **unzip_path**: If needed, unzip the source to this path before unbacking.
        - **extract_path**: Extract the backup into this path.
        - **unback_cmd**: If exists, use this external command to unback.
          It is a Python string template that receives variables "bk_path" and "extract_path".
          An external command might be useful to unback encrypted backups.
          For example, check https://github.com/dinosec/iphone-dataprotection/blob/master/python_scripts/backup_tool.py
        - **remove_unzip_path**: If set to True (default), delete the unzip directory after unzipping the backup zip file
    """

    def read_config(self):
        super().read_config()
        self.set_default_config('unzip_path', os.path.join(self.myconfig('sourcedir'), 'unzip'))
        self.set_default_config('extract_path', os.path.join(self.myconfig('sourcedir'), 'mnt', 'p01'))
        self.set_default_config('remove_unzip_path', 'True')
        self.set_default_config('unback_cmd', '')

    def _get_backup_directory(self, path):
        """ Try to guess the iOS backup directory.

        - If the path is a directory and it includes a file Info.plist, assume it is a backup directory
        - If the path is a zip file and the directory does not exist yet, extract the zip into unzip_path
        and check for the file Info.plist

        Parameters:
            path (str): A path to an extracted backup directory, or a zip including an iOS backup

        Returns:
            An absolute path where the unzipped backup is located.

        Raises:
            base.job.RVTError if the file can't be unbacked, for whatever reason
        """

        if zipfile.is_zipfile(path):
            # if the path is a zip file, extract the zip into extract_path and check for Info.plist
            try:
                unzip_path = self.myconfig('unzip_path')
                base.utils.check_directory(unzip_path, create=True, delete_exists=False)

                with zipfile.ZipFile(path, 'r') as myzip:
                    bkid = myzip.namelist()[0]

                    self.logger().debug(f'Extracting file {path} to {unzip_path}')
                    if not base.utils.check_directory(os.path.join(unzip_path, bkid)):
                        for zn in tqdm(myzip.namelist(), desc='Unzip backup', disable=self.myflag('progress.disable')):
                            myzip.extract(zn, unzip_path)
                    else:
                        # if the directory already exist, skip
                        self.logger().warning(f'The unzip directory already exists: {os.path.join(unzip_path, bkid)}. Won\'t unzip')

                if base.utils.check_file(os.path.join(unzip_path, bkid, 'Info.plist')):
                    return os.path.abspath(os.path.join(unzip_path, bkid))

                # notice this line is not reached if Info.plist exists
                shutil.rmtree(unzip_path)
                raise base.job.RVTError(f'The zip file {unzip_path} doesn\'t seem a compressed iOS backup')
            except Exception as exc:
                self.logger().warning(f'Cannot read zip file: {exc}')

        elif base.utils.check_directory(path) and base.utils.check_file(os.path.join(path, 'Info.plist')):
            # if the path is a directory and it includes Info.plist, assume it is a backup directory
            return os.path.abspath(path)

        raise base.job.RVTError(f'The path {path} doesn\'t seem to contain an iOS backup')

    def run(self, path):
        """ Unpacks a directory

        Parameters:
            path (str): The path to a backup directory or zip file

        Returns:
            An empty array, always.

        Raises:
            base.job.RVTError if the file can't be unbacked, for whatever reason
        """
        self.check_params(path, check_path=True, check_path_exists=True)
        self.logger().debug(f'Unback: {path}')
        # check unzip path
        if base.utils.check_directory(self.myconfig('unzip_path')):
            try:
                shutil.rmtree(self.myconfig('unzip_path'))
            except PermissionError:
                self.logger().warning(f'Can\'t remove: {self.myconfig("unzip_path")}. I will try to continue')
            except OSError:
                # for example: directory is busy
                self.logger().warning(f'Can\'t remove: {self.myconfig("unzip_path")}. I will try to continue')
        extract_path = self.myconfig('extract_path')

        # create the extract_path directory, if it does not exist
        base.utils.check_directory(extract_path, create=True, delete_exists=True)
        self.logger().debug(f'Extracting to: {extract_path}')
        # get the path where the uncompressed backup is
        bk_path = self._get_backup_directory(path)
        self.logger().debug(f'Backup directory: {bk_path}')

        unback_cmd = self.myconfig('unback_command')
        if unback_cmd:
            # if an unback command is provided and the extract_path does not exist, use it
            unback_cmd = unback_cmd.format(bk_path=bk_path, extract_path=extract_path)
            self.logger().debug(f'Running {unback_cmd}')
            subprocess.call(unback_cmd, shell=True)
            # finally, copy some important files
            shutil.copy2(os.path.join(bk_path, 'Info.plist'), os.path.join(extract_path, 'Info.plist'))
            shutil.copy2(os.path.join(bk_path, 'Status.plist'), os.path.join(extract_path, 'Status.plist'))
        elif os.path.exists(os.path.join(bk_path, 'Manifest.db')) and open(os.path.join(bk_path, 'Manifest.db'), 'rb').read(4) == b'SQLi':
            # try to do our own unback by querying the database
            database = self.database(bk_path)
            with sqlite3.connect(f'file://{bk_path}/{database}?mode=ro', uri=True) as conn:
                c = conn.cursor()
                total_iterations = c.execute('SELECT count(*) FROM Files').fetchone()[0]
                for row in tqdm(c.execute('SELECT * FROM Files ORDER BY flags DESC'), total=total_iterations, desc='Unbacking', disable=self.myflag('progress.disable')):
                    # copy files using their real names
                    if row[3] == 2:
                        # directories
                        os.makedirs(os.path.join(extract_path, row[1], row[2]), exist_ok=True)
                    elif row[3] == 1:
                        # files
                        shutil.copy2(os.path.join(bk_path, row[0][:2], row[0]), os.path.join(extract_path, row[1], row[2]))
            # finally, copy some important files
            shutil.copy2(os.path.join(bk_path, database), os.path.join(extract_path, database))
            shutil.copy2(os.path.join(bk_path, 'Info.plist'), os.path.join(extract_path, 'Info.plist'))
            shutil.copy2(os.path.join(bk_path, 'Manifest.plist'), os.path.join(extract_path, 'Manifest.plist'))
            shutil.copy2(os.path.join(bk_path, 'Status.plist'), os.path.join(extract_path, 'Status.plist'))

        # finally, if the unzip path exists, remove it
        if self.myflag('remove_unzip_path') and base.utils.check_directory(self.myconfig('unzip_path')):
            try:
                shutil.rmtree(self.myconfig('unzip_path'))
            except PermissionError:
                self.logger().warning(f'Can\'t remove: {self.myconfig("unzip_path")}')
            except OSError:
                # for example: directory is busy
                self.logger().warning(f'Can\'t remove: {self.myconfig("unzip_path")}')

        return []
