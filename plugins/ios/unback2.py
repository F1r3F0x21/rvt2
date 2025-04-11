#!/usr/bin/env python3
#
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

"""
This file gets the backup from the variable path and 'unbacks' it in the desired extract_path
"""

import shutil
from iOSbackup import iOSbackup
import os
import os.path
from tqdm import tqdm

import zipfile
import base.job
import plugins.ios
import base.utils


class Unback2(plugins.ios.IOSModule):
    """
    Unback an iOS backup directory or zip file containing an iOS backup.

    In case of encrypted backups, an external unback command must be provided.


    Configuration:
        - **unzip_path**: If needed, unzip the source to this path before unbacking.
        - **extract_path**: Extract the backup into this path.
        - **password**: backup password
        - **remove_unzip_path**: If set to True (default), delete the unzip directory after unzipping the backup zip file
    """

    def read_config(self):
        super().read_config()
        self.set_default_config('unzip_path', os.path.join(self.myconfig('sourcedir'), 'unzip'))
        self.set_default_config('extract_path', os.path.join(self.myconfig('sourcedir'), 'mnt', 'p01'))
        self.set_default_config('remove_unzip_path', 'True')

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

        password = self.myconfig('password', '1nc1d3pwd2')

        b = iOSbackup(udid=os.path.basename(bk_path), backuproot=self.myconfig('unzip_path'), cleartextpassword=password)
        for dom in b.getDomains():
            b.getFolderDecryptedCopy(includeDomains=dom, targetFolder=extract_path)

        shutil.copy2(os.path.join(bk_path, 'Info.plist'), os.path.join(extract_path, 'Info.plist'))
        shutil.copy2(os.path.join(bk_path, 'Manifest.plist'), os.path.join(extract_path, 'Manifest.plist'))
        shutil.copy2(os.path.join(bk_path, 'Status.plist'), os.path.join(extract_path, 'Status.plist'))
        shutil.copy2(b.manifestDB, os.path.join(extract_path, 'Manifest.db'))  # get decrypted copy of Manifest.db
        os.chmod(os.path.join(extract_path, 'Manifest.db'), 0o640)

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
