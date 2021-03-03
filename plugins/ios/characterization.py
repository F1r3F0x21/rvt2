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

import os
import sqlite3
import csv
import biplist
import datetime
import json

import base.job
import base.utils


class Characterization(base.job.BaseModule):
    """
    A module that parses the Manifest.plist to characterize the iPhone.

    The path is an unbacked iPhone backup. See job plugins.ios.unback.Unback

    Configuration:
        - **outfile**: Characterization is writen to this file.
    """

    def read_config(self):
        super().read_config()
        self.set_default_config('outfile', os.path.join(self.myconfig('analysisdir'), 'characterize.csv'))
        self.set_default_config('outfile_json', os.path.join(self.myconfig('analysisdir'), 'os_info.json'))

    def run(self, path):
        """
        Parameters:
            path (str): The path to the directory where the backup was unbacked.

        Returns:
            An array of a dictionary with the extracted documentation
        """
        self.logger().debug('Parsing: %s', path)
        self.check_params(path, check_path=True, check_path_exists=True)

        if not base.utils.check_file(os.path.join(path, 'Manifest.plist')):
            raise base.job.RVTError('Manifest.plist not found. Is the source a (decrypted) iOS backup?')

        ios_conf_files = {
            'Manifest.plist': self.parse_manifest,
            'Info.plist': self.parse_info,
            'Status.plist': self.parse_status,
            'RootDomain/Library/Preferences/com.apple.MobileBackup.plist': self.parse_mobile_backup,
            'HomeDomain/Library/Preferences/com.apple.mobile.ldbackup.plist': self.parse_ldbackup,
            'HomeDomain/Library/Accounts/Accounts3.sqlite': self.parse_accounts
        }

        data = dict()
        self.lockdown = False
        self.path = path

        for file, parsing_function in ios_conf_files.items():
            try:
                base.utils.check_file(os.path.join(path, 'Manifest.plist'), error_missing=True)
                parsing_function(data)
            except Exception:
                pass

        # Write the output on a json and a csv file
        base.utils.check_file(self.myconfig('outfile'), delete_exists=True, create_parent=True)
        base.utils.check_file(self.myconfig('outfile_json'), delete_exists=True)
        with open(self.myconfig('outfile'), "w") as outfile_csv:
            writer = csv.writer(outfile_csv)
            writer.writerow(("Characteristic", "Value"))
            for k, v in data.items():
                writer.writerow([k, v])
        with open(self.myconfig('outfile_json'), 'w') as outfile_json:
            json.dump(data, outfile_json, indent=4)

        self.logger().info("iPhone's characterization exported at %s", self.myconfig('outfile'))

        return [data]

    def parse_manifest(self, data):
        manifest = biplist.readPlist(os.path.join(self.path, 'Manifest.plist'))
        data['Version'] = manifest.get('Version', 'None')
        data['IsEncrypted'] = manifest.get('IsEncrypted', 'None')
        data['LastBackupDate_Manifest.plist'] = str(manifest.get('Date', 'None'))
        if 'Lockdown' in manifest:
            self.lockdown = True
            data['DeviceName'] = manifest['Lockdown'].get('DeviceName', 'None')
            data['UniqueDeviceID'] = manifest['Lockdown'].get('UniqueDeviceID', 'None')
            data['SerialNumber'] = manifest['Lockdown'].get('SerialNumber', 'None')
            data['ProductVersion'] = manifest['Lockdown'].get('ProductVersion', 'None')
            data['ProductType'] = manifest['Lockdown'].get('ProductType', 'None')
            data['BuildVersion'] = manifest['Lockdown'].get('BuildVersion', 'None')
        data['WasPasscodeSet'] = manifest.get('WasPasscodeSet', 'None')

    def parse_info(self, data):
        info = biplist.readPlist(os.path.join(self.path, 'Info.plist'))
        data['GUID'] = info.get('GUID', 'None')
        data['ICCID'] = info.get('ICCID', 'None')
        data['IMEI'] = info.get('IMEI', 'None')
        data['MEID'] = info.get('MEID', 'None')
        data['PhoneNumber'] = info.get('Phone Number', 'None')
        data['ProductName'] = info.get('Product Name', 'None')
        data['macOSVersion'] = info.get('macOS Version', 'None')
        data['macOS Build Version'] = info.get('macOS Build Version', 'None')
        data['LastBackupDate_Info.plist'] = str(info.get('Last Backup Date', 'None'))
        # check some data, they must be the same as the one in Manifest.plist
        if self.lockdown:
            assert data['UniqueDeviceID'].lower() == info['Target Identifier'].lower()
            assert data['DeviceName'] == info['Device Name']
            assert data['DeviceName'] == info['Display Name']
            assert data['SerialNumber'] == info['Serial Number']
            assert data['ProductVersion'] == info['Product Version']
            assert data['ProductType'] == info['Product Type']
            assert data['BuildVersion'] == info['Build Version']

    def parse_status(self, data):
        status = biplist.readPlist(os.path.join(self.path, 'Status.plist'))
        data['UUID'] = status['UUID']
        data['BackupDate_Status.plist'] = str(status.get('Date', 'None'))

    def parse_mobile_backup(self, data):
        mobileBackup = biplist.readPlist(os.path.join(self.path, 'RootDomain/Library/Preferences/com.apple.MobileBackup.plist'))
        data['AccountEnabledDate'] = mobileBackup.get('AccountEnabledDate', 'None')
        if 'BackupStateInfo' in mobileBackup:
            data['BackupStateInfoIscloud'] = mobileBackup['BackupStateInfo'].get('isCloud', 'None')
            data['BackupStateInfoDate'] = mobileBackup['BackupStateInfo'].get('date', 'None')
        if 'RestoreInfo' in mobileBackup:
            data['RestoreDate'] = mobileBackup['RestoreInfo'].get('RestoreDate', 'None')
            data['WasCloudRestore'] = mobileBackup['RestoreInfo'].get('WasCloudRestore', 'None')
            data['BackupBuildVersion'] = mobileBackup['RestoreInfo'].get('BackupBuildVersion', 'None')
            data['DeviceBuildVersion'] = mobileBackup['RestoreInfo'].get('DeviceBuildVersion', 'None')

    def parse_ldbackup(self, data):
        ldBackup = biplist.readPlist(os.path.join(self.path, 'HomeDomain/Library/Preferences/com.apple.mobile.ldbackup.plist'))
        macOSFormatDate = ldBackup.get('LastiTunesBackupDate', None)
        if macOSFormatDate:
            data['LastiTunesBackupDate'] = datetime.datetime.utcfromtimestamp(int(macOSFormatDate) + 978307200).strftime("%Y-%m-%d %H:%M:%S")
        data['LastiTunesBackupTZ'] = ldBackup.get('LastiTunesBackupTZ', 'None')
        data['RequiresEncryption'] = str(ldBackup.get('RequiresEncryption', '')) or str(ldBackup.get('WillEncrypt', '')) or 'Undefined'

    def parse_accounts(self, data):
        conn = sqlite3.connect('file://{}/HomeDomain/Library/Accounts/Accounts3.sqlite?mode=ro'.format(self.path), uri=True)
        c = conn.cursor()
        query = """
            SELECT a.ZACCOUNTTYPEDESCRIPTION, a.ZCREDENTIALTYPE,
            c.ZACCOUNTDESCRIPTION, c.ZUSERNAME, c.ZACCOUNTTYPE,
            DATETIME(ZDATE+978307200, 'unixepoch')
            FROM ZACCOUNT c JOIN ZACCOUNTTYPE a ON c.ZACCOUNTTYPE == a.Z_PK;
        """

        for row in c.execute(query):
            if row[3] is not None:
                account = ' '.join([row[0], 'Account'])
                if row[2]:
                    account = ' - '.join([account, row[2]])
                user_and_date = ' - '.join([row[3], row[5]])
                data[account] = user_and_date

                # Outdated references:
                # switcher = {
                #     33: "iCloud Account",
                #     27: "Hotmail Account",
                #     38: "Jabber Account",
                #     16: "Gmail Account",
                #     13: "Yahoo Account",
                #     11: "Facebook Account",
                #     10: "LinkedIn Account",
                #     4: "Twitter Account",
                #     8: "Flickr Account",
                # }

    def get_property(self, property):
        os_info_json = self.myconfig('outfile_json')
        if os.path.exists(os_info_json) and os.path.getsize(os_info_json) > 0:
            with open(os_info_json, 'r') as infile:
                info = json.load(infile)
                return info.get(property, '')
        return ''


class LoadApolloVersion(base.job.BaseModule):
    def run(self, path=None):
        version = Characterization(self.config).get_property('Version').split('.')[0]
        conf_file = os.path.join(self.config.config['ios']['plugindir'], 'apollo', 'rvt2-ios-{}.ini'.format(version))
        if os.path.exists(conf_file):
            self.config.read(conf_file)
        return []
