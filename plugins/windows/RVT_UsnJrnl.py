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
import ujson as json
import sqlite3

import base.job
from base.utils import check_folder
from base.commands import run_command


class UsnJrnl(base.job.BaseModule):

    def run(self, path=""):
        self.outdir = self.myconfig('outdir')
        check_folder(self.outdir)
        self.tmp_outdir = os.path.join(self.outdir, 'tmp')
        self.tl_outdir = self.myconfig('timelinesdir')
        check_folder(self.tmp_outdir)
        mft_file = ""

        if not path:
            # parsed_usnjrnl
            file_dict = self.find_velociraptor_usn()
            for filename, self.partition in file_dict.items():
                f_out = open(os.path.join(self.tmp_outdir, 'J_Outfile.csv'), 'w')
                w = csv.writer(f_out, delimiter=",", escapechar='¬')
                with open(filename, 'r') as f_in:
                    line = json.loads(f_in.readline())
                    headers = list(line.keys())[:-1]
                    w.writerow(headers)
                    w.writerow([line[field] for field in headers])
                    for line in f_in:
                        line = json.loads(line)
                        w.writerow([line[field] for field in headers])
                f_out.close()
                mft_file = os.path.join(self.myconfig('mountdir'), self.partition, '$MFT')
                self.generate_mft_csv(mft_file)
                usnjrnl_csv = os.path.join(self.tmp_outdir, "J_Outfile.csv")
                mft_csv = self.find_csv()
                self.dump(usnjrnl_csv, mft_csv)
            return []
        # Imagefile

        mft_file = path.replace("Extend/$UsnJrnl:$J", 'MFT')
        self.generate_mft_csv(mft_file)
        self.generate_usnjrnl_csv(path)
        usnjrnl_csv = self.find_csv(False)
        mft_csv = self.find_csv()

        self.partition = os.path.basename(os.path.dirname(mft_file))
        self.dump(usnjrnl_csv, mft_csv)

        return []

    def generate_mft_csv(self, mft_file):
        """ Creates csv file from MFT """

        cmd2 = self.myconfig('cmd2')
        cmd2_vars = {'windows_tool': self.myconfig('windows_tool'),
                     'executable': self.myconfig('executable'),
                     'outdir': self.tmp_outdir,
                     'mft_file': mft_file}
        cmd2_args = shlex.split(cmd2.format(**cmd2_vars))
        cmd2_args = shlex.split(cmd2_args[0])

        self.logger().debug(f'Running command: {str(cmd2_args)}')
        run_command(cmd2_args)
        return True

    def generate_usnjrnl_csv(self, path):
        """ Creates csv file from UsnJrnl """

        cmd = self.myconfig('cmd')
        cmd_vars = {'windows_tool': self.myconfig('windows_tool'),
                    'executable': self.myconfig('executable'),
                    'path': path,
                    'outdir': self.tmp_outdir}
        cmd_args = shlex.split(cmd.format(**cmd_vars))
        cmd_args = shlex.split(cmd_args[0])

        self.logger().debug(f'Running command: {str(cmd_args)}')
        run_command(cmd_args)
        return True

    def dump(self, usnjrnl_csv, mft_csv):
        """ Create output files of UsnJrnl """
        # Check file is not empty

        usnjrnl_rewind = self.myconfig('usnjrnl_rewind')

        cmd = ['python3', usnjrnl_rewind, '-m', mft_csv, '-u', usnjrnl_csv, self.tmp_outdir]
        self.logger().debug(f'Running command: {str(cmd)}')
        run_command(cmd)
        usn_db = os.path.join(self.tmp_outdir, 'NTFS.sqlite')
        self.fill_mft_orphan(usn_db, mft_csv)

        f_out = open(os.path.join(self.outdir, f'UsnJrnl_dump_{self.partition}.csv'), 'w')
        w = csv.writer(f_out, delimiter=";")
        f_out2 = open(os.path.join(self.outdir, f'UsnJrnl_{self.partition}.csv'), 'w')
        w2 = csv.writer(f_out2, delimiter=";")
        w.writerow(['Date', 'MFT Entry', 'MFT sequence', 'Parent MFT Entry', 'Parent MFT sequence', 'Filename', 'File Attributes', 'Reason'])
        w2.writerow(['Date', 'Filename', 'Full Path', 'File Attributes', 'Reason', 'MFT Entry', 'Parent MFT Entry'])

        regex = re.compile("(RENAMENEWNAME|RENAME_NEW_NAME|RENAMEOLDNAME|RENAME_OLD_NAME|FILEDELETE|FILE_DELETE|FILECREATE|FILE_CREATE).CLOSE")

        relativedir = os.path.join(self.myconfig('source'), 'mnt', self.partition)

        with open(os.path.join(self.tmp_outdir, 'USNJRNL.fullPaths.csv'), 'r') as f_in:
            reader = csv.reader(f_in, delimiter=",")
            next(reader, None)
            for row in reader:
                row[9] = row[9].upper()
                row[10] = row[10].upper()
                w.writerow([row[8], row[2], row[3], row[4], row[5], row[0], row[10], row[9]])
                if regex.search(row[9]):
                    w2.writerow([row[8], row[0], os.path.join(relativedir, row[6].replace('\\', '/')[2:], row[0]), row[10], row[9], row[2], row[4]])
        f_out.close()
        f_out2.close()
        for fname in os.listdir(self.tmp_outdir):
            os.remove(os.path.join(self.tmp_outdir, fname))

        return []

    def find_velociraptor_usn(self):
        """ Find velociraptor json files of parsed usnjrnl and returns list of files and partition """
        source_folder = self.myconfig('sourcedir')

        flows_folder = os.path.join(source_folder, 'flows')
        device = {}
        result = {}

        for fname in os.listdir(source_folder):  # gets a dict with devices and partition associated
            if fname.endswith('.mnt'):
                with open(os.path.join(source_folder, fname), 'r') as f_in:
                    device = json.loads(f_in.readline())
                break
        for fname in os.listdir(flows_folder):  # finds json files with data of UsnJrnl
            if fname.endswith('json'):
                with open(os.path.join(flows_folder, fname), 'r') as f_in:
                    line = json.loads(f_in.readline())
                    if 'ParentSequenceNumber' in line.keys():  # File maches
                        for k in device.keys():
                            if k.endswith(line['Device'][:-1]) and '$MFT' in os.listdir(device[k]):
                                result[os.path.join(flows_folder, fname)] = device[k].split('/')[-1]
                                break
        return result

    def find_csv(self, MFT=True):
        """ csv output files of MFTCmd of UsnJrnl or MFT files """

        if MFT:
            flag = "MFT"
        else:
            flag = "J"

        for fname in os.listdir(self.tmp_outdir):
            if fname.endswith(f'{flag}_Output.csv'):
                return os.path.join(self.tmp_outdir, fname)

    def fill_mft_orphan(self, usn_db, mft_csv):
        """ fills orphan paths with usnjrnl info """

        orphan_mft = []

        # Read mft_csv to get an orphan list
        with open(mft_csv, 'r') as f_in:
            reader = csv.reader(f_in, delimiter=",")
            next(reader, None)
            for row in reader:
                if row[5][2:].startswith("PathUnknown"):
                    orphan_mft.append([int(row[0]), int(row[1]), int(row[3]), int(row[4]), row[5].replace('\\', '/'), row[6]])
        if len(orphan_mft) == 0:
            return []

        # opens db with full paths of journal
        connection = sqlite3.connect(usn_db)
        cursor = connection.cursor()

        f_out = open(os.path.join(self.tl_outdir, f"filled_orphan_{self.partition}.csv"), 'w')
        w = csv.writer(f_out, delimiter=";")
        w.writerow(['EntryNumber', 'SequenceNumber', 'ParentEntryNumber', 'ParentSequenceNumber', 'ParentPath', 'FileName'])
        rows = cursor.execute("SELECT EntryNumber, SequenceNumber, ParentPath FROM USNJRNL_FullPaths").fetchall()
        paths = {}
        for row in rows:
            if row[0] not in paths.keys():
                paths[row[0]] = {}
            paths[row[0]][row[1]] = row[2]
        connection.close()

        for orphan in orphan_mft:
            if orphan[2] in paths.keys() and orphan[3] in paths[orphan[2]].keys():
                w.writerow([orphan[0], orphan[1], orphan[2], orphan[3], paths[orphan[2]][orphan[3]][2:].replace('\\', '/'), orphan[5]])
            else:
                orphan[4] = orphan[4][2:].replace('\\', '/')
                w.writerow(orphan)
        connection.close()
        f_out.close()
