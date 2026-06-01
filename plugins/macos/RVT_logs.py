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
import csv
import base.job
from plugins.external.ccl_asldb import ccl_asldb, OSX_asl_login_timeline
from plugins.common.RVT_files import GetFiles
from base.utils import check_folder
from base.commands import run_command


class ASL(base.job.BaseModule):

    def run(self, path=""):
        if not os.path.isdir(self.myconfig('mountdir')):
            raise base.job.RVTError(f"Folder {self.myconfig('mountdir')} not exists")

        info_path = self.myconfig('outdir')
        check_folder(info_path)
        search = GetFiles(self.config)
        asl_files = list(search.search(r"var/log/asl/.*\.asl$"))

        # asl dump
        with open(os.path.join(info_path, "asldump.csv"), "w") as out_asl:
            writer = csv.writer(out_asl, delimiter="|", quotechar='"')
            headers = ["Timestamp", "Host", "Sender", "PID", "Reference Process", "Reference PID", "Facility", "Level", "Message", "Other details"]
            writer.writerow(headers)
            for file in asl_files:
                self.logger().info(f"Processing: {file}")
                try:
                    f = open(os.path.join(self.myconfig('casedir'), file), "rb")
                except IOError as e:
                    self.logger().error(f"Could not open file '{file}' ({e}): Skipping this file")
                    continue

                try:
                    db = ccl_asldb.AslDb(f)
                except ccl_asldb.AslDbError as e:
                    self.logger().error(f"Could not read file as ASL DB '{file}' ({e}): Skipping this file")
                    f.close()
                    continue

                for record in db:
                    writer.writerow([record.timestamp.isoformat(), record.host, record.sender, str(record.pid), str(record.refproc), str(record.refpid), record.facility, record.level_str, record.message.replace(
                        "\n", " ").replace("\t", "    "), "; ".join(["{0}='{1}'".format(key, record.key_value_dict[key]) for key in record.key_value_dict]).replace("\n", " ").replace("\t", "    ")])
                f.close()

        asl_path = list(set(os.path.dirname(asl) for asl in asl_files))

        for path in asl_path:
            self.logger().info(f"Processing files from folder: {path}")
            OSX_asl_login_timeline.__dowork__((os.path.join(self.myconfig('casedir'), path),), (os.path.join(self.myconfig('outdir'), "login_power.md"),))
        self.logger().info("Done ASL")
        return []


class ParseUnifiedLogReader(base.job.BaseModule):

    def run(self, path=""):
        if not os.path.isdir(self.myconfig('mountdir')):
            raise base.job.RVTError(f"Folder {self.myconfig('mountdir')} not exists")

        search = GetFiles(self.config)
        parser = os.path.join(self.myconfig('rvthome'), "plugins/external/UnifiedLogReader/scripts/UnifiedLogReader.py")
        uuidtext = search.search("/var/db/uuidtext$")
        timesync = search.search("/var/db/diagnostics/timesync$")
        diagnostics = search.search("/var/db/diagnostics$")

        ulr_path = self.myconfig('outdir')
        check_folder(ulr_path)

        if not uuidtext or not timesync or not diagnostics:
            return []

        python3 = '/usr/bin/python3'

        try:
            run_command([python3, parser, os.path.join(self.myconfig('casedir'), uuidtext[0]), os.path.join(self.myconfig('casedir'), timesync[0]), os.path.join(self.myconfig('casedir'), diagnostics[0]), ulr_path, "-l", "WARNING"])
        except Exception as exc:
            self.logger().error(f'Problems with UnifiedLogReader.py. Error: {exc}')
        self.logger().info("Done parsing UnifiedLogReader")
        return []
