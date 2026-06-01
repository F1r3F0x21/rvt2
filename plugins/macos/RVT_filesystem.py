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
import sqlite3
import base.job
from plugins.external.PythonDsstore import dsstore
from plugins.common.RVT_files import GetFiles
from base.utils import check_folder
from base.commands import run_command


class FSEvents(base.job.BaseModule):

    def run(self, path=""):
        if not os.path.isdir(self.myconfig('mountdir')):
            raise base.job.RVTError(f"Folder {self.myconfig('mountdir')} not exists")

        search = GetFiles(self.config)
        parser = os.path.join(self.myconfig('rvthome'), "plugins/external/FSEventsParser/FSEParser_V4.0.py")
        fsevents = search.search(r"\.fseventsd$")

        fsevents_path = self.myconfig('outdir')
        check_folder(fsevents_path)

        python = self.myconfig('python', '/usr/bin/python')

        n = 1
        for f in fsevents:
            self.logger().info(f"Processing file {f}")
            run_command([python, parser, "-c", f"Report_{f.split('/')[-2]}",
                         "-s", os.path.join(self.myconfig('casedir'), f), "-t", "folder", "-o", fsevents_path,
                         "-q", os.path.join(self.myconfig('rvthome'), "plugins/external/FSEventsParser/report_queries.json")])
            n += 1
        self.logger().info("Done FSEvents")
        return []


class Spotlight(base.job.BaseModule):

    def run(self, path=""):
        if not os.path.isdir(self.myconfig('mountdir')):
            raise base.job.RVTError(f"Folder {self.myconfig('mountdir')} not exists")

        search = GetFiles(self.config)
        parser = os.path.join(self.myconfig('rvthome'), "plugins/external/spotlight_parser/spotlight_parser.py")
        spotlight = search.search(r"/\.spotlight.*/store.db$")

        spotlight_path = self.myconfig('outdir')
        check_folder(spotlight_path)

        # TODO: adapt external spotlight_parser.py script to python3
        python = self.myconfig('python', '/usr/bin/python')

        n = 1
        errorlog = os.path.join(self.myconfig('sourcedir'), f"{self.myconfig('source')}_aux.log")
        with open(errorlog, 'a') as logfile:
            for f in spotlight:
                self.logger().info(f"Processing file {f}")
                run_command([python, parser, os.path.join(self.myconfig('casedir'), f), spotlight_path, "-p", f"spot-{str(n)}"], stdout=logfile, stderr=logfile)
                n += 1
        self.logger().info("Spotlight done")
        return []


class ParseDSStore(base.job.BaseModule):

    def run(self, path=""):
        if not os.path.isdir(self.myconfig('mountdir')):
            raise base.job.RVTError(f"Folder {self.myconfig('mountdir')} not exists")

        search = GetFiles(self.config)
        dsstore_files = search.search(r"/\.ds_store$")

        output1 = os.path.join(self.myconfig('outdir'), "dsstore_dump.txt")
        output2 = os.path.join(self.myconfig('outdir'), "dsstore.txt")

        with open(output1, 'w') as out1:
            filelist = set()
            n_stores = 0
            for dstores in dsstore_files:
                out1.write(f"{dstores}\n-------------------------------\n")
                with open(os.path.join(self.myconfig('casedir'), dstores), "rb") as ds:
                    try:
                        d = dsstore.DS_Store(ds.read(), debug=False)
                        files = d.traverse_root()
                        for f in files:
                            filelist.add(os.path.join(os.path.dirname(dstores), f))
                            out1.write(f"{f}\n")
                    except Exception as exc:
                        self.logger().warning(f"Problems parsing file {dstores}. Error: {exc}")
                n_stores += 1
                out1.write("\n")

        self.logger().info(f"Founded {n_stores} .DS_Store files")

        with open(output2, "w") as out:
            for f in sorted(filelist):
                out.write(f"{f}\n")
        self.logger().info("ParseDSStore Done")
        return []


class Quarantine(base.job.BaseModule):

    def run(self, path=""):
        search = GetFiles(self.config)
        quarantine = search.search("/com.apple.LaunchServices.QuarantineEventsV2$")

        output = os.path.join(self.myconfig('outdir'), "quarantine.txt")

        with open(output, "w") as out:
            for k in quarantine:
                self.logger().info(f"Extracting information of file {k}")
                with sqlite3.connect(f"file://{os.path.join(self.myconfig('casedir'), k)}?mode=ro", uri=True) as conn:
                    conn.text_factory = str
                    c = conn.cursor()

                    out.write(f"{k}\n------------------------------------------\n")
                    query = '''SELECT LSQuarantineEventIdentifier as id, LSQuarantineTimeStamp as ts, LSQuarantineAgentBundleIdentifier as bundle,
LSQuarantineAgentName as agent_name, LSQuarantineDataURLString as data_url,
LSQuarantineSenderName as sender_name, LSQuarantineSenderAddress as sender_add, LSQuarantineTypeNumber as type_num,
LSQuarantineOriginTitle as o_title, LSQuarantineOriginURLString as o_url, LSQuarantineOriginAlias as o_alias
FROM LSQuarantineEvent  ORDER BY ts;'''.replace('\n', ' ')
                    c.execute(query)

                    out.write("\n\nid|ts|bundle|agent_name|data_url|sender_name|sender_add|type_num|o_title|o_url|o_alias\n--|--|--|--|--|--|--|--|--|--|--\n")
                    for i in c.fetchall():
                        out.write(f"{i[0]}|{i[1]}|{i[2]}|{i[3]}|{i[4]}|{i[5]}|{i[6]}|{i[7]}|{i[8]}|{i[9]}|{i[10]}\n")
                    out.write("\n")
                    c.close()

        self.logger().info("Done parsing QuarantineEvents")
        return []
