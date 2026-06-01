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
import csv
import base.job
from plugins.common.RVT_files import GetFiles
from base.utils import check_folder
from plugins.external.apollo import apollo


class KnowledgeC(base.job.BaseModule):

    def run(self, path=""):
        if not os.path.isdir(self.myconfig('mountdir')):
            raise base.job.RVTError(f"Folder {self.myconfig('mountdir')} not exists")

        search = GetFiles(self.config)
        knowledgec = search.search("/knowledgec.db$")

        knowledgec_path = self.myconfig('outdir')
        check_folder(knowledgec_path)

        for k in knowledgec:
            self.logger().info(f"Processing file {k}")

            if k.find('/Users/') < 0:
                prefix = "private"
            else:
                aux = re.search("/Users/([^/]+)", k)
                prefix = aux.group(1)

            db_path = os.path.join(self.myconfig("casedir"), k)

            streams_file = os.path.join(knowledgec_path, f"{prefix}_streams.txt")
            with open(streams_file, "w") as f:
                for stream in apollo.list_streams(db_path):
                    f.write(f"{stream}\n")

            for module, columns, rows_or_exc in apollo.run_all(db_path):
                if isinstance(rows_or_exc, Exception):
                    self.logger().error(f"Module {module.name} failed on {k}: {rows_or_exc}")
                    continue

                out_file = os.path.join(knowledgec_path, f"{prefix}_{module.name}.csv")
                with open(out_file, "w", newline="") as f:
                    writer = csv.writer(f, delimiter="|", quotechar='"')
                    writer.writerow(columns)
                    writer.writerows(rows_or_exc)
                self.logger().info(f"Written {out_file}")

        self.logger().info("Done parsing KnowledgeC")
        return []
