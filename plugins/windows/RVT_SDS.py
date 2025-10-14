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

# Main reference: File System Forensic Analysis by Brian Carrier, tables 13.12 to 13.17
# Based on https://github.com/williballenthin/INDXParse/blob/master


import os
import re
import ujson as json
from ntfs_sds_parser import PySDSParser

import base.job
from base.utils import check_folder


class SDS(base.job.BaseModule):

    def run(self, path=""):
        self.source_path = self.myconfig('sourcedir')
        self.outdir = self.myconfig('outdir')
        check_folder(self.outdir)

        part_aux = re.search("/mnt/(p\d+)/", path)

        if part_aux:
            self.partition = part_aux.group(1)
        else:
            raise base.job.RVTError(f'$Secure:$SDS file {path} does not exist')
        bodyfile = f"{os.path.join(self.outdir, os.path.basename(self.source_path))}_BODY_{self.partition}.csv"
        if not os.path.exists(bodyfile):
            bodyfile = f"{os.path.join(self.outdir, os.path.basename(self.source_path))}_BODY.csv"
        inodes = {}
        with open(bodyfile, 'r') as body:
            for line in body:
                line = line.split('|')
                inodes[line[2].split('-')[0]] = line[1]
        try:
            parser = PySDSParser(path)

            for entry in parser:
                result = {}
                if not entry.is_error:
                    result = json.loads(entry.to_json())
                    result['path'] = inodes.get(str(result["id"]), '')
                    yield result
        except Exception as e:
            self.logger().error(f"ERROR: {e}")
