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

# Main reference: File System Forensic Analysis by Brian Carrier, tables 13.12 to 13.17
# Based on https://github.com/williballenthin/INDXParse/blob/master

from dissect.thumbcache.thumbcache_file import ThumbcacheFile
import os
import re

import base.job
from base.utils import check_folder


class Thumbcache(base.job.BaseModule):
    """ Parse Thumbcache.

    """

    def run(self, path=""):
        """ Generator of thumb files from thumbcache """

        outdir = self.myconfig('outdir')
        user = re.search("/Users/([^/]+)", path).group(1)

        check_folder(outdir)

        for fname in os.listdir(path):
            if not (fname.startswith('icon') or fname.startswith('thumb')) or fname.find('idx') > -1 or os.path.getsize(os.path.join(path, fname)) == 0:
                continue
            kind = fname.split('_')[0]
            with open(os.path.join(path, fname), "rb") as file:
                try:
                    cache_file = ThumbcacheFile(file)

                    for entry in cache_file.entries():
                        output_file = os.path.join(outdir, f"{kind}_{user}_{entry.hash}_{entry.identifier}_{fname.split('_')[1][:-3]}.bmp")
                        os.makedirs(outdir, exist_ok=True)
                        with open(output_file, "wb") as output:
                            output.write(entry.data)
                        yield {'type': kind, 'user': user, 'hash': entry.hash, 'data_checksum': entry.data_checksum.hex(), 'header_checksum': entry.header_checksum.hex(), 'identifier': entry.identifier}
                except Exception:
                    self.logger().error("Problems parsing %s", os.path.join(path, fname))
