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
import sys

import base.job
from base.utils import check_directory, check_file, get_filehash, relative_path


class CrypnetUrlCache(base.job.BaseModule):

    def run(self, path=""):
        """ Extracts CrypnetUrlCache artifacts of a disk """

        cryptnet_path = os.path.join(self.myconfig('rvthome'), "plugins/external/CryptnetURLCacheParser")
        sys.path.insert(1, cryptnet_path)
        import CryptnetUrlCacheParser as crypnetUrlCache

        out_folder = self.myconfig('outdir')
        check_directory(out_folder, create=True)

        metadata_path = None
        content_path = None

        for dirn in os.listdir(path):
            if dirn.lower() == 'metadata':
                metadata_path = os.path.join(path, dirn)
            elif dirn.lower() == 'content':
                content_path =  os.path.join(path, dirn)

        for filename in os.listdir(metadata_path):
            res = crypnetUrlCache.CertutilCacheParser(os.path.join(metadata_path, filename)).Parse(useContent=False)
            if res:
                fname = os.path.join(content_path, filename)
                if os.path.isfile(fname):
                    res['SHA256'] = get_filehash(fname)
                fname = base.utils.relative_path(res['FullPath'], self.myconfig('casedir'))
                res['path'] = fname
                yield res
