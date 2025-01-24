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

import subprocess
import os
from base.utils import check_directory
import base.job


class Volatility(base.job.BaseModule):

    def run(self, path=""):
        """ Use volatility to get information of a memory image file,
            such as the physical memory of a device as retrieved by F-Response

        Parameters:
            path: the path to the image
        """

        outdir = self.myconfig('outdir')
        self.volatility = self.myconfig('volatility')
        plugins = self.myconfig('volatility_plugins').split()
        imagedir = self.myconfig('imagedir')
        # path = None
        if os.path.isdir(imagedir):
            for fname in os.listdir(imagedir):
                if fname.startswith(self.myconfig('source')):
                    path = os.path.join(imagedir, fname)

        check_directory(outdir, create=True)
        self.volatility = self.config.get('plugins.common', 'volatility', '/usr/local/bin/vol.py')

        if not path:
            mntdir = os.path.join(self.myconfig('sourcedir'), 'mnt')
            for p in os.listdir(mntdir):
                for fname in os.listdir(os.path.join(mntdir, p)):
                    if fname == 'PhysicalMemory.mem':
                        path = os.path.join(mntdir, p, fname)
                        break
            if not path:
                raise base.job.RVTError('No path to a memory image provided. Please, specify the path as the argument to the job')
        elif not os.path.exists(path):
            raise base.job.RVTError('Provided path {} does not exist. Please, use an actual memory image file as argument')

        for plugin in plugins:
            with open(os.path.join(outdir, f'{plugin}.txt'), 'w') as f_out:
                f_out.write(self.volatility_results(path, plugin))

        return []

    def volatility_results(self, path, plugin):
        """ Returns output """

        try:
            output = subprocess.run([self.volatility, "-q", "-f", path, plugin], capture_output=True)
            return output.stdout.decode()
        except Exception:
            self.logger().error(f"Error with plugin {plugin}")
            return []
