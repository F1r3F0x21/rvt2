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

# TODO finish script and dump to file
# Linux partitions must be mounted

import base.job
import os
import subprocess, shlex
from . import get_username
from base.utils import save_dummy


class Bashrc(base.job.BaseModule):
    
    """ Extract the essential information about bash configs in Bashrc file.

    Module description:
        - **from_module**: Data dict.
        - **yields**: The updated dict data.
    """

    def read_config(self):
        super().read_config()
        self.set_default_config('bashdir', None)

    def run(self, path=None):
        bash_dir = self.myconfig('bashdir')

        username = get_username(path, mount_dir=self.myconfig('mountdir'),subfolder=".bashrc")
        file_out = os.path.join(bash_dir, "bashrcFile", username + '.txt')

        command = "mkdir -p " + bash_dir + "bashrcFile/"
        args = shlex.split(command)
        subprocess.Popen(args,  stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        command = "cp -r " + path + " " + file_out
        args = shlex.split(command)
        process = subprocess.Popen(args,  stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        output = process.stderr.readline().strip()
        if output:
            self.logger().error(output)

