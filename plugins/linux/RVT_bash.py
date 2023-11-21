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

import base.job
import os
import subprocess, shlex
from . import get_username
from base.utils import check_folder


class BashFilesCp(base.job.BaseModule):
    
    """ Extract the essential information about bash configs.

    Module description:
        - **from_module**: Data dict.
        - **yields**: The updated dict data.
    """

    def read_config(self):
        super().read_config()
        self.set_default_config('bashdir', None)

    def run(self, path=None):
        bash_dir = self.myconfig('bashdir')

        sub_folder = os.path.basename(path)
        if sub_folder.startswith('.'):
            prefix_file = sub_folder[1:]
        prefix_file_ = prefix_file + "_"

        username = get_username(path, mount_dir=self.myconfig('mountdir'),subfolder=sub_folder)
        file_out = os.path.join(bash_dir, prefix_file, prefix_file_+ username + '.txt')

        folder_out = os.path.join(bash_dir, prefix_file)
        check_folder(folder_out)
        
        command = "cp -r " + path + " " + file_out
        args = shlex.split(command)
        process = subprocess.Popen(args,  stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        output = process.stderr.readline().strip()
        if output:
            self.logger().error(output)

class BashHistory(base.job.BaseModule):
    
    """ Extract the essential information about bash history in Bash_History file.

    Module description:
        - **from_module**: Data dict.
        - **yields**: The updated dict data.
    """

    def read_config(self):
        super().read_config()
        self.set_default_config('bashdir', None)

    def run(self, path=None):
        username = get_username(path, mount_dir=self.myconfig('mountdir'),subfolder=".bash_history")
        
        list_commands = []
        for line in self.from_module.run(path):
            if line != "ls" and line != "clear" :
                list_commands.append(line)
        
        yield {username:list_commands}
