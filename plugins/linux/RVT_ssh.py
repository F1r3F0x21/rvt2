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
import re
from sshpubkeys import SSHKey

class Ssh_authorized_keys(base.job.BaseModule):
    
    """ Extract the ssh authorized_keys

    Module description:
        - **from_module**: Data dict.
        - **yields**: The updated dict data.
    """

    def read_config(self):
        super().read_config()
        self.set_default_config('isRoot', None)


    def run(self, path=None):
        self.check_params(path, check_path=True, check_path_exists=True)
        is_Root = self.myconfig('isRoot')


        # get the home username of the current authorized_keys file
        if is_Root == "False":
            path_components = path.split(os.path.sep)
            indexof_ssh = path_components.index(".ssh")
            username = path_components[indexof_ssh -1]
        else:
            username = "root"

        pattern_authorized_keys = r'[\S\s]*ssh-\w+\s(\S*)'
        for line in self.from_module.run(path):
            if line and not line.startswith('#'):
                match = re.match(pattern_authorized_keys, line)
                if match:
                    key = SSHKey(line)
                    key.parse()
                    sshkeys_entry_dict = {
                        "username": username,
                        "key_algorithm": key.key_type,
                        "key_data": match.groups()[0],
                        "key_options": key.options,
                        "key_comment": key.comment,
                        "key_bits": key.bits
                    }
                    yield sshkeys_entry_dict
                else:
                    self.logger().error("Regex pattern failed with some ssh_authorized_keys " + line)


class Ssh_known_hosts(base.job.BaseModule):
    
    """ Extract the ssh known_hosts

    Module description:
        - **from_module**: Data dict.
        - **yields**: The updated dict data.
    """

    def read_config(self):
        super().read_config()

    def run(self, path=None):
        self.check_params(path, check_path=True, check_path_exists=True)

        # get the home username of the current known_hosts file
        path_components = path.split(os.path.sep)
        indexof_ssh = path_components.index(".ssh")
        username = path_components[indexof_ssh -1]
        yield "****************************************"
        yield username
        yield "****************************************"

        for line in self.from_module.run(path):
            #TODO
            yield line