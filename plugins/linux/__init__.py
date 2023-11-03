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

import os
import base.job

class LinuxModule(base.job.BaseModule):
    """ A base class for the modules for Linux. """
    def username(self, path):
        mount_dir = self.myconfig('mountdir')

        # get the home username of the current authorized_keys file
        file_path = path[len(mount_dir):]
        path_components = file_path.split(os.path.sep)
        if "home" in path_components:
            indexof_ssh = path_components.index(".ssh")
            username = path_components[indexof_ssh -1]
        else:    
            username = "root"
        return username
