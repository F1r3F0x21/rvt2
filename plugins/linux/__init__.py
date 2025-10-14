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


def get_username(path, mount_dir, subfolder=".ssh"):
    """ Get the home username of the file path """

    file_path = path[len(mount_dir):]
    path_components = file_path.split(os.path.sep)
    if "home" in path_components:
        indexof_subfolder = path_components.index(subfolder)
        username = path_components[indexof_subfolder - 1]
    if "root" in path_components:
        username = "root"
    else:
        username = path_components[-2]

    return username
