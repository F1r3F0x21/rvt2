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
import base.job
from plugins.common.RVT_files import GetFiles
from base.utils import check_folder
from base.commands import run_command


class MacMRU(base.job.BaseModule):

    def run(self, path=""):

        search = GetFiles(self.config)
        users = search.search(r"p\d+(/root)?/Users/[^/]+$")
        mru_path = self.myconfig('outdir')
        check_folder(mru_path)

        parser = os.path.join(self.myconfig('rvthome'), "plugins/external/macMRU/macMRU.py")
        python3 = os.path.join(self.myconfig('rvthome'), '.venv/bin/python3')

        for user in users:
            self.logger().info(f"Extracting MRU info from user {os.path.basename(user)}")
            with open(os.path.join(mru_path, f'{os.path.basename(user)}.txt'), 'w') as f:
                self.logger().debug(f"Generating file {os.path.join(mru_path, f'{os.path.basename(user)}.txt')}")
                run_command([python3, parser, os.path.join(self.myconfig('casedir'), user)], stdout=f)

        self.logger().info("Done parsing MacMRU")
        return []
