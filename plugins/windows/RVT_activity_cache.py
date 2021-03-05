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
from base.utils import save_csv, relative_path, check_directory
from base.commands import run_command
from plugins.common.RVT_files import GetFiles


class ActivitiesCache(base.job.BaseModule):

    def run(self, path=""):
        """ Parses activitiesCache.db
        """

        # Known folder GUIDs
        # "https://docs.microsoft.com/en-us/dotnet/framework/winforms/controls/known-folder-guids-for-file-dialog-custom-places"
        # Duration or totalEngagementTime += e.EndTime.Value.Ticks - e.StartTime.Ticks)
        # https://docs.microsoft.com/en-us/uwp/api/windows.applicationmodel.useractivities
        # StartTime: The start time for the UserActivity
        # EndTime: The time when the user stopped engaging with the UserActivity

        self.check_params(path, check_path=True, check_path_exists=True)
        base_path = self.myconfig('outdir')
        check_directory(base_path, create=True)

        # Load query
        query_file = self.myconfig('query_file')
        with open(query_file, 'r') as qf:
            query = qf.read()

        # Query db and create csv
        rel_path = relative_path(os.path.abspath(path), self.myconfig('casedir'))
        self.logger().debug("Parsing Activities Cache file {}".format(rel_path))
        module = base.job.load_module(self.config, 'base.input.SQLiteReader', extra_config=dict(query=query))
        outfile = os.path.join(base_path, 'activitycache_{}_{}.csv'.format(rel_path.split('/')[-2], rel_path.split('/')[2]))
        save_csv(module.run(path), outfile=outfile, file_exists='OVERWRITE', quoting=1)

        return []


class ActivitiesCacheOld(base.job.BaseModule):

    def run(self, path=""):
        """ Parses activities cache

        """

        self.search = GetFiles(self.config, vss=self.myflag("vss"))
        self.logger().debug("Parsing Activities Cache files")

        base_path = self.myconfig('outdir')
        check_directory(base_path, create=True)

        activities = self.search.search("/ConnectedDevicesPlatform/.*/ActivitiesCache.db$")

        activities_cache_parser = self.myconfig('activities_cache_parser', os.path.join(self.myconfig('rvthome'), '.venv/bin/winactivities2json.py'))
        python3 = self.myconfig('python3', os.path.join(self.myconfig('rvthome'), '.venv/bin/python3'))

        for act in activities:
            with open(os.path.join(base_path, '{}_activitycache_{}.json'.format(act.split('/')[2], act.split('/')[-2])), 'w') as out_file:
                run_command([python3, activities_cache_parser, '-s', act], from_dir=self.myconfig('casedir'), stdout=out_file)
        return []
