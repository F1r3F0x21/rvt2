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
from plugins.common.RVT_disk import getSourceImage
from base.utils import check_directory
from base.commands import run_command
import base.job


class Timelines(base.job.BaseModule):
    """
    Generates timeline and body files for a disk and its VSS (if set)

    Configuration:
        - **vss**: If True, generate timelines and body files for the VSS, not the main disk (only useful on Windows systems)
        - **fls**: Path to the fls app (TSK)
        - **apfs_fls**: Path to a fls app with APFS support (TSK>?)
        - **mactime**: Path to the mactime app (TSK)
    """

    def read_config(self):
        super().read_config()
        self.set_default_config('mactime', 'mactime')
        self.set_default_config('fls', 'fls')
        self.set_default_config('vss', False)
        self.set_default_config('apfs_fls', 'apfs_fls')

    def run(self, path=None):
        """ The path is the absolute path to the imagefile or device. If not provided, search in imagedir for known extensions """
        vss = self.myflag('vss')
        fls = self.myconfig('fls')
        apfs_fls = self.myconfig('apfs_fls')
        mactime = self.myconfig('mactime')

        disk = getSourceImage(self.myconfig, imagefile=path)

        tl_path = self.myconfig('outdir')
        if vss:
            tl_path = self.myconfig('voutdir')

        check_directory(tl_path, create=True)

        if not vss:
            self.logger().debug("Generating BODY file for %s", disk.disknumber)
            body = os.path.join(tl_path, "{}_BODY.csv".format(disk.disknumber))

            # create the body file
            with open(body, "wb") as f:
                for p in disk.partitions:
                    mountpath = base.utils.relative_path(p.mountpath, self.myconfig('casedir'))

                    if not p.isMountable:
                        continue
                    if not disk.sectorsize:
                        # unkwown sector size
                        run_command([fls, "-s", "0", "-m", mountpath, "-r", "-o", str(p.osects), "-i", "raw", disk.imagefile], stdout=f, logger=self.logger())
                    elif p.filesystem == "NoName":
                        # APFS filesystems are identified as NoName, according to our experience
                        try:
                            run_command([apfs_fls, "-B", str(p.block_number), "-s", "0", "-m", mountpath, "-r", "-o", str(p.osects), "-b", str(disk.sectorsize), "-i", "raw", disk.imagefile], stdout=f, logger=self.logger())
                        except Exception:
                            # sometimes, APFS filesystems report a wrong offset. Try again with offset*8
                            run_command([apfs_fls, "-B", str(p.block_number), "-s", "0", "-m", mountpath, "-r", "-o", str(p.osects * 8), "-b", str(disk.sectorsize), "-i", "raw", disk.imagefile], stdout=f, logger=self.logger())
                    else:
                        # we know the sector size
                        if p.encrypted:
                            run_command([fls, "-s", "0", "-m", mountpath, "-r", "-b", str(disk.sectorsize), p.loop], stdout=f, logger=self.logger())
                        else:
                            run_command([fls, "-s", "0", "-m", mountpath, "-r", "-o", str(p.osects), "-b", str(disk.sectorsize), disk.imagefile], stdout=f, logger=self.logger())

            # create the timeline using mactime
            self.logger().debug("Creating timeline of {}".format(disk.disknumber))
            hsum = os.path.join(tl_path, "%s_hour_sum.csv" % disk.disknumber)
            fcsv = os.path.join(tl_path, "%s_TL.csv" % disk.disknumber)
            with open(fcsv, "wb") as f:
                run_command([mactime, "-b", body, "-m", "-y", "-d", "-i", "hour", hsum], stdout=f, logger=self.logger())
            run_command(['sed', '-i', '1,2d', hsum])  # Delete header because full path is included
        else:
            # generate body and timeline for each VSS in the disk
            for p in disk.partitions:
                for v, dev in p.vss.items():
                    if dev != "":
                        self.logger().debug("Generating BODY file for {}".format(v))
                        body = os.path.join(tl_path, "{}_BODY.csv".format(v))

                        with open(body, "wb") as f:
                            mountpath = base.utils.relative_path(p.mountpath, self.myconfig('casedir'))
                            run_command([fls, "-s", "0", "-m", "%s" % mountpath, "-r", dev], stdout=f, logger=self.logger())

                        self.logger().debug("Creating timeline for {}".format(v))
                        hsum = os.path.join(tl_path, "%s_hour_sum.csv" % v)
                        fcsv = os.path.join(tl_path, "%s_TL.csv" % v)
                        with open(fcsv, "wb") as f:
                            run_command([mactime, "-b", body, "-y", "-d", "-i", "hour", hsum], stdout=f, logger=self.logger())
                        run_command(['sed', '-i', '1,2d', hsum])  # Delete header because full path is included

        self.logger().debug("Timelines generation done!")
        return []


class MFTTimeline(base.job.BaseModule):
    """
    Generates timeline and body files from an $MFT.

    Configuration:
        - **mactime**: Path to the mactime app (TSK)
        - **volume_id**: volume identifier, such as partition number. Ex: 'p03'
        - **mft_tool**: name of the tool used to parse the MFT. Options: `MFTECmd` and `analyzeMFT`
        - **wine_docker**: path to docker instance running wine
        - **executable**: path to executable app to parse timeline
        - **summary**: generate a summary of files by `time_range`
        - **time_range**: time range for buckets to split the timeline in the summary. Options: `hour` and `day`
    """

    # TODO: bindings with docker

    def read_config(self):
        super().read_config()
        self.set_default_config('mactime', 'mactime')
        self.set_default_config('volume_id', 'p01')
        self.set_default_config('summary', True)
        self.set_default_config('time_range', 'hour')
        self.set_default_config('mft_tool', 'MFTECmd')
        self.set_default_config('wine_docker', self.config.config['plugins.common']['wine_docker'])
        self.set_default_config('executable', self.config.config['plugins.common']['mftecmd'])
        # self.set_default_config('wine_docker', os.path.join(self.myconfig('rvthome'), 'somewhere_else', 'wine-docker'))
        # self.set_default_config('executable', os.path.join(self.myconfig('rvthome'), 'somewhere', 'MFTECmd.exe'))

    def run(self, path=""):

        self.check_params(path, check_from_module=False, check_path=True, check_path_exists=True)
        self.path = path
        tl_dir = self.myconfig('outdir')
        check_directory(tl_dir)

        body_filename = "{}_BODY.csv".format(self.myconfig('source'))
        if self.myconfig('mft_tool') == 'MFTECmd':
            executable = self.myconfig('executable') if not self.myconfig('executable').endswith('analyzeMFT.py') else self.config.config['plugins.common']['mftecmd']
            cmd_args = (self.myconfig('wine_docker'), 'wine', self.myconfig('executable'), '-f', self.path, '--body', tl_dir, '--bodyf', body_filename, '--dbl', 'c')
            substitution = 'c:'
        elif self.myconfig('mft_tool') == 'analyzeMFT':
            executable = self.myconfig('executable') if not self.myconfig('executable').endswith('MFTECmd.exe') else self.config.config['plugins.common']['analyzemft']
            cmd_args = (executable, '-f', self.path, '--bodystd', '--bodyfull', '-b', os.path.join(tl_dir, body_filename))
            substitution = ''
        else:
            raise base.job.RVTError('Selected tool for parsing RVT not accepted: {}. Options: "MFTECmd" and "analyzeMFT"'.format(self.myconfig('mft_tool')))

        self.logger().debug('Running MFT with params: {}; {}; {}; {}; {}; {}; {}'.format(path, tl_dir, body_filename, self.myconfig('mft_tool'), executable, self.myconfig('volume_id'), cmd_args))
        self.generate_body(cmd_args)
        self.preceding_path(tl_dir, body_filename, substitution)
        self.timeline_from_body(tl_dir, self.myflag('summary'), self.myconfig('time_range'))
        return []

    def generate_body(self, cmd_args):
        # Generate body file
        self.logger().debug("Generating BODY file for {}".format(self.path))
        run_command(*cmd_args)

    def preceding_path(self, tl_dir, body_filename, substitution='c:'):
        # Modify preceding path
        volume_id = self.myconfig('volume_id')
        cmd = r"sed -i 's@\(\d*|{}\)\(.*\)@\1{}/mnt/{}\2@g' {}".format(substitution, self.myconfig('source'), volume_id, os.path.join(tl_dir, body_filename))
        run_command(cmd)

    def timeline_from_body(self, tl_dir, body_filename, summary=True, time_range='hour'):
        # Generate timeline and hour_sum
        self.logger().debug("Creating timeline for {}".format(self.path))
        fcsv = os.path.join(tl_dir, "%s_TL.csv" % self.myconfig('source'))
        cmd = [self.myconfig('mactime'), "-b", os.path.join(tl_dir, body_filename), "-m", "-y", "-d"]
        if time_range not in ('hour', 'day'):
            raise base.job.RVTError('Selected time range for summary is not allowed: {}. Only "day" and "hour" supported'.format(time_range))
        if summary:
            summary_file = os.path.join(tl_dir, "{}_{}_sum.csv".format(self.myconfig('source'), time_range))
            cmd = [self.myconfig('mactime'), "-b", os.path.join(tl_dir, body_filename), "-y", "-d", "-i", time_range, summary_file]
        with open(fcsv, "wb") as f:
            run_command(cmd, stdout=f, logger=self.logger())
        if summary:
            run_command(['sed', '-i', '1,2d', summary_file])  # Delete header because full path is included
