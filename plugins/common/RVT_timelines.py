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
import shlex
from plugins.common.RVT_disk import getSourceImage
from base.utils import check_directory, windows_format_path
from base.commands import run_command
import base.job


class BaseTimeline(base.job.BaseModule):

    def read_config(self):
        super().read_config()
        self.set_default_config('mactime', 'mactime')
        self.set_default_config('fls', 'fls')
        self.set_default_config('apfs_fls', 'apfs_fls')
        self.set_default_config('summary', True)
        self.set_default_config('time_range', 'hour')

    def timeline_from_body(self, tl_dir, body_filename, summary=True, time_range='hour'):
        """ Generate timeline and summary of files by time_range """
        self.logger().debug(f"Creating timeline for {self.myconfig('source')}")
        fcsv = os.path.join(tl_dir, f"{self.myconfig('source')}_TL.csv")
        cmd = [self.myconfig('mactime'), "-b", os.path.join(tl_dir, body_filename), "-m", "-y", "-d"]
        if time_range not in ('hour', 'day'):
            raise base.job.RVTError(f'Selected time range for summary is not allowed: {time_range}. Only "day" and "hour" supported')
        if summary:
            summary_file = os.path.join(tl_dir, f"{self.myconfig('source')}_{time_range}_sum.csv")
            cmd = [self.myconfig('mactime'), "-b", os.path.join(tl_dir, body_filename), "-y", "-d", "-i", time_range, summary_file]
        with open(fcsv, "wb") as f:
            run_command(cmd, stdout=f, logger=self.logger())
        if summary:
            run_command(['sed', '-i', '1,2d', summary_file])  # Delete header because full path is included


class Timelines(BaseTimeline):
    """
    Generates timeline and body files for a disk

    Configuration:
        - **fls**: Path to the fls app (TSK)
        - **apfs_fls**: Path to a fls app with APFS support (TSK>?)
        - **mactime**: Path to the mactime app (TSK)
    """

    def read_config(self):
        super().read_config()

    def run(self, path=None):
        """ The path is the absolute path to the imagefile or device. If not provided, search in imagedir for known extensions """

        self.fls = self.myconfig('fls')
        self.apfs_fls = self.myconfig('apfs_fls')
        self.mactime = self.myconfig('mactime')

        # Prepare output directory
        self.tl_path = self.myconfig('outdir')
        check_directory(self.tl_path, create=True)

        # Generate BODY file
        body_filename = self.generate_body(path=path)

        # create the timeline using mactime
        self.timeline_from_body(self.tl_path, body_filename, self.myflag('summary'), self.myconfig('time_range'))
        self.logger().debug("Timeline generation done!")
        return []

    def generate_body(self, path):
        """ Generate BODY file, taking into account the kind of partition """
        disk = getSourceImage(self.myconfig, imagefile=path)

        self.logger().debug(f"Generating BODY file for {disk.source}")
        body = os.path.join(self.tl_path, f"{disk.source}_BODY.csv")

        # create the body file
        with open(body, "wb") as f:
            if disk.imagetype == "dummy":
                run_command(['find', base.utils.relative_path(os.path.join(self.myconfig('sourcedir'), 'mnt'), self.myconfig('casedir')),
                             "-exec", "stat", "-c", '0|%n|-|%A|0|0|%s|%X|%Y|%Z|%W', '{}', ';'], stdout=f, logger=self.logger())
                return f"{disk.source}_BODY.csv"
            for p in disk.partitions:
                mountpath = base.utils.relative_path(p.mountpath, self.myconfig('casedir'))

                if not p.isMountable:
                    continue
                if p.filesystem == "lvm":
                    for lv in p.lvm_info:
                        vol = lv["logicalVolume"]
                        mountpath = base.utils.relative_path(os.path.join(p.mountdir, f'p{p.partition}l{vol}'), self.myconfig('casedir'))
                        run_command([self.fls, "-s", "0", "-m", mountpath, "-r", os.path.join(p.mountaux, f'lvm{p.partition}', f'lvm{vol}')], stdout=f, logger=self.logger())
                elif not disk.sectorsize:
                    # unkwown sector size
                    if disk.imagetype == "compressed":
                        run_command(['find', mountpath, "-exec", "stat", "-c",
                                     '0|%n|-|%A|0|0|%s|%X|%Y|%Z|%W', '{}', ';'], stdout=f, logger=self.logger())
                    else:
                        run_command([self.fls, "-s", "0", "-m", mountpath, "-r", "-o", str(
                            p.osects), *(("-i", "raw") if disk.imagetype == 'raw' else ()), disk.imagefile], stdout=f, logger=self.logger())
                elif p.filesystem == "NoName":
                    # APFS filesystems are identified as NoName, according to our experience
                    try:
                        run_command([self.apfs_fls, "-B", str(p.block_number), "-s", "0", "-m", mountpath, "-r", "-o", str(
                            p.osects), "-b", str(disk.sectorsize), "-i", "raw", disk.imagefile], stdout=f, logger=self.logger())
                    except Exception:
                        # sometimes, APFS filesystems report a wrong offset. Try again with offset*8
                        run_command([self.apfs_fls, "-B", str(p.block_number), "-s", "0", "-m", mountpath, "-r", "-o", str(
                            p.osects * 8), "-b", str(disk.sectorsize), "-i", "raw", disk.imagefile], stdout=f, logger=self.logger())
                else:
                    # we know the sector size
                    if p.encrypted:
                        run_command([self.fls, "-s", "0", "-m", mountpath, "-r", "-b", str(disk.sectorsize),
                                     os.path.join(p.mountaux, f'bp{p.partition}', 'bde1')], stdout=f, logger=self.logger())
                    else:
                        run_command([self.fls, "-s", "0", "-m", mountpath, "-r", "-o", str(p.osects),
                                     "-b", str(disk.sectorsize), disk.imagefile], stdout=f, logger=self.logger())

        return f"{disk.source}_BODY.csv"


class MFTTimeline(BaseTimeline):
    """
    Generates timeline and body files from an $MFT.

    Configuration:
        - **volume_id**: volume identifier, such as partition number. Ex: 'p03'
        - **executable**: path to executable app to parse timeline
        - **summary**: generate a summary of files by `time_range`
        - **time_range**: time range for buckets to split the timeline in the summary. Options: `hour` and `day`
    """

    def read_config(self):
        super().read_config()
        self.set_default_config('volume_id', 'p01')
        # self.set_default_config('cmd', 'env WINEDEBUG=fixme-all wine {executable} -f {path} --body {outdir} --bodyf {filename} --bdl c --nl')
        self.set_default_config('cmd', '')
        self.set_default_config('executable', os.path.join(self.config.config['plugins.windows']['windows_tools_dir'], 'MFTECmd', 'MFTECmd.dll'))
        self.set_default_config('windows_tool', os.path.join(self.config.config['plugins.windows']['dotnet_dir'], 'dotnet'))
        self.set_default_config('windows_format', True)
        self.set_default_config('drive_letter', 'c:')

    def run(self, path=""):

        # Check if there's another mft_timeline job running
        base.job.wait_for_job(self.config, self)

        self.check_params(path, check_from_module=False, check_path=True, check_path_exists=True)
        self.path = path
        tl_dir = self.myconfig('outdir')
        check_directory(tl_dir, create=True)

        # Create a volume specific body file to avoid overriding other partitions
        main_body_filename = f"{self.myconfig('source')}_BODY.csv"
        body_filename = f"{self.myconfig('source')}_BODY_{self.myconfig('volume_id')}.csv"
        body_filename_pattern = f"{self.myconfig('source')}_BODY_*.csv"

        # WARNING: Use cmd with caution. Anything can be executed
        cmd = self.myconfig('cmd')
        path_conversion = windows_format_path if self.myflag('windows_format') else lambda x, enclosed: '"' + x + '"'
        cmd_vars = {'windows_tool': self.myconfig('windows_tool'),
                    'executable': path_conversion(self.myconfig('executable'), enclosed=True),
                    'path': path_conversion(path, enclosed=True),
                    'outdir': path_conversion(self.myconfig('outdir'), enclosed=True),
                    'filename': body_filename}
        cmd_args = shlex.split(cmd.format(**cmd_vars))
        substitution = self.myconfig('drive_letter')

        self.logger().debug(f'Running command: {str(cmd_args)}')
        self.generate_body(cmd_args)
        self.preceding_path(tl_dir, body_filename, substitution)
        self.merge_timelines(tl_dir, body_filename_pattern, main_body_filename)
        self.timeline_from_body(tl_dir, main_body_filename, self.myflag('summary'), self.myconfig('time_range'))
        return []

    def generate_body(self, cmd_args):
        """ Generate body file """
        self.logger().debug(f"Generating BODY file for {self.path}")
        run_command(cmd_args)

    def preceding_path(self, tl_dir, body_filename, substitution='c:'):
        """ Modify preceding path """
        volume_id = self.myconfig('volume_id')
        if substitution:
            cmd = rf"sed -i 's@\(\d*|\){substitution}\(.*\)@\1{self.myconfig('source')}/mnt/{volume_id}\2@g' {os.path.join(tl_dir, body_filename)}"
        else:
            # For every entry, assume the path will start by "[a-zA-Z]:"
            cmd = rf"sed -i 's@\(\d*|\)[a-zA-Z]:\(.*\)@\1{self.myconfig('source')}/mnt/{volume_id}\2@g' {os.path.join(tl_dir, body_filename)}"
        run_command(cmd)

    def merge_timelines(self, tl_dir, body_pattern, main_body_filename):
        """ Merge all body files into a single one.

        This type of output, where all partitions converge in a single file,
        ressembles sleuthkit timeline for a disk image. Then all timelines generated,
        regardless how they are created, follow the same pattern.
        """
        main_body = os.path.join(tl_dir, main_body_filename)
        cmd = rf"cat {os.path.join(tl_dir, body_pattern)} > {main_body}"
        run_command(cmd)
