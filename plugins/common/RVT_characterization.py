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
import re
from collections import defaultdict
import base.job
from plugins.common.RVT_disk import getSourceImage
from base.utils import human_readable_size

# TODO: Get disk info from new cloning machine


class CharacterizeDisk(base.job.BaseModule):
    """ Extract summary info about disk partitions.
    """

    def run(self, path=None):
        """ The output dictionaries with disk information are expected to be sent to a mako template """
        disk = getSourceImage(self.myconfig)
        if disk.imagetype == 'dummy':  # imagefile not found
            raise base.job.RVTError('No imagefile found. Make sure image file in directory {} is one of the following: raw, 001, dd, aff, E01, vhdx, zip'.format(self.myconfig('imagedir')))

        disk_info = self.get_image_information(disk)
        self.logger().debug('Disk characterization finished')

        return [
            dict(disk_info=disk_info, source=self.myconfig('source'))
        ]

    def get_image_information(self, disk):
        """ Get partition tables and number of vss. If cloning logs are provided, model ans serial number are obtained """
        disk_info = defaultdict(str)

        disk_info["Size"] = human_readable_size(os.stat(disk.imagefile).st_size)
        disk_info["npart"] = disk.getPartitionNumber()

        logfile = "{}.LOG".format(disk.imagefile[:-3])

        if os.path.isfile(logfile):
            with open(logfile, "r") as f1:
                for line in f1:
                    aux = re.search(r"\*\s*(Model\s*:\s*[^\|]*)\|\s*Model\s*:", line)
                    if aux:
                        disk_info["model"] = aux.group(1)
                    aux = re.search(r"\*\s*(Serial\s*:\s*[^\|]*)\|\s*Serial\s*:", line)
                    if aux:
                        disk_info["serial_number"] = aux.group(1)
        disk_info["partition"] = []

        for p in disk.partitions:
            if p.filesystem != "Unallocated" and not p.filesystem.startswith("Primary Table"):
                disk_info["partition"].append({"pnumber": p.partition, "size": human_readable_size(p.size), "type": p.filesystem, "vss": len(p.vss)})

        return disk_info
