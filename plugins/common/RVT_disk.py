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

"""
Manages images
"""

import os
import re
import subprocess
import pytsk3
import json
from plugins.common.RVT_partition import Partition, fs_descr
import logging
from base.utils import check_folder, check_file
from base.commands import run_command
import base.job


def getSourceImage(myconfig, imagefile=None, vss=False):
    """ Returns the path to the image file.

    imagefile is the absolute path to the image file or device.
    If not provided, search in imagedir for files as "source.ext"

    Known images are in the KNOWN_IMAGETYPES directory.
    """

    if imagefile:
        check_file(imagefile, error_missing=True)

    # Search in imagedir files with known extensions
    source = myconfig('source')
    imagedir = myconfig('imagedir')

    for ext in KNOWN_IMAGETYPES.keys():
        ifile = os.path.join(imagedir, f"{source}.{ext}")
        if check_file(ifile):
            if test_magic_image(ifile):
                return KNOWN_IMAGETYPES[ext]['imgclass'](imagefile=ifile, imagetype=KNOWN_IMAGETYPES[ext]['type'], params=myconfig)
            else:
                logging.warning(f'{imagefile} is not {ext} file. It will be treated as raw file')
                return KNOWN_IMAGETYPES['raw']['imgclass'](imagefile=ifile, imagetype=KNOWN_IMAGETYPES['raw']['type'], params=myconfig)
    logging.warning(f'Image file not found for source={source} in imagedir={imagedir}')
    imf = get_mountpoints(myconfig, myconfig('sourcedir'))
    if imf:  # mounted image
        return RawImage(imf, 'raw', myconfig)
    return DummyImage(imagefile=None, imagetype='dummy', params=myconfig)


def get_mountpoints(myconfig, sourcedir):
    mntpath = os.path.join(sourcedir, 'mnt')
    regex = re.compile(rf"^([^ ]+) .*{mntpath}/(p\d+)")
    with open('/proc/mounts', 'r') as f_in:
        for line in f_in:
            aux = regex.search(line)
            if aux:
                return aux.group(1)
    return False


def test_magic_image(imagefile):
    """ Sometimes, vmkd files are in flat format

    This function checks if it is the same of extension """

    ext = imagefile.split('.')[-1].lower()
    with open(imagefile, 'rb') as f_in:
        magic = f_in.read(16)
    if ext == 'vmdk':
        return magic[:3] == b'KDM' or magic == b'# Disk Descripto'
    elif ext == 'vhdx':
        return magic[:8] == b'vhdxfile'
    elif ext == 'vhd':
        return magic[:9] == b'connectix'
    elif ext == 'e01':
        return magic[:3] == b'EVF'
    else:
        return True


class BaseImage(object):
    def __init__(self, imagefile, imagetype, params, load=True):
        self.logger = logging.getLogger('Disk')
        self.params = params
        self.load = load
        if load:
            vars = self.load_disk()
            if vars:
                for var, value in vars.items():
                    setattr(self, var, value)
                return
        self.morgue = self.params('morgue')
        self.source = self.params('source')  # source
        self.imagefile = imagefile
        self.imagetype = imagetype
        self.sectorsize = None
        self.partitions = []
        self.fusedirectory = None
        self.mmls()

    def mount(self, partitions='', vss=False):
        for p in self.partitions:
            p.mount()
        if self.load:
            self.save_disk()

    def umount(self):
        """ Unmounts all partitions"""

        # umount data partitions

        for p in self.partitions:
            p.umount()

    def mmls(self):
        pass

    def myflag(self, option, default=False):
        """ A convenience method for self.config.getboolean(self.section, option, False) """
        value = self.params(option, str(default))
        return value in ('True', 'true', 'TRUE', 1)

    def save_disk(self):
        """ Write partition variables in a JSON file """

        check_folder(self.params('auxdir'))
        outfile = os.path.join(self.params('auxdir'), f'disk_info.json')
        skipped_vars = ['logger', 'params', 'partitions', 'fuse_imagetype', 'load', 'raw_image']

        with open(outfile, 'w') as out:
            try:
                jsondata = json.dumps(
                    {k: v for k, v in self.__dict__.items() if k not in skipped_vars}, indent=4)
                out.write(jsondata)
            except TypeError as exc:
                raise exc

    def load_disk(self):
        """ Load disk variables from JSON file. Avoids running mmls every time """

        infile = os.path.join(self.params('auxdir'), f'disk_info.json')
        if self.myflag('remove_info') and check_file(infile):
            try:
                os.remove(infile)
            except Exception:
                self.logger.error(f"Error while deleting file: {infile}")
            return False

        self.logger.debug(f'Loading disk information')
        if check_file(infile) and os.path.getsize(infile) != 0:
            with open(infile) as inputfile:
                try:
                    return json.load(inputfile)
                except Exception:
                    self.logger.warning(f'JSON file {infile} malformed')
                    return False
        return False

    def exists(self):
        """ Returns True if the disk was found in the morgue. """
        return check_file(self.imagefile)

    def __str__(self):
        if self.exists():
            text = f'Case source={self.source} sectorsize={self.sectorsize}\n\n'
            for p in self.partitions:
                text += f"Partition: {p.partition}\n\tOffset in sectors: {p.osects}\n\tCluster Size: {p.clustersize}\n\tFile System: {p.filesystem}\n\tSize: {p.size}"
                if hasattr(p, 'vss') and len(p.vss) > 0:
                    text += f"\n\t \tpartition {p.partition} has {len(p.vss)} stores"
                if p.encrypted:
                    text += f"\n\t \tpartition {p.partition} is encrypted"
                text += "\n\n"
            return text
        else:
            return f'Source id={self.source} not found'


class DummyImage(BaseImage):
    def __init__(self, imagefile, imagetype, params):
        super().__init__(imagefile, imagetype, params)
        self.imagetype = 'dummy'

    def mount(self, partitions='', vss=False):
        pass

    def umount(self, unzip_path=None):
        pass

    def mmls(self):
        pass


class RawImage(BaseImage):
    """ A class for raw images. """

    def mount(self, partitions=None, vss=False):
        """ Mounts partitions of disk
        Args:
            partitions (str): Comma separated list of partitions to be mounted (mounts all available partitions by default). Ex: 'p02,v1p03,p05'
        Returns:
            bool: False in case of error
        """
        # TODO: partition.mount when vss mounts all vss. It will be desirable to select only one or some of them
        if not partitions:
            parts = self.partitions
        else:
            part_by_name = {''.join(['p', p.partition]): p for p in self.partitions}
            vss_by_name = {v: p for p in self.partitions for v in p.vss}
            parts = []
            try:
                for p in partitions.split(','):
                    if p.startswith('p'):
                        parts.append(part_by_name[p])
                    elif p.startswith('v'):
                        parts.append(vss_by_name[p])
            except KeyError:
                raise base.job.RVTError(f'Partition name {p} not found')
        if len(parts) < 1:
            raise base.job.RVTError('No partition set to be mounted')

        for p in parts:
            if p.isMountable or p.filesystem in ['HFS', 'ext4']:
                p.mount()
                p.save_partition()

    def _getRawImagefile(self):
        """ Get the raw image file.

        Some images (encase, aff4...) must be mounted in order to have a raw image.
        Use this method to mount and get the path of these auxiliary mounts.
        """

        return self.imagefile

    def mmls(self):
        """ Read partitions from the image """

        imagefile = self._getRawImagefile()
        self.logger.debug(f"Listing partitions. source={self.params('source')} imagefile={imagefile} type={self.imagetype}")

        img = pytsk3.Img_Info(imagefile)
        try:
            volume = pytsk3.Volume_Info(img)
            self.sectorsize = volume.info.block_size
        except Exception:
            volume = None

        if not volume:
            self.logger.info(f"File imagefile={self.imagefile} has not a partition table or is malformed. Trying to manage as a single partition")
            try:
                fs = pytsk3.FS_Info(img)
                filesystem = fs_descr[fs.info.ftype]
                filesystem = filesystem.split("TSK_FS_TYPE_")[-1]
                self.sectorsize = 512
                self.partitions.append(Partition(imagefile, int(os.stat(self.imagefile).st_size) / int(self.sectorsize), filesystem, "0", "0", self.sectorsize, self.params))
                return
            except Exception:
                self.logger.error(f"Error getting image partition info from imagefile={self.imagefile}")
                return

        for part in volume:
            partition = "%02d" % int(part.addr)
            osects = part.start
            size = part.len
            try:
                fs = pytsk3.FS_Info(img, int(int(osects) * int(self.sectorsize)))
                filesystem = fs_descr[fs.info.ftype]
                filesystem = filesystem.split("TSK_FS_TYPE_")[-1]
            except Exception:
                filesystem = part.desc.decode()
            if filesystem.startswith('Macintosh HD'):
                filesystem = "HFS"
            elif filesystem.startswith('Linux'):
                filesystem = "ext4"
            elif filesystem == "NoName":
                apfs_pstat = self.params('apfs_pstat', '/usr/local/src/sleuthkit-APFS/tools/pooltools/pstat')
                mosects = osects
                if self.sectorsize == 4096:  # sleuthkit-APFS uses 512 blocksize
                    # TODO: check if this must be osects *= 8
                    mosects = osects * 8
                pstat = ""
                try:
                    pstat = subprocess.check_output([apfs_pstat, "-o", str(osects), "-P", "apfs", self.imagefile]).decode()
                except Exception:
                    pstat = subprocess.check_output([apfs_pstat, "-o", str(osects * 8), "-P", "apfs", self.imagefile]).decode()
                pstat = pstat.split("\n")
                n = 0
                for p in pstat:
                    aux = re.search(r"APSB Block Number:\s+(\d+)", p)
                    if aux:
                        try:
                            partition = str(int(part.addr) * 10 + n)
                            self.partitions.append(Partition(imagefile, size, filesystem, osects, partition, self.sectorsize, self.params, aux.group(1), n))
                            n += 1
                        except Exception:
                            self.logger.error(f"Problems getting information about APFS partition {partition} with block Number {aux.group(1)}")
            try:
                self.partitions.append(Partition(imagefile, size, filesystem, osects, partition, self.sectorsize, self.params))
            except Exception as exc:
                self.logger.error(f"Error getting information about partition {partition}: {exc}")

    def myflag(self, option, default=False):
        """ A convenience method for self.config.getboolean(self.section, option, False) """
        value = self.params(option, str(default))
        return value in ('True', 'true', 'TRUE', 1)


class FuseImage(BaseImage):
    """ Manages different liblyal images

    It creates a fuse device in mountauxdir that will be used as imagefile to mounting partitions
    """

    def __init__(self, imagefile, imagetype, params):
        super().__init__(imagefile, imagetype, params)

        self.fuse_imagetype = {'encase': ['ewfmount', 'ewf1'],
                               'vmdk': ['vmdkmount', 'vmdk1'],
                               'vhdi': ['vhdimount', 'vhdi1']}
        self.fuse_path = os.path.join(self.params('mountauxdir'), self.imagetype)
        check_folder(self.fuse_path)
        # fusedevice will be used as imagefile
        self.fusedirectory = os.path.join(self.fuse_path, self.fuse_imagetype[self.imagetype][1])
        self.mount_fuse()  # first time has to be mounted to fill disk and partitions info
        self.raw_image = RawImage(self.fusedirectory, 'raw', self.params, load=False)
        self.partitions = self.raw_image.partitions

    def mount_fuse(self):
        # mount fusedevice from imagefile
        mount_app = self.params(self.fuse_imagetype[self.imagetype][1], f'/usr/local/bin/{self.fuse_imagetype[self.imagetype][0]}')
        if not os.path.exists(mount_app):
            mount_app = self.params(self.fuse_imagetype[self.imagetype][1], f'/usr/bin/{self.fuse_imagetype[self.imagetype][0]}')
        if not os.path.exists(self.fusedirectory):
            # mounts fusedevice with command
            try:
                run_command([mount_app, self.imagefile, "-X", "allow_root", self.fuse_path])
            except Exception:
                self.logger.error(f"Cannot mount {self.imagetype} imagefile={self.imagefile}")
                raise base.job.RVTError(f"Cannot mount {self.imagetype} imagefile={self.imagefile}")

    def mount(self, partitions=None, vss=False):

        # creates RawImage to mount
        self.raw_image.mount(partitions, vss)
        if self.load:
            self.save_disk()

    def umount(self):
        raw_image = RawImage(self.fusedirectory, 'raw', self.params, load=False)
        for p in raw_image.partitions:
            p.umount()
        umount = self.params('umount', '/bin/umount')

        run_command(["sudo", umount, '-l', self.fuse_path])


class CompressedImage(BaseImage):
    """ Manages a compressed file as an image file mounting with archivemount """

    def mmls(self):
        """ There is only one partition, named as configured in partname. Default: p01 """

        self.partitions.append(Partition(self.imagefile, 0, 'compressed', 0, '01', 0, self.params))


class AFFImage(BaseImage):
    """ Manages an AFF4 image """

    def _getRawImagefile(self):
        fuse_path = os.path.join(self.params('mountauxdir'), "aff")
        imagefile = os.path.join(fuse_path, f"{os.path.basename(self.imagefile)}.raw")
        self.auxdirectories.append(fuse_path)
        if not os.path.exists(imagefile):
            affuse = self.params('affuse', '/usr/bin/affuse')
            check_folder(fuse_path)
            try:
                run_command(["sudo", affuse, self.imagefile, fuse_path])
                fuse_path = os.path.join(self.params('mountauxdir'), "aff")
                imagefile = os.path.join(fuse_path, f"{os.path.basename(self.imagefile)}.raw")
            except Exception:
                self.logger.error(f"Cannot mount AFF imagefile={self.imagefile}")
                raise base.job.RVTError(f"Cannot mount AFF imagefile={self.imagefile}")
        return imagefile

    def umount(self, unzip_path=None):
        super().umount()
        # unmount auxiliary images (encase and aff4)
        umount = self.params('umount', '/bin/umount')
        for mp in self.auxdirectories:
            run_command(["sudo", umount, '-l', mp])


class VHDXImage(BaseImage):
    """ Manages a VHDX image (VmWare)

    Params:
        - nbd-device: the device to mount. Defaults to /dev/ndb0 """

    def _getRawImagefile(self):
        device = self.params('nbd_device', '/dev/nbd0')
        qemu_nbd = self.params('qemu_nbd', 'qemu-nbd')
        try:
            # TODO: check if this needs sudo
            run_command(["sudo", qemu_nbd, "-c", device, "-r", self.imagefile])
        except Exception:
            self.logger.error(f"Cannot mount VHDX imagefile={self.imagefile}")
            raise base.job.RVTError(f"Cannot mount VHDX imagefile={self.imagefile}")
        return device

    def umount(self):
        super().umount()
        device = self.params('ndb-device', '/dev/nbd0')
        qemu_nbd = self.params('qemu_nbd', '/usr/bin/qemu_nbd')
        # TODO: check if this needs sudo
        run_command(["sudo", qemu_nbd, "-d", device])


# name: type, imageclass
# The order is important: zip must be the last option (an image maybe already unzipped)
KNOWN_IMAGETYPES = {
    "/dev": dict(type='raw', imgclass=RawImage),
    "001": dict(type='raw', imgclass=RawImage),
    "dd": dict(type='raw', imgclass=RawImage),
    "raw": dict(type='raw', imgclass=RawImage),
    "aff": dict(type='aff', imgclass=AFFImage),
    "aff4": dict(type='aff4', imgclass=AFFImage),
    "E01": dict(type='encase', imgclass=FuseImage),
    "vmdk": dict(type='vmdk', imgclass=FuseImage),
    "vhdx": dict(type='vhdx', imgclass=VHDXImage),
    "zip": dict(type='compressed', imgclass=CompressedImage),
    "tar": dict(type='compressed', imgclass=CompressedImage),
    "tgz": dict(type='compressed', imgclass=CompressedImage),
    "rar": dict(type='compressed', imgclass=CompressedImage),
    "7z": dict(type='compressed', imgclass=CompressedImage)
}
# NOT_MOUNTABLE_PARTITIONS = ("Primary Table", "GPT Header", "Safety Table", "Partition Table", "Unallocated")
