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

import logging
import pytsk3
import os
import pyvshadow
import re
import time
import getpass
import grp
import subprocess
import ujson as json
from base.utils import check_folder, check_file, check_directory
from base.commands import run_command


fs_descr = {
    0x00000000: 'TSK_FS_TYPE_DETECT',
    0x00000001: 'TSK_FS_TYPE_NTFS',
    0x00000002: 'TSK_FS_TYPE_FAT12',
    0x00000004: 'TSK_FS_TYPE_FAT16',
    0x00000008: 'TSK_FS_TYPE_FAT32',
    0x0000000a: 'TSK_FS_TYPE_EXFAT',
    0x0000000e: 'TSK_FS_TYPE_FAT_DETECT',
    0x00000010: 'TSK_FS_TYPE_FFS1',
    0x00000020: 'TSK_FS_TYPE_FFS1B',
    0x00000040: 'TSK_FS_TYPE_FFS2',
    0x00000070: 'TSK_FS_TYPE_FFS_DETECT',
    0x00000080: 'TSK_FS_TYPE_EXT2',
    0x00000100: 'TSK_FS_TYPE_EXT3',
    0x00002180: 'TSK_FS_TYPE_EXT_DETECT',
    0x00000200: 'TSK_FS_TYPE_SWAP',
    0x00000400: 'TSK_FS_TYPE_RAW',
    0x00000800: 'TSK_FS_TYPE_ISO9660',
    0x00001000: 'TSK_FS_TYPE_HFS',
    0x00009000: 'TSK_FS_TYPE_HFS_DETECT',
    0x00002000: 'TSK_FS_TYPE_EXT4',
    0x00004000: 'TSK_FS_TYPE_YAFFS2',
    0x00008000: 'TSK_FS_TYPE_HFS_LEGACY',
    0x00010000: 'TSK_FS_TYPE_APFS',
    0x00020000: 'TSK_FS_TYPE_LOGICAL',
    0xffffffff: 'TSK_FS_TYPE_UNSUPP'
}

non_mountable_partitions = ("Primary Table", "GPT Header", "Safety Table", "Unallocated", "Extended Table", "DOS Extended")


def ismounted(path):
    return os.path.ismount(path)


class Partition(object):
    """ Stores relevant information about a partition. Allows to mount the partiton
    """

    def __init__(self, imagefile, size, filesystem, osects, partition, sectorsize, myconfig, mountpoint=None, bn="", voln=""):
        self.logger = logging.getLogger(__name__)
        self.myconfig = myconfig
        self.partition = partition

        # Try to load variables from a previously generated json file
        vars = self.load_partition()
        if vars:
            for var, value in vars.items():
                setattr(self, var, value)
            return

        # Initialize basic attributes for a partition
        self.mountdir = self.myconfig('mountdir')
        if mountpoint:
            self.mountpath = mountpoint
        else:
            self.mountpath = os.path.join(self.myconfig('mountdir'), f'p{partition}')
        self.mountaux = self.myconfig('mountauxdir')
        self.imagefile = imagefile  # path to the source image
        self.filesystem = filesystem  # filesystem name according to mmls
        self.size = int(size) * int(sectorsize)
        self.fuse = {}
        self.osects = osects
        self.loop = ""  # Loop device for partiton
        self.obytes = int(osects) * int(sectorsize)
        self.isMountable = True
        if self.filesystem == "compressed":
            self.save_partition()
            return
        self.check_bitlocker()  # Check if a partition uses bitlocker and set self.encrypted
        if bn:
            self.block_number = bn
            self.voln = voln

        # Skip partitions know to be non mountable
        for unm in non_mountable_partitions:
            if self.filesystem.startswith(unm):
                self.isMountable = False
                self.clustersize = sectorsize
                return
        # Obtain clustersize and block_size
        try:
            img = pytsk3.Img_Info(imagefile)
            fs = pytsk3.FS_Info(img, offset=int(self.osects) * int(sectorsize))
            if filesystem == 'Linux':
                filesystem = fs_descr[fs.info.ftype]
                self.filesystem = filesystem.split("TSK_FS_TYPE_")[-1]
                if filesystem.startswith('Linux'):
                    filesystem = "ext4"
            self.clustersize = fs.info.block_size
        except Exception:
            # self.logger.warning(f"Problems getting information about partition {self.partition}")
            if self.check_lvm():
                self.clustersize = sectorsize
                self.filesystem = 'lvm'
                self.get_lvm_info()
            elif self.encrypted or self.filesystem == "NoName" or self.filesystem == "HFS":
                self.clustersize = 4096
            else:
                self.clustersize = 512
                self.isMountable = False
                return

        # Check for VSS
        if self.filesystem.startswith('NTFS') or self.filesystem.startswith('Basic data partition') or self.encrypted:
            self._get_vshadowinfo()

        # Save partition information to be easily retrieved later
        self.save_partition()

    def _get_vshadowinfo(self):
        """ Save VSS information """

        vshadow_volume = pyvshadow.volume()

        with DataRangeFileObject(self.imagefile, self.obytes, self.size) as file_object:
            try:
                vshadow_volume.open_file_object(file_object)
                if vshadow_volume.number_of_stores > 0:
                    self.vss = []  # list of all vss on a partition
                    # self.vss_mounted = {}  # Mount point for all vss
                    self.vss_info = {}
                    self.logger.debug(f"Partition {self.partition} has {vshadow_volume.number_of_stores} mounting points")
                    for current_store in range(vshadow_volume.number_of_stores):
                        vshadow_store = vshadow_volume.get_store(current_store)
                        if current_store + 1 not in self.vss_info:
                            self.vss_info[current_store + 1] = {}
                        self.vss_info[current_store + 1]['id'] = vshadow_store.identifier
                        self.vss_info[current_store + 1]['shadow_id'] = vshadow_store.copy_identifier
                        self.vss_info[current_store + 1]['creation_time'] = vshadow_store.creation_time.strftime("%Y-%m-%dT%H:%M:%S")
                        # vshadow_store.get_size()

                    self.vss = [f"v{i}p{self.partition}" for i in range(1, vshadow_volume.number_of_stores + 1)]
                vshadow_volume.close()
            except Exception as exc:
                print(str(exc))
                self.logger.warning(f"Problems getting vshadow info of partition {self.partition}. Maybe it has no mounting points")

    def check_lvm(self):
        """ checks if filesystem is lvm.

        There are some problems with python bindings and vslvmmount
        To mount using lvm system tools the image must be modified
        """

        magic = b'\x4c\x41\x42\x45\x4c\x4f\x4e\x45'

        with open(self.imagefile, "rb") as f:
            f.seek(self.obytes + 512)
            a = f.read(8)
            if a == magic:
                return True
        return False

    def get_lvm_info(self):
        """ Describes lvm info in the partition

        Python bindings not work well so information is obtained with output of command """

        lvminfo = self.myconfig('vslvminfo', '/usr/local/bin/vslvminfo')
        output = ""
        DEVNULL = open(os.devnull, 'wb')
        if self.obytes == 0:
            try:
                if not self.encrypted:
                    output = subprocess.check_output([lvminfo, self.imagefile], stderr=DEVNULL).decode()
                else:
                    output = subprocess.check_output([lvminfo, self.loop], stderr=DEVNULL).decode()
            except Exception:
                pass
        else:
            try:
                if not self.encrypted:
                    output = subprocess.check_output([lvminfo, self.imagefile, "-o", str(self.obytes)], stderr=DEVNULL).decode()
                else:
                    output = subprocess.check_output([lvminfo, self.loop], stderr=DEVNULL).decode()
            except Exception:
                pass  # No vss found

        DEVNULL.close()
        self._parse_lvm_info_output(output)

        self.logger.debug(f"Partition {self.partition} has {len(self.lvm_info)} lvm volumes")

    def _parse_lvm_info_output(self, output):
        """ Parse lvm information from standard vslvminfo output.
            Expected format example:

            ```
        vslvminfo 20240504

        Linux Logical Volume Manager (LVM) information:
        Volume Group (VG):
            Name:                   VulnOSv2-vg
            Identifier:             RJRcoE-WgWP-CS2S-....-v1ZF-....-TT8SFQ
            Sequence number:            3
            Extent size:                4.0 MiB (4194304 bytes)
            Number of physical volumes:     1
            Number of logical volumes:      2

        Physical Volume (PV): 1
            Name:                   pv0
            Identifier:             SA3YAl-91Rk-....-cQGz-TnXl-....-awbQjd
            Device path:                /dev/sda5
            Volume size:                31 GiB (33568063488 bytes)

        Logical Volume (LV): 1
            Name:                   root
            Identifier:             cEA4A3-....-U3Sj-....-mK9i-1rwE-bE6f2t
            Number of segments:         1
            Segment: 1
                Offset:             0x00000000 (0)
                Size:               30 GiB (32761708544 bytes)
                Number of stripes:      1
                Stripe: 1
                    Physical volume:    pv0
                    Data area offset:   0x00000000 (0)

        Logical Volume (LV): 2
            Name:                   swap_1
            Identifier:             Q7X8aN-....-SVUY-PS35-y3dz-....-uAcg1f
            Number of segments:         1
            Segment: 1
                Offset:             0x00000000 (0)
                Size:               768 MiB (805306368 bytes)
                Number of stripes:      1
                Stripe: 1
                    Physical volume:    pv0
                    Data area offset:   0x7a0c00000 (32761708544)
        ```
        """

        self.lvm_info = []
        inlogicalV = False
        for line in output.split("\n"):
            if line.startswith('Logical Volume'):
                inlogicalV = True
                current_volume = {}
                current_volume['logicalVolume'] = line.split(" ")[-1]
            elif inlogicalV and line.lstrip().startswith('Name:'):
                current_volume['Name'] = line.split("\t")[-1]
            elif inlogicalV and line.lstrip().startswith('Identifier'):
                current_volume['Id'] = line.split("\t")[-1]
            elif inlogicalV and line.lstrip().startswith('Size'):
                aux = re.search(r"\((\d+) bytes", line)
                current_volume['Size'] = int(aux.group(1))
                self.lvm_info.append(current_volume)

    def check_bitlocker(self):
        """ Check if partition is encrypted with bitlocker """

        self.encrypted = False
        initBitlocker = b"\xeb\x58\x90\x2d\x46\x56\x45\x2d\x46\x53\x2d"
        with open(self.imagefile, "rb") as f:
            f.seek(self.obytes)
            a = f.read(11)
            if a == initBitlocker:
                self.encrypted = True
                self.logger.debug("Partition {self.partition} is encrypted")

    def mount(self):
        """ Main mounting method for partitions. Calls specific function depending on Filesystem type """

        if not self.isMountable:
            return

        self.logger.debug(f'Mounting partition={self.partition} of type={self.filesystem} from imagefile={self.imagefile}')
        vss = self.myflag('vss')

        mount = self.myconfig('mount', '/bin/mount')
        archivemount = self.myconfig('archivemount', '/usr/bin/archivemount')

        try:
            if self.filesystem == 'compressed':
                args = 'readonly,allow_other'
                self.mountPartition(archivemount, args, sudo=False)
            elif self.encrypted:
                self.mount_bitlocker()
                if vss and len(self.vss) > 0:
                    self.vss_mount()
            elif self.filesystem.startswith("HFS"):
                args = f"{self.myconfig('hfs_args').format(gid=grp.getgrgid(os.getegid())[2])}{',offset=%s' % self.obytes if self.obytes !=0 else ''},sizelimit={self.size}"
                self.mountPartition(mount, args, mountpath=os.path.join(self.mountaux, f"p{self.partition}"))
                self.bindfs_mount()
            elif self.filesystem.lower().startswith("ext"):
                args = f"{self.myconfig('ext4_args')}{',offset=%s' % self.obytes if self.obytes !=0 else ''},sizelimit={self.size}"
                try:
                    self.mountPartition(mount, args, mountpath=os.path.join(self.mountaux, f"p{self.partition}"))
                except Exception:
                    args = args + ',norecovery'
                    self.mountPartition(mount, args, mountpath=os.path.join(self.mountaux, f"p{self.partition}"))
                self.bindfs_mount()
            elif self.filesystem == "NoName":
                self.mount_APFS()
            elif self.filesystem.startswith("FAT"):
                args = f"{self.myconfig('fat_args').format(gid=grp.getgrgid(os.getegid())[0])}{',offset=%s' % self.obytes if self.obytes !=0 else ''},sizelimit={self.size}"
                self.mountPartition(mount, args)
            elif self.filesystem == "lvm":
                self.mount_lvm()
            else:
                args = f"{self.myconfig('ntfs_args').format(gid=grp.getgrgid(os.getegid())[2])}{',offset=%s' % self.obytes if self.obytes !=0 else ''},sizelimit={self.size}"
                self.mountPartition(mount, args, 'ntfs-3g')
                if hasattr(self, 'vss') and len(self.vss) > 0:
                    self.vss_mount()
        except Exception as exc:
            self.logger.error(f"Error mounting partition: {exc}. imagefile={self.imagefile} partition=p{self.partition}")
        self.save_partition()

    def mountPartition(self, mount_app, args, extra_args=None, sudo=True, imagefile=None, mountpath=None, offset=True):
        """ mounts generic partition

        Args:
            mount_app (str): application used to mount partition
            args (str): arguments used to mount, readonly, sizelimit,...
            extra_args (str): filesystem args, for example ntfs-3g
            imagefile (str): imagefile path (used for auxiliary mouny point). If None, use self.imagefile.
            mountpath (str): mount the image on this path. If None, use `source/mnt/pXX`.
            offset (bool): Used to ignore disk offset (used for auxiliary mount point)
        """

        if not mountpath:
            mountpath = os.path.join(self.mountdir, f"p{self.partition}")
        if ismounted(mountpath):
            self.logger.debug(f"{mountpath} is already mounted")
            return 0
        if not imagefile:
            imagefile = self.imagefile
        check_folder(mountpath)
        run_command([*(("sudo",) if sudo else ()), mount_app, imagefile, *(("-t", extra_args) if extra_args else ()), "-o", args, mountpath], logger=self.logger)

    def mount_bitlocker(self):
        rec_key = self.myconfig('recovery_keys')
        dislocker = self.myconfig('bdemount', '/usr/local/bin/bdemount')
        mountauxpath = os.path.join(self.mountaux, f'bp{self.partition}')
        if ismounted(mountauxpath):
            self.logger.debug(f"bitlocker fuse device {mountauxpath} is already mounted")
            return 0
        check_folder(mountauxpath)
        import time

        args = f"{self.myconfig('ntfs_args').format(gid=grp.getgrgid(os.getegid())[2])}"
        if rec_key == "":
            self.logger.warning(f"Recovery key not available on partition p{self.partition}. Trying without key")
            try:
                run_command([dislocker, "-o", self.obytes, "-X", "allow_root", "-o", self.imagefile, mountauxpath], logger=self.logger)
                time.sleep(2)
                self.mountPartition('mount', args, 'ntfs-3g', imagefile=os.path.join(mountauxpath, "dislocker-file"), offset=False)
            except Exception as exc:
                self.logger.error(f"Problems mounting bitlocker partition p{self.partition} without recovery_key: {str(exc)}")
                return -1
        else:
            self.logger.debug(f"Trying to mount {self.partition} with recovery keys at {mountauxpath}")
            # loop wih different recovery keys, comma separated
            for rk in rec_key.split(','):
                try:
                    run_command([dislocker, "-X", "allow_root", "-r", rk, self.imagefile, "-o", str(self.obytes), mountauxpath], logger=self.logger)
                    time.sleep(2)
                    self.mountPartition('mount', args, 'ntfs-3g', imagefile=os.path.join(mountauxpath, "bde1"), offset=False)
                    break
                except Exception as exc:
                    self.logger.error(f"Problems mounting bitlocker of partition p{self.partition}: {str(exc)}")
                    return -1

    def mount_APFS(self):
        apfsmount = self.myconfig('apfsmount', '/usr/local/bin/apfs-fuse')
        mountpath = os.path.join(self.mountaux, f"p{self.partition}")
        if ismounted(mountpath):
            self.logger.debug(f"{mountpath} is already mounted")
            return 0
        check_folder(mountpath)
        run_command(["sudo", apfsmount, "-s", str(self.obytes), "-v", str(self.voln), self.imagefile, mountpath], logger=self.logger)
        self.bindfs_mount()

    def bindfs_mount(self):
        user = getpass.getuser()
        group = grp.getgrgid(os.getegid())[0]

        mountaux = os.path.join(self.mountaux, f"p{self.partition}")
        check_folder(self.mountpath)
        bindfs = self.myconfig('bindfs', '/usr/bin/bindfs')
        run_command(["sudo", bindfs, "-p", "550", "-u", user, "-g", group, mountaux, self.mountpath], logger=self.logger)

    def fvde_mount(self):
        self.logger.debug('Obtaining encrypted partition')
        fvdemount = self.myconfig('fvdemount', '/usr/local/bin/fvdemount')
        password = self.myconfig('password')
        mountpoint = os.path.join(self.mountaux, f"vp{self.partition}")
        check_folder(mountpoint)
        # TODO: get 'EncryptedRoot.plist.wipekey' from recovery partition: https://github.com/libyal/libfvde/wiki/Mounting
        encryptedfile = os.path.join(self.myconfig('sourcedir'), 'EncryptedRoot.plist.wipekey')
        run_command([fvdemount, "-e", encryptedfile, "-p", password, "-X", "allow_root", "-o", str(self.obytes), self.imagefile, mountpoint], logger=self.logger)
        time.sleep(2)  # let it do his work
        args = f"{self.myconfig('hfs_args').format(gid=grp.getgrgid(os.getegid())[2])},sizelimit={self.size}"
        self.mountPartition('mount', args, imagefile=os.path.join(mountpoint, 'fvde1'), mountpath=os.path.join(self.mountaux, f"p{self.partition}"), offset=False)

    def mount_lvm(self):
        lvmmount = self.myconfig('vslvmmount', f'/usr/local/bin/vslvmmount')
        mountauxpath = os.path.join(self.mountaux, f'lvm{self.partition}')

        if ismounted(mountauxpath):
            self.logger.debug(f"lvm partition {mountauxpath} is already mounted")
            return 0

        check_folder(mountauxpath)
        try:
            run_command([lvmmount, self.imagefile, '-o', str(self.obytes), "-X", "allow_root", mountauxpath])
        except Exception:
            self.logger.error(f"Cannot mount lvm of imagefile={self.imagefile} of partition {self.partition}")
            return

        for lv in self.lvm_info:
            p = Partition(os.path.join(mountauxpath, f'lvm{lv["logicalVolume"]}'), lv["Size"] / self.clustersize, 'Linux', 0, f'{self.partition}l{lv["logicalVolume"]}', self.clustersize, self.myconfig)
            p.mount()

    def vss_mount(self):
        vshadowmount = self.myconfig('vshadowmount', '/usr/local/bin/vshadowmount')

        # Create auxiliar fuse mount point
        vp = os.path.join(self.mountaux, f"vp{self.partition}")

        if len(self.fuse) == 0 or "fuse" not in self.fuse.keys():
            self.logger.debug(f'Mounting auxiliary vss point: {vp}')
            check_directory(vp, create=True)
            if self.encrypted:
                run_command(["sudo", vshadowmount, "-X", "allow_root", self.loop, vp], logger=self.logger)
            else:
                run_command([vshadowmount, "-X", "allow_root", self.imagefile, "-o", str(self.obytes), vp], logger=self.logger)

        # Create as many new sources as VSS existing, and mount them
        for p in self.vss:
            mp = os.path.join(f"{self.myconfig('sourcedir')}_{p}", "mnt", f"p{self.partition}")  # mounted as a new source
            args = f"{self.myconfig('ntfs_args').format(gid=grp.getgrgid(os.getegid())[2])}"
            self.mountPartition('mount', args, extra_args='ntfs-3g', imagefile=os.path.join(vp, f"vss{p.split('v')[1].split('p')[0]}"), mountpath=mp, offset=False)

    def umount(self):
        """ Unmounts all partitions """

        self.umountPartition(self.mountpath)
        time.sleep(1)
        self.umountPartition(os.path.join(self.mountaux, f'p{self.partition}'))
        self.umountPartition(os.path.join(self.mountaux, f'bp{self.partition}'))  # bitlocker aux path
        # umount lvm partitions
        for part in os.listdir(self.mountdir):
            if part.startswith(f"p{self.partition}l"):
                self.umountPartition(os.path.join(self.mountdir, part))
                self.umountPartition(os.path.join(self.mountaux, part))
        self.umountPartition(os.path.join(self.mountaux, f'lvm{self.partition}'))
        # umount vss
        if hasattr(self, 'vss'):
            for part in self.vss:
                self.umountPartition(os.path.join(f"{self.myconfig('sourcedir')}_{part}", "mnt", f"p{self.partition}"))
            self.umountPartition(os.path.join(self.mountaux, f'vp{self.partition}'))

        self.save_partition()

    def umountPartition(self, mp):
        """ Umount path """

        if not ismounted(mp):
            return

        umount = self.myconfig('umount', '/bin/umount')

        try:
            run_command(["sudo", umount, '-l', mp], logger=self.logger)
        except Exception:
            self.logger.error(f"Error unmounting {self.mountpath}")
        # Remove partition info file if 'remove_info' is True:
        self.save_partition()

    def myflag(self, option, default=False):
        """ A convenience method for self.config.getboolean(self.section, option, False) """
        value = self.myconfig(option, str(default))
        return value in ('True', 'true', 'TRUE', 1)

    def save_partition(self):
        """ Write partition variables in a JSON file """

        check_folder(self.myconfig('auxdir'))
        outfile = os.path.join(self.myconfig('auxdir'), f'p{self.partition}_info.json')
        skipped_vars = ['logger', 'myconfig']
        with open(outfile, 'w') as out:
            try:
                jsondata = json.dumps({k: v for k, v in self.__dict__.items() if k not in skipped_vars}, indent=4, escape_forward_slashes=False)
                out.write(jsondata)
            except TypeError as exc:
                raise exc

    def load_partition(self):
        """ Load partition variables from JSON file. Avoids running mmls every time """

        infile = os.path.join(self.myconfig('auxdir'), f'p{self.partition}_info.json')
        if self.myflag('remove_info') and check_file(infile):
            try:
                os.remove(infile)
            except Exception:
                self.logger.error(f"Error while deleting file: {infile}")
            return False

        self.logger.debug(f'Loading partition {self.partition} information')
        if check_file(infile) and os.path.getsize(infile) != 0:
            with open(infile) as inputfile:
                try:
                    return json.load(inputfile)
                except Exception:
                    self.logger.warning(f'JSON file {infile} malformed')
                    return False
        return False

    def __str__(self):
        return(f"""
            Image file = {self.imagefile}
            Partition path = {self.mountpath}
            Partition filesystem = {self.filesystem}
            Partition offset = {self.obytes}
            Partition size = {self.size}
            Partition clusters size = {self.clustersize}
            """)


class DataRangeFileObject(object):
    """File-like object that maps an in-file data range. Obtained from tests of libvshadow"""

    def __init__(self, path, range_offset, range_size):
        """Initializes a file-like object.

        Args:
          path (str): path of the file that contains the data range.
          range_offset (int): offset where the data range starts.
          range_size (int): size of the data range starts, or None to indicate
              the range should continue to the end of the parent file-like object.
        """
        if range_size is None:
            stat_object = os.stat(path)
            range_size = stat_object.st_size

        super(DataRangeFileObject, self).__init__()
        self._current_offset = 0
        self._file_object = open(path, "rb")
        self._range_offset = range_offset
        self._range_size = range_size

    def __enter__(self):
        """Enters a with statement."""
        return self

    def __exit__(self, unused_type, unused_value, unused_traceback):
        """Exits a with statement."""
        return

    def close(self):
        """Closes the file-like object."""
        if self._file_object:
            self._file_object.close()
            self._file_object = None

    def get_offset(self):
        """Retrieves the current offset into the file-like object.

        Returns:
          int: current offset in the data range.
        """
        return self._current_offset

    def get_size(self):
        """Retrieves the size of the file-like object.

        Returns:
          int: size of the data range.
        """
        return self._range_size

    def read(self, size=None):
        """Reads a byte string from the file-like object at the current offset.

        The function will read a byte string of the specified size or
        all of the remaining data if no size was specified.

        Args:
          size (Optional[int]): number of bytes to read, where None is all
              remaining data.

        Returns:
          bytes: data read.

        Raises:
          IOError: if the read failed.
        """
        if (self._range_offset < 0 or (self._range_size is not None and self._range_size < 0)):
            raise IOError("Invalid data range.")

        if self._current_offset < 0:
            raise IOError(
                "Invalid current offset: {0:d} value less than zero.".format(self._current_offset))

        if (self._range_size is not None and self._current_offset >= self._range_size):
            return b""

        if size is None:
            size = self._range_size
        if self._range_size is not None and self._current_offset + size > self._range_size:
            size = self._range_size - self._current_offset

        self._file_object.seek(
            self._range_offset + self._current_offset, os.SEEK_SET)

        data = self._file_object.read(size)

        self._current_offset += len(data)

        return data

    def seek(self, offset, whence=os.SEEK_SET):
        """Seeks to an offset within the file-like object.

        Args:
          offset (int): offset to seek to.
          whence (Optional(int)): value that indicates whether offset is an absolute
              or relative position within the file.

        Raises:
          IOError: if the seek failed.
        """
        if self._current_offset < 0:
            raise IOError(
                "Invalid current offset: {0:d} value less than zero.".format(self._current_offset))

        if whence == os.SEEK_CUR:
            offset += self._current_offset
        elif whence == os.SEEK_END:
            offset += self._range_size
        elif whence != os.SEEK_SET:
            raise IOError("Unsupported whence.")
        if offset < 0:
            raise IOError("Invalid offset value less than zero.")

        self._current_offset = offset


# Next code extracted from https://stackoverflow.com/questions/1667257/how-do-i-mount-a-filesystem-using-python


# import ctypes
# import ctypes.util
# libc = ctypes.CDLL(ctypes.util.find_library('c'), use_errno=True)
# libc.mount.argtypes = (ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_ulong, ctypes.c_char_p)


# def mount(source, target, fs, options=''):
#     ret = libc.mount(source.encode(), target.encode(), fs.encode(), 0, options.encode())
#     if ret < 0:
#         errno = ctypes.get_errno()
#         raise OSError(errno, f"Error mounting {source} ({fs}) on {target} with options '{options}': {os.strerror(errno)}")
