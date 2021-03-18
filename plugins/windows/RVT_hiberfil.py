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

import re
import os
import subprocess
from plugins.common.RVT_files import GetFiles
from base.utils import check_folder
import base.job
from base.commands import run_command
from plugins.windows.RVT_os_info import CharacterizeWindows


class Hiberfil(base.job.BaseModule):

    def read_config(self):
        super().read_config()
        self.set_default_config('profile', '')
        self.set_default_config('volatility_plugins', "pslist netscan filescan shutdowntime mftparser")
        self.set_default_config('volume_id', 'p01')
        self.set_default_config('overwrite_imagecopy', False)

    def run(self, path=""):
        """ Get information of hiberfil.sys using volatility

        """
        hiber_path = self.myconfig('outdir')
        check_folder(hiber_path)
        self.volatility = self.config.get('plugins.common', 'volatility', '/usr/local/bin/vol.py')

        if not path:
            search = GetFiles(self.config)
            hiberlist = search.search("/hiberfil.sys$")

            for h in hiberlist:
                aux = re.search("{}/([^/]*)/".format(base.utils.relative_path(self.myconfig('mountdir'), self.myconfig('casedir'))), h)
                partition = aux.group(1)
                profile = version = self.myconfig('profile')
                if not profile:  # This is the default configuration
                    profile, version = self.get_win_profile(partition)
                hiber_file = os.path.join(self.myconfig('casedir'), h)
                hiber_raw = self._make_raw_copy(hiber_file, hiber_path, partition, profile, version)
                self.vol_extract(hiber_raw, profile)

        else:
            if not os.path.exists(path):
                raise base.job.RVTError('Provided path {} does not exist. Please, use an actual hiberfil.sys file as argument or let the job search in the source allocated files')
            partition = self.myconfig('volume_id')
            profile = self.myconfig('profile')
            version = profile
            if not profile:
                profile, version = self.get_win_profile(partition)
            hiber_raw = self._make_raw_copy(path, hiber_path, partition, profile, version)
            self.vol_extract(hiber_raw, profile)

        return []

    def _make_raw_copy(self, file, outdir, partition, profile, version):
        """ Create an image copy of hiberfil.sys """

        skip_dump = False
        hiber_raw = os.path.join(outdir, "hiberfil_{}.raw".format(partition))
        if os.path.exists(hiber_raw) and os.path.getsize(hiber_raw) > 0:
            if not self.myflag('overwrite_imagecopy'):
                self.logger().warning('Imagecopy {} already exists. Existing copy will be used. If you want to create a new one, set parameter `overwrite_imagecopy` to True')
                skip_dump = True
            else:
                os.remove(hiber_raw)

        if not skip_dump:
            self._check_version(profile, file, hiber_raw)
            self.logger().debug('Creating an imagecopy of file {} at {}'.format(file, hiber_raw))
            with open(os.path.join(outdir, "hiberinfo_{}.txt".format(partition)), 'w') as pf:
                pf.write("Profile: %s\nVersion: %s" % (profile, version))
            run_command([self.volatility, "--profile={}".format(profile), "-f", file, "imagecopy", "-O", hiber_raw], logger=self.logger())

        return hiber_raw

    def vol_extract(self, archive, profile):
        """ Extracts data from decompressed hiberfil files

        Args:
            archive (str): file to extract information
            profile (str): volatility profile
        """
        if not os.path.isfile(archive):
            raise base.job.RVTError('No raw extraction file generated. File does not exist: {}'.format(archive))

        plugins = self.myarray('volatility_plugins')

        partition = re.search(r"/hiberfil_([vp\d]+)\.raw$", archive)
        partition = partition.group(1)
        hiber_output = os.path.join(self.myconfig('outdir'), "data_{}.txt".format(partition))

        self.logger().debug("Extracting information from {}".format(archive.split(self.myconfig('outputdir'))[-1]))

        with open(hiber_output, "a") as f:
            for plugin in plugins:
                self.logger().debug("Plugin {}".format(plugin))
                output = subprocess.check_output([self.volatility, "--profile={}".format(profile), "-f", archive, plugin]).decode()
                f.write("*********** {} ************\n{}\n".format(plugin, output))

    def get_win_profile(self, partition):
        """ Gets volatility profile and windows version from reg_Info file

        Args:
            partition (str): partition number to get volatility profile

        returns:
            tuple: tuple of volatility profile and windows version
        """
        profile = {}
        profile["10.0x64"] = "Win10x64"
        profile["10.0.10240x64"] = "Win10x64_10240_17770"
        profile["10.0.10586x64"] = "Win10x64_10586"
        profile["10.0.14393x64"] = "Win10x64_14393"
        profile["10.0.15063x64"] = "Win10x64_15063"
        profile["10.0.16299x64"] = "Win10x64_16299"
        profile["10.0.17134x64"] = "Win10x64_17134"
        profile["10.0.17763x64"] = "Win10x64_17763"
        profile["10.0.18362x64"] = "Win10x64_18362"
        profile["10.0.19041x64"] = "Win10x64_19041"
        profile["10.0x86"] = "Win10x86"
        profile["10.0.10240x86"] = "Win10x86_10240_17770"
        profile["10.0.10586x86"] = "Win10x86_10586"
        profile["10.0.14393x86"] = "Win10x86_14393"
        profile["10.0.15063x86"] = "Win10x86_15063"
        profile["10.0.16299x86"] = "Win10x86_16299"
        profile["10.0.17134x86"] = "Win10x86_17134"
        profile["10.0.17763x86"] = "Win10x86_17763"
        profile["10.0.18362x86"] = "Win10x86_18362"
        profile["10.0.19041x86"] = "Win10x86_19041"
        profile["6.3.9600x64"] = "Win8SP1x64"
        profile["6.3.9600x64"] = "Win81U1x64"
        profile["6.2.9200x64"] = "Win8SP0x64"
        profile["6.3.9600x86"] = "Win8SP1x86"
        profile["6.3.9600x86"] = "Win81U1x86"
        profile["6.2.9200x86"] = "Win8SP0x86"
        profile["6.1.7601x64"] = "Win7SP1x64"
        profile["6.1.7600x64"] = "Win7SP0x64"
        profile["6.1.7601x86"] = "Win7SP1x86"
        profile["6.1.7600x86"] = "Win7SP0x86"
        profile["6.0.6000x64"] = "VistaSP0x64"
        profile["6.0.6001x64"] = "VistaSP1x64"
        profile["6.0.6002x64"] = "VistaSP2x64"
        profile["6.0.6000x86"] = "VistaSP0x86"
        profile["6.0.6001x86"] = "VistaSP1x86"
        profile["6.0.6002x86"] = "VistaSP2x86"
        profile["5.2.3790x64"] = "Win2003SP2x64"
        profile["5.2.3790x86"] = "Win2003SP2x86"
        profile["5.1.2600x64"] = "WinXPSP3x64"
        profile["5.1.2600x86"] = "WinXPSP3x86"

        os_version = CharacterizeWindows(config=self.config).get_windows_version(partition=partition)
        architecture = "x64" if os_version.get('ProcessorArchitecture', '').lower() == 'amd64' else "x86"
        prof = "{}.{}{}".format(os_version.get("Version", ""), os_version.get("BuildNumber", ""), architecture)
        if prof not in profile.keys():
            prof = "{}{}".format(os_version.get("Version", ""), architecture)
            if prof not in profile.keys():
                raise base.job.RVTError("Windows version not in the profiles list: {}".format(str(os_version)))

        return profile[prof], prof

    def _check_version(self, profile, file, hiber_raw):
        if profile.startswith('Win10') or profile.startswith('Win8'):
            raise base.job.RVTError("{} could not be descompressed with a linux distro. Descompress with Windows 8 o higher hiberfil.sys file using https://arsenalrecon.com/weapons/hibernation-recon/. Save output at {}".format(file, hiber_raw))
        return
