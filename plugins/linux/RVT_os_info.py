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

import ujson as json
import os
import re
import shlex
import subprocess
import base.job
import zoneinfo
from collections import defaultdict
from datetime import datetime, timezone
from base.utils import check_directory, date_to_iso, get_filehash


class CharacterizeLinux(base.job.BaseModule):
    """ Extract the essential information about Unix OS from several artifacts:
    - etc/os-release
    - etc/lsb-release
    - etc/centos-release
    - etc/hostname
    - etc/timezone
    - etc/localtime
    - proc/version
    - var/log/dmesg
    - var/log/installer/syslog
    - var/log/wtmp

    Creates a set of files in output/auxdir
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.aux_file = self.myconfig('aux_file')

    def read_config(self):
        super().read_config()
        self.set_default_config('aux_file', os.path.join(self.config.config['plugins.linux']['auxdir'], 'os_info.json'))

    def run(self, path=None):
        # Check if there's another characterize job running
        base.job.wait_for_job(self.config, self)

        # Some forensic acquisition tools (GRR) dump the artifacts different partition folders, but all refer to the same OS
        # TODO: define argument to admit this folder structure
        oneOS = False

        # Get OS information
        self.partitions = [folder for folder in sorted(os.listdir(self.myconfig('mountdir'))) if folder.startswith('p')]
        self.os_info = defaultdict(dict)
        for part in self.partitions:
            self.os_information(part, oneOS)

        # Save information in auxiliar file to be later accessed by other modules
        self.aux_file = self.myconfig('aux_file')
        aux_json_file_raw = '.'.join(self.aux_file.split('.')[:-1]) + '_raw.json'
        check_directory(os.path.dirname(self.aux_file), create=True)
        with open(self.aux_file, 'w') as outfile:
            json.dump(self.os_info, outfile, indent=4)
        with open(aux_json_file_raw, 'w') as outfile:
            json.dump(self.os_info, outfile)

        # The output dictionaries with os information are expected to be sent to a mako template
        return [dict(os_info=self.os_info, source=self.myconfig('source'))]

    def os_information(self, part, oneOS):
        """ Linux OS Information """
        partition = "p01" if oneOS else part
        part_path = os.path.join(self.myconfig('mountdir'), part)

        # etc/release
        release_dict = {
            "PRETTY_NAME": "ProductName",
            "NAME": "DistributionName",
            "VERSION": "CurrentVersion",
            "VERSION_ID": "CurrentVersionId",
            "VERSION_CODENAME": "DistributionCodename",
            "ID_LIKE": "BaseDistribution",
            "DISTRIB_RELEASE": "CurrentVersionId",
            "DISTRIB_CODENAME": "DistributionCodename",
            "DISTRIB_DESCRIPTION": "ProductName"
        }
        # Start by etc/os-release since it is present in most modern Linux distributions
        # Process Debian based etc/lsb-release the same way
        for dist_file in ["etc/os-release", "etc/lsb-release"]:
            if os.path.isfile(os.path.join(part_path, dist_file)) or os.path.islink(os.path.join(part_path, dist_file)):
                release_file = os.path.join(part_path, dist_file)
                if os.path.islink(release_file):
                    release_file = os.path.join(part_path, os.path.realpath(release_file))
                with open(release_file, 'r') as file:
                    for line in file:
                        values = line.strip().split("=")
                        try:
                            self.os_info[partition][release_dict.get(values[0], 'Delete')] = values[1].strip('"')
                        except Exception:
                            pass
        # Update with other distribution specific releases. Those files only include the ProductName
        release_file = ""
        if not (os.path.isfile(os.path.join(part_path, "etc/lsb-release")) or os.path.islink(os.path.join(part_path, "etc/lsb-release"))):
            if os.path.isdir(os.path.join(part_path, "etc")):
                for f in os.listdir(os.path.join(part_path, "etc")):
                    if f.endswith("-release"):
                        release_file = os.path.join(part_path, "etc", f)
        if release_file:
            with open(release_file, 'r') as file:
                for line in file:
                    if line:
                        self.os_info[partition]['ProductName'] = line.rstrip()

        # Combine and sanitize data
        if "CurrentVersion" not in self.os_info[partition]:
            self.os_info[partition]["CurrentVersion"] = self.os_info[partition].get("CurrentVersionId", "")
        if "ProductName" not in self.os_info[partition]:
            self.os_info[partition]["ProductName"] = self.os_info[partition].get("DistributionName", "")
        if self.os_info[partition]:
            self.os_info[partition].pop("CurrentVersionId", "")
            self.os_info[partition].pop("DistributionName", "")
            self.os_info[partition].pop("Delete", "")

        # etc/hostname
        target_file = os.path.join(part_path, "etc/hostname")
        if os.path.isfile(target_file):
            with open(target_file, "r") as file:
                self.os_info[partition]["ComputerName"] = file.read().rstrip()

        # Timezone data etc/timezone
        tz_string = ''
        target_file = os.path.join(part_path, "etc/timezone")
        if os.path.isfile(target_file):
            with open(target_file, "r") as file:
                tz_string = file.read().rstrip()
        else:
            # Timezone data etc/localtime
            target_file = os.path.join(part_path, "etc/localtime")
            if os.path.isfile(target_file):
                with open(os.path.join(self.config.get('linux', 'plugindir', './'), 'timezone_hashes.json')) as f:
                    timezone_hashes = json.load(f)
                localtime_hash = get_filehash(target_file)
                if localtime_hash in timezone_hashes:
                    tz_string = timezone_hashes[localtime_hash]
                    if tz_string.startswith('posix') or tz_string.startswith('right'):
                        tz_string = tz_string[6:]

        # Enrich the timezone name with the current UTC offset
        if tz_string:
            try:
                utc_offset_seconds = datetime.now(zoneinfo.ZoneInfo(tz_string)).utcoffset().total_seconds()
                hours, remainder = divmod(utc_offset_seconds, 3600)
                minutes = remainder // 60
                self.os_info[partition]["TimeZone"] = f'{tz_string} ({int(hours):+03}:{int(minutes):02})'
            except Exception as exc:
                self.logger().warning(f'Timezone not recognized: {tz_string}')
                self.os_info[partition]["TimeZone"] = tz_string

        # Linux Kernel Version proc/version
        target_file = os.path.join(part_path, "proc/version")
        if os.path.isfile(target_file):
            with open(target_file, "r") as file:
                for line in file:
                    aux = re.search(r"(Linux version [^\s]*)", line)
                    if aux:
                        self.os_info[partition]["LinuxKernelVersion"] = aux.group(1)
                        break

        # Linux Kernel var/log/dmesg
        target_file = os.path.join(part_path, "var/log/dmesg")
        if os.path.isfile(target_file) and not self.os_info[partition].get("LinuxKernelVersion"):
            with open(target_file, "r") as file:
                for line in file:
                    aux = re.search(r"(Linux version [^\s]*)", line)
                    if aux:
                        self.os_info[partition]["LinuxKernelVersion"] = aux.group(1)
                        break

        # Installation date var/log/installer/syslog
        if os.path.isfile(os.path.join(part_path, "var/log/installer/syslog")):
            creation_time = os.path.getctime(os.path.join(part_path, "var/log/installer/syslog"))
            self.os_info[partition]["InstallDate"] = datetime.fromtimestamp(creation_time, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        # Last Shutdown var/log/wtmp
        if os.path.isfile(os.path.join(part_path, "var/log/wtmp")):
            command = f"last -x shutdown -f {os.path.join(part_path, 'var/log/wtmp')} --time-format iso"
            args = shlex.split(command)
            tz = self.os_info[partition].get("TimeZone", "UTC")
            env = {'TZ': tz}
            process = subprocess.Popen(args, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            output_string = process.stdout.read().split('\n')

            last_shutdown_line = output_string[0]
            # Sample line format
            # shutdown system down  5.19.0-43-generi 2023-06-15T16:55:27+02:00 - 2023-06-16T09:10:17+02:00  (16:14)
            if last_shutdown_line.startswith("shutdown system down"):
                try:
                    from_time = datetime.fromisoformat(last_shutdown_line.split()[4])
                    to_time = datetime.fromisoformat(last_shutdown_line.split()[6])
                    last_shutdown_time = max(from_time, to_time)
                    self.os_info[partition]["ShutdownTime"] = date_to_iso(last_shutdown_time, input_timezone=tz, logger=self.logger()).replace("+00:00", "Z")
                except Exception:
                    pass

    def get_information(self, item, partition='p01'):
        """ Get selected OS or user information by reading a previously defined json file where information is stored """

        self.logger().debug(f'Getting {item} information about partition {partition}')
        os_info_keys = ["productname", "currentversion", "distributioncodename", "computername", "timezone", "linuxkernelversion", "installdate", "shutdowntime", "basedistribution"]
        if item.lower() in os_info_keys:
            default_output = ''
        else:
            raise base.job.RVTError(f'Selected item <{item}> is not a recognized OS attribute')

        # Parse the minimal information from hives if not done before
        if not os.path.exists(self.aux_file):
            self.run()
        info = self.load_saved_os_info()
        if info:
            return info.get(partition, defaultdict(dict)).get(item, default_output)

        return default_output

    def get_timezone(self, partition='p01'):
        tz_large = self.get_information("TimeZone", partition=partition)
        if tz_large:
            return tz_large.split()[0]
        self.logger().warning('No timezone info found in the machine. Using UTC as default')
        return 'UTC'

    def load_saved_os_info(self):
        """ Load all OS info data from a previously saved json file """
        if os.path.exists(self.aux_file) and os.path.getsize(self.aux_file) > 0:
            with open(self.aux_file, 'r') as infile:
                return json.load(infile)
        return {}


class Fstab(base.job.BaseModule):
    """ Extract the essential information about fstab file. """

    def read_config(self):
        super().read_config()

    def run(self, path=None):
        partitions_dict = {}
        for line in self.from_module.run(path):
            if line and not line.startswith('#'):
                data = line.split()
                group_entry_dict = {
                    "device": data[0],
                    "mount_point": data[1],
                    "type": data[2],
                    "options": data[3],
                    "backup": data[4],
                    "pass": data[5]
                }
                partitions_dict[group_entry_dict["device"]] = group_entry_dict

        # Save information in auxiliar file to be used by other modules
        aux_json_file = self.myconfig('aux_file')
        aux_json_file_raw = '.'.join(aux_json_file.split('.')[:-1]) + '_raw.json'
        check_directory(os.path.dirname(aux_json_file), create=True)

        with open(aux_json_file, 'w') as outfile:
            json.dump(partitions_dict, outfile, indent=4)
        with open(aux_json_file_raw, 'w') as outfile:
            json.dump(partitions_dict, outfile)

        return [dict(partitions=partitions_dict, source=self.myconfig('source'))]
