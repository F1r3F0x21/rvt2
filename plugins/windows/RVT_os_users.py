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
import datetime
import json
from collections import defaultdict
import base.job
from base.utils import check_directory, check_file

# TODO: Obtain last login from events instead of registry


class CharacterizeWindows(base.job.BaseModule):
    """ Extract summary info about Windows partitions Os general information and users.

    Timeline and Regripper output files must had been previously generated.

    Parameters:
        :ripplugins (str): path to json containing the list of essential plugins executed by 'autorip' job
    """

    def read_config(self):
        super().read_config()
        self.set_default_config('hivesdir', os.path.join(self.myconfig('outputdir'), 'windows', 'hives'))
        self.set_default_config('ripplugins', os.path.join(self.config.config['windows']['plugindir'], 'minimalrip.json'))

    def run(self, path=None):
        """ The output dictionaries with os information are expected to be sent to a mako template """

        self.partitions = [folder for folder in sorted(os.listdir(self.myconfig('mountdir'))) if folder.startswith('p')]
        # Get the autorip outputfile associated with each necessary plugin. Generate output if necessary
        self.get_ripplugins()
        used_plugins = ['winver2', 'shutdown', 'timezone', 'lastloggedon', 'processor_architecture', 'compname', 'samparse', 'profilelist']
        self.plugin_files = {plug: p['file'] for plug in used_plugins for p in self.ripplugins if plug in p['plugins']}
        # Define self.ntusers, that gets the creation date of NTUSER.DAT for every user and partition
        self.make_ntuser_timeline()
        self.os_info = defaultdict(dict)
        # Get OS and users information
        for part in self.partitions:
            self.os_information(part)
            self.users_information(part)

        self.logger().debug('Windows OS characterization finished')

        return [
            dict(os_info=self.os_info, source=self.myconfig('source'))
        ]

    def get_ripplugins(self):
        """ Get the autorip outputfile associated with each necessary plugin.
            If autorip results aren't found, generate a subsection of all plugins
        """
        self.hives_dir = self.myconfig('hivesdir')

        # Check registry is parsed. Generate the minimum files needed otherwise
        ripplugins_file = self.myconfig('ripplugins')
        if not check_directory(self.hives_dir):
            module = base.job.load_module(
                self.config,
                'plugins.windows.RVT_autorip.Autorip',
                extra_config=dict(path=self.myconfig('mountdir') + '/p*', ripplugins=ripplugins_file))
            list(module.run())

        with open(ripplugins_file) as rf:
            self.ripplugins = json.load(rf)

    def os_information(self, part):
        """ Characterize Windows partitions from registry files. """

        os_plugins = ['winver2', 'shutdown', 'timezone', 'lastloggedon', 'processor_architecture', 'compname']

        plugin_fields = {'winver2': ['ProductName', 'CurrentVersion', 'InstallationType', 'EditionID', 'CurrentBuild', 'ProductId', 'RegisteredOwner', 'RegisteredOrganization', 'InstallDate'],
                         'shutdown': ['ShutdownTime'],
                         'processor_architecture': ['PROCESSOR_ARCHITECTURE'],
                         'compname': ['ComputerName']}

        field_names = {'ProductName': 'ProductName', 'CurrentVersion': 'CurrentVersion', 'InstallationType': 'InstallationType',
                       'EditionID': 'EditionID', 'CurrentBuild': 'CurrentBuild', 'ProductId': 'ProductId', 'RegisteredOwner': 'RegisteredOwner',
                       'RegisteredOrganization': 'RegisteredOrganization', 'InstallDate': 'InstallDate', 'ShutdownTime': 'ShutdownTime',
                       '  TimeZoneKeyName': 'TimeZone', 'PROCESSOR_ARCHITECTURE': 'ProcessorArchitecture', 'ComputerName': 'ComputerName'}

        # Main loop to populate os_info
        for plug in os_plugins:
            hivefile = os.path.join(self.hives_dir, '{}_{}.txt'.format(self.plugin_files[plug], part))
            if not check_file(hivefile):
                continue
            with open(hivefile, 'r') as f_in:
                if plug == 'lastloggedon':
                    for line in f_in:
                        if line.startswith('LastLoggedOn'):
                            f_in.readline()
                            last_write = f_in.readline()[11:].rstrip('\n')
                            f_in.readline()
                            last_user = f_in.readline()[22:].rstrip('\n')
                            self.os_info[part]['LastLoggedOn'] = '{} ({})'.format(last_write, last_user)
                            break
                    continue
                elif plug == 'timezone':
                    for line in f_in:
                        if line.startswith('TimeZoneInformation'):
                            bias, tz_name = '', ''
                            while not line.startswith('....................') and line != "":
                                line = f_in.readline()
                                if line.startswith('  Bias'):
                                    bias = line[line.find('('):].rstrip('\n')
                                if line.startswith('  TimeZoneKeyName'):
                                    line = line[len('  TimeZoneKeyName') + 3:].rstrip('\n')
                                    tz_name = line[:line.find('Time') + 4]
                            self.os_info[part]['TimeZone'] = '{} {}'.format(tz_name, bias)
                            break
                    continue

                for field in plugin_fields[plug]:
                    f_in.seek(0)
                    for line in f_in:
                        if line.startswith(field):
                            if plug == 'compname':
                                self.os_info[part][field_names[field]] = line.split('= ')[1].rstrip('\n')
                            else:
                                self.os_info[part][field_names[field]] = line[len(field) + 3:].rstrip('\n')
                            break

    def users_information(self, part):
        """ Get Users general information in Windows partitions from registry files and timeline. """

        # Skip displaying partition info if it does not contain an OS
        if not self.os_info.get(part, None):
            self.logger().debug('No OS information for partition {}'.format(part))
            return

        line = '  '
        users = []
        user_profiles = []
        samparse_hivefile = os.path.join(self.hives_dir, '{}_{}.txt'.format(self.plugin_files['samparse'], part))
        profilelist_hivefile = os.path.join(self.hives_dir, '{}_{}.txt'.format(self.plugin_files['profilelist'], part))

        # Usually samparse and profilelist should be on the same outputfile, but treat it separately just in case
        if not check_file(samparse_hivefile) or not profilelist_hivefile:
            return

        # Parse samparse
        with open(samparse_hivefile) as f_in:
            # while not line.startswith('profilelist') and line != "":  ### NOOOO
            while not line.startswith('samparse'):  # anything before samparse uotput is ignored
                line = f_in.readline()

            while not line.startswith('.' * 20):   # a large line of points marks the end of the plugin output
                line = f_in.readline()
                aux = re.search(r"Username\s*:\s*(.*)\n", line)
                if aux:
                    user = [aux.group(1), "", ""]
                    while line != "\n":
                        line = f_in.readline()
                        aux = re.search(r"Account Created\s*:\s*(.*)\n", line)
                        if aux:
                            date = datetime.datetime.strptime(aux.group(1), '%Y-%m-%d %H:%M:%SZ')
                            user[1] = date.strftime('%Y-%m-%d %H:%M:%S')
                            continue
                        aux = re.search(r"Last Login Date\s*:\s*(.*)\n", line)  # TODO: check this field is reliable
                        if aux:
                            if aux.group(1).find("Never") == -1:
                                date = datetime.datetime.strptime(aux.group(1), '%Y-%m-%d %H:%M:%SZ')
                                user[2] = date.strftime('%Y-%m-%d %H:%M:%S')
                            else:
                                user[2] = "Never"
                            users.append(user)
                            break

        # Parse profilelist
        line = '  '
        with open(profilelist_hivefile) as f_in:
            while not line.startswith('profilelist'):  # anything before profilelist uotput is ignored
                line = f_in.readline()

            while not line.startswith('.' * 20):   # a large line of points marks the end of the plugin output
                line = f_in.readline()

            # while not line.startswith('....................') and line != "":   ### NOOOO
                # line = f_in.readline()
                aux = re.match(r"Path\s*:\s*.:.Users.(.*)", line.strip())
                if aux:
                    user = [aux.group(1), "", "", ""]  # username, creation_time, last_write, SID
                    while line != "\n":
                        line = f_in.readline()
                        sid_search = re.search(r"SID\s*:\s*(.*)", line.strip())
                        last_write_search = re.search(r"LastWrite\s*:\s*(.*)", line.strip())
                        if sid_search:
                            user[3] = sid_search.group(1)
                        elif last_write_search:
                            date = datetime.datetime.strptime(last_write_search.group(1), '%Y-%m-%d %H:%M:%SZ')
                            user[2] = date.strftime("%Y-%m-%d %H:%M:%S")
                            user_profiles.append(user)

        # Get creation date from NTUSER.DAT if not found in profilelist
        for i in user_profiles:
            for j in self.ntusers[part]:
                if i[0] == j[0] and i[1] == "":
                    i[1] = j[1].strftime('%Y-%m-%d %H:%M:%S')
        self.os_info[part]["users"] = users
        self.os_info[part]["user_profiles"] = user_profiles

    def make_ntuser_timeline(self):
        """ Get user creation date from the birth time of NTUSER.dat """

        timeline_file = os.path.join(self.config.get('plugins.common', 'timelinesdir'), '{}_TL.csv'.format(self.myconfig('source')))
        if not check_file(timeline_file):
            self.logger().warning('Timeline file not found: {}'.format(timeline_file))
            self.ntusers = {}
            return
        ntusers = defaultdict(list)
        with open(timeline_file, "r", encoding="iso8859-15") as tl_f:
            for line in tl_f:
                mo = re.search(r"mnt/(p\d+)/(?:Documents and settings|Users)/([^/]*)/(?:NTUSER|UsrClass)\.dat\"", line, re.IGNORECASE)
                if mo is not None:
                    part, user = mo.group(1), mo.group(2)
                    line = line.split(',')
                    if line[2][3] != 'b':
                        continue
                    if line[0].endswith("Z"):
                        date = datetime.datetime.strptime(line[0], '%Y-%m-%dT%H:%M:%SZ')
                    else:
                        date = datetime.datetime.strptime(line[0], '%Y %m %d %a %H:%M:%S')
                    if user not in ntusers[part]:
                        ntusers[part].append((user, date))

        self.ntusers = ntusers
