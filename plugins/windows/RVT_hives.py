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
import dateutil.parser
import shlex
import shutil
from collections import OrderedDict
from Registry import Registry
from Registry.RegistryParse import parse_windows_timestamp as _parse_windows_timestamp
from tqdm import tqdm

from plugins.external import jobparser
import base.job
from base.utils import check_directory, save_csv, relative_path, windows_format_path
from base.commands import run_command, yield_command
from plugins.common.RVT_files import GetTimeline
from plugins.windows.RVT_os_info import CharacterizeWindows


def parse_windows_timestamp(value):
    try:
        return _parse_windows_timestamp(value)
    except ValueError:
        return datetime.datetime.min


WINDOWS_TIMESTAMP_ZERO = parse_windows_timestamp(0).strftime("%Y-%m-%d %H:%M:%S")


def get_hives(path):
    """ Obtain the paths to all registry hives files present in a directory specified by `path`.

    Arguments:
        path (str): Hives location directory. Expected inputs:
            - Directory where registry hive files are stored, such as 'Windows/System32/config/' or 'Windows/AppCompat/Programs/'
            - Main volume directory --> Root directory, where 'Documents and Settings' or 'Users' folders are expected
            - Custom folder containing hives. Warning: 'ntuser.dat' are expected to be stored in a username folder.

    Returns:
        regfiles (dict): Dictionary where keys are hive related names and values are the absolute paths to those hives.
            In case of ntuser and usrclass hives, they are organized by username
    """
    regfiles = {}

    # Common Hives
    hive_names = {
        'system': 'system',
        'software': 'software',
        'sam': 'sam',
        'security': 'security',
        'amcache.hve': 'amcache',
        'syscache.hve': 'syscache'}

    # Search only first level, not subfolders. File nams MUST BE the expected Windows hives names. If names had been changed, they will be ommited
    for file in os.listdir(path):
        for hive_file, hive_name in hive_names.items():
            if file.lower() == hive_file:
                regfiles[hive_name] = os.path.join(path, file)

    # User hives
    usr = []
    regfiles["ntuser"] = {}
    regfiles["usrclass"] = {}

    # Recursive search in subdirectories. Username will be taken from the directory name where hive is found
    for root, dirs, files in os.walk(path):
        for file in files:
            for hve, hve_name in zip(['ntuser.dat', 'usrclass.dat'], ['ntuser', 'usrclass']):
                if file.lower() == hve:
                    user = relative_path(root, path).split('/')[0]
                    if user not in regfiles[hve_name]:
                        regfiles[hve_name][user] = os.path.join(root, file)
                        usr.append(user)

    if not regfiles['ntuser'] and not regfiles['usrclass']:
        del regfiles['ntuser']
        del regfiles['usrclass']

    return regfiles


class Amcache(base.job.BaseModule):
    """ Parses Amcache.hve registry hive. """

    def read_config(self):
        super().read_config()
        self.set_default_config('path', '')
        self.set_default_config('volume_id', '')

    def run(self, path=""):
        self.check_params(path, check_path=True, check_path_exists=True)
        self.amcache_path = path

        # Determine output filename
        id = self.myconfig('volume_id', None)
        self.partition = id if id else 'p01'  # needed to get OS info
        vss = self.myflag('vss')
        outfolder = self.myconfig('voutdir') if vss else self.myconfig('outdir')
        check_directory(outfolder, create=True)
        self.outfile = os.path.join(outfolder, 'amcache{}.txt'.format('_{}'.format(id) if id else ''))

        self.logger().debug("Parsing {}".format(self.amcache_path))

        try:
            reg = Registry.Registry(self.amcache_path)
            entries = self.parse_amcache_entries(reg)
            save_csv(entries, outfile=self.outfile, file_exists='OVERWRITE', quoting=0)
        except KeyError:
            self.logger().warning("Expected subkeys not found in hive file: {}".format(self.amcache_path))
        except Exception as exc:
            self.logger().warning("Problems parsing: {}. Error: {}".format(self.amcache_path, exc))

        self.logger().debug("Amcache.hve parsing finished")
        return []

    def parse_amcache_entries(self, registry):
        """ Return a generator of dictionaries describing each entry in the hive.

        Fields:
            * KeyLastWrite: Possible application first executed time (must be tested)
            * AppPath: application path inside the volume
            * AppName: friendly name for application, if any
            * Sha1Hash: binary file SHA-1 hash value
            * Created: file creation time
            * LastModified: file modificatin time
            * GUID: Volume GUID the application was executed from
        """

        # Hive subkeys may have different relevant subkeys depending on OS version.
        # File amcache.hve appears on Windows 8. Previous versions used the RecentFileCache.bcf. Use job windows.execution for parsing this file
        #   * {GUID}\\Root\\File
        #   * {GUID}\\Root\\Programs
        #   * {GUID}\\Root\\InventoryApplication
        #   * {GUID}\\Root\\InventoryApplicationFile
        entries_by_version = {
            'Windows 10': {
                '1507': ['Programs', 'File'],
                '1511': ['Programs', 'File'],
                '1607': ['InventoryApplication', 'InventoryApplicationFile'],
                '1703': ['InventoryApplication', 'InventoryApplicationFile'],
                '1709': ['InventoryApplication', 'InventoryApplicationFile'],
                '1803': ['InventoryApplication', 'InventoryApplicationFile'],
                '1809': ['InventoryApplication', 'InventoryApplicationFile'],
                'default': ['InventoryApplication', 'InventoryApplicationFile'],
            },
            'Windows Server 2012': {
                '': ['File'],
                'R2': ['File']
            },
            'Windows Server 2016': {
                '1607': ['InventoryApplication', 'InventoryApplicationFile'],
                '1709': ['InventoryApplication', 'InventoryApplicationFile']
            },
            'Windows Server 2019': {'1809': ['InventoryApplication', 'InventoryApplicationFile']},
            'Windows 8': {'': ['File']},
            'Windows 8.1': {'': ['File']},
            'Windows 7': {'default': ['InventoryApplication', 'InventoryApplicationFile']}
        }
        structures = {
            'File': self._parse_File_entries,
            'Programs': self._parse_Programs_entries,
            'InventoryApplication': self._parse_IA_entries,
            'InventoryApplicationFile': self._parse_IAF_entries
        }

        os_version = CharacterizeWindows(config=self.config).get_windows_version(partition=self.partition)
        if os_version['Name']:
            self.logger().debug('Processing OS version {} {} {}'.format(os_version['Name'], os_version['SubVersion'], os_version['BuildNumber']))
        version_to_search = entries_by_version.get(os_version['Name'], {'default': ['InventoryApplication', 'InventoryApplicationFile', 'Programs', 'File']})
        if os_version['SubVersion'] in version_to_search:
            keys_to_search = version_to_search[os_version['SubVersion']]
        else:
            keys_to_search = version_to_search['default']
        if not keys_to_search:
            self.logger().info('Version {} has no known amcache keys'.format(os_version['Name']))
            raise KeyError

        # Parse every relevant key
        found_key = None
        for key in keys_to_search:
            try:
                volumes = registry.open("Root\\{}".format(key))
                found_key = key
                self.logger().debug('Parsing entries in key: Root\\{}'.format(key))
                for app in structures[key](volumes):
                    yield app
            except Registry.RegistryKeyNotFoundException:
                self.logger().debug('Key "Root\\{}" not found'.format(key))
            except Exception as exc:
                self.logger().warning(exc)

        if not found_key:
            raise KeyError('None of the subkeys found in Amcache')

    def _parse_File_entries(self, volumes):
        """ Parses File subkey entries for amcache hive """

        fields = {'LastModified': "17", 'Created': "12", 'AppPath': "15", 'AppName': "0", 'Sha1Hash': "101"}
        for volumekey in volumes.subkeys():
            for filekey in volumekey.subkeys():
                app = OrderedDict([('KeyLastWrite', WINDOWS_TIMESTAMP_ZERO), ('AppName', ''), ('AppPath', ''),
                                   ('ProgramId', ''), ('Sha1Hash', ''), ('Version', ''), ('Size', ''),
                                   ('Created', ''), ('LastModified', ''), ('Installed', ''), ('Uninstalled', ''), ('LinkDate', ''),
                                   ('GUID', ''), ('Subkey', 'File')])
                app['GUID'] = volumekey.path().split('}')[0][1:]
                app['KeyLastWrite'] = filekey.timestamp()
                for f in fields:
                    try:
                        val = filekey.value(fields[f]).value()
                        if f == 'Sha1Hash':
                            val = val[4:]
                        elif f in ['LastModified', 'Created']:
                            val = parse_windows_timestamp(val).strftime("%Y-%m-%d %H:%M:%S")
                        app.update({f: val})
                    except Registry.RegistryValueNotFoundException:
                        pass
                yield app

    def _parse_Programs_entries(self, volumes):
        """ Parses Programs subkey entries for amcache hive """

        fields = {'AppName': "0", 'AppPath': "d", 'Version': "1", 'Installed': "a", 'Uninstalled': "b"}
        for volumekey in volumes.subkeys():
            for filekey in volumekey.subkeys():
                app = OrderedDict([('KeyLastWrite', WINDOWS_TIMESTAMP_ZERO), ('AppName', ''), ('AppPath', ''),
                                   ('ProgramId', ''), ('Sha1Hash', ''), ('Version', ''), ('Size', ''),
                                   ('Created', ''), ('LastModified', ''), ('Installed', ''), ('Uninstalled', ''), ('LinkDate', ''),
                                   ('GUID', ''), ('Subkey', 'Programs')])
                app['GUID'] = volumekey.path().split('}')[0][1:]
                app['KeyLastWrite'] = filekey.timestamp()
                for f in fields:
                    try:
                        val = filekey.value(fields[f]).value()
                        if f in ['Installed', 'Uninstalled']:
                            val = datetime.datetime.fromtimestamp(int(val)).strftime("%Y-%m-%d %H:%M:%S")
                        app.update({f: val})
                    except Registry.RegistryValueNotFoundException:
                        pass
                yield app

    def _parse_IA_entries(self, volumes):
        """ Parses InventoryApplication subkey entries for amcache hive """

        names = {'RootDirPath': 'AppPath',
                 'InstallDate': 'Installed',
                 'ProgramId': 'ProgramId',
                 'ProgramInstanceId': 'Sha1Hash',
                 'Name': 'AppName',
                 'Version': 'Version'}

        for volumekey in volumes.subkeys():
            app = OrderedDict([('KeyLastWrite', WINDOWS_TIMESTAMP_ZERO), ('AppName', ''), ('AppPath', ''),
                               ('ProgramId', ''), ('Sha1Hash', ''), ('Version', ''), ('Size', ''),
                               ('Created', ''), ('LastModified', ''), ('Installed', ''), ('Uninstalled', ''), ('LinkDate', ''),
                               ('GUID', ''), ('Subkey', 'InventoryApplication')])
            app['GUID'] = volumekey.path().split('}')[0][1:]
            app['KeyLastWrite'] = volumekey.timestamp()
            for v in volumekey.values():
                if v.name() in ['RootDirPath', 'Name', 'Version']:
                    app.update({names.get(v.name(), v.name()): v.value()})
                elif v.name() in ['ProgramID', 'ProgramInstanceId']:
                    sha = v.value()[4:]  # SHA-1 hash is registered 4 0's padded
                    app.update({names.get(v.name(), v.name()): sha})
                elif v.name() == 'InstallDate':
                    install_date = ''
                    if v.value():
                        install_date = datetime.datetime.strptime(v.value(), "%m/%d/%Y %H:%M:%S").strftime("%Y-%m-%dT%H:%M:%SZ")
                    app.update({names.get(v.name(), v.name()): install_date})
            yield app

    def _parse_IAF_entries(self, volumes):
        """ Parses InventoryApplicationFile subkey entries for amcache hive."""

        names = {'LowerCaseLongPath': 'AppPath',
                 'FileId': 'Sha1Hash',
                 'ProductName': 'AppName',
                 'Size': 'Size',
                 'ProgramId': 'ProgramId',
                 'LinkDate': 'LinkDate',
                 'Version': 'Version'}

        for volumekey in volumes.subkeys():
            app = OrderedDict([('KeyLastWrite', WINDOWS_TIMESTAMP_ZERO), ('AppName', ''), ('AppPath', ''),
                               ('ProgramId', ''), ('Sha1Hash', ''), ('Version', ''), ('Size', ''),
                               ('Created', ''), ('LastModified', ''), ('Installed', ''), ('Uninstalled', ''), ('LinkDate', ''),
                               ('GUID', ''), ('Subkey', 'InventoryApplicationFile')])
            app['GUID'] = volumekey.path().split('}')[0][1:]
            app['KeyLastWrite'] = volumekey.timestamp()
            for v in volumekey.values():
                if v.name() in ['LowerCaseLongPath', 'ProductName', 'Size']:
                    app.update({names.get(v.name(), v.name()): v.value()})
                elif v.name() in ['FileId', 'ProgramId']:
                    sha = v.value()[4:]  # SHA-1 hash is registered 4 0's padded
                    app.update({names.get(v.name(), v.name()): sha})
                elif v.name() == 'LinkDate':
                    link_date = ''
                    if v.value():
                        link_date = datetime.datetime.strptime(v.value(), "%m/%d/%Y %H:%M:%S").strftime("%Y-%m-%dT%H:%M:%SZ")
                    app.update({names.get(v.name(), v.name()): link_date})
            yield app


class ShimCache(base.job.BaseModule):
    """ Extracts ShimCache information from registry hives. """

    # TODO: .sdb shim database files (ex: Windows/AppPatch/sysmain.sdb)

    def read_config(self):
        super().read_config()
        self.set_default_config('path', '')
        self.set_default_config('volume_id', '')

    def run(self, path=""):
        self.check_params(path, check_path=True, check_path_exists=True)
        self.shimcache_path = path

        # Determine output filename
        id = self.myconfig('volume_id', None)
        vss = self.myflag('vss')
        outfolder = self.myconfig('voutdir') if vss else self.myconfig('outdir')
        check_directory(outfolder, create=True)
        self.outfile = os.path.join(outfolder, 'shimcache{}.txt'.format('_{}'.format(id) if id else ''))

        self.logger().debug("Parsing shimcache on {}".format(self.shimcache_path))
        save_csv(self.parse_ShimCache_hive(self.shimcache_path), outfile=self.outfile, file_exists='OVERWRITE', quoting=0)
        self.logger().debug("Finished extraction from ShimCache")

        return []

    def parse_ShimCache_hive(self, sysfile):
        """ Launch shimcache regripper plugin and parse results """
        ripcmd = self.config.get('plugins.common', 'rip', '/opt/regripper/rip.pl')
        date_regex = re.compile(r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}')

        res = run_command([ripcmd, "-r", sysfile, "-p", "shimcache"], logger=self.logger())
        for line in res.split('\n'):
            if ':' not in line[:4]:
                continue
            matches = re.search(date_regex, line)
            if matches:
                path = line[:matches.span()[0] - 2]
                date = str(datetime.datetime.strptime(matches.group(), '%Y-%m-%d %H:%M:%S'))
                executed = bool(len(line[matches.span()[1]:]))
                yield OrderedDict([('LastModified', date), ('AppPath', path), ('Executed', executed)])


class SysCache(base.job.BaseModule):
    """ Parse SysCache registry hive """

    def read_config(self):
        super().read_config()
        self.set_default_config('path', '')
        self.set_default_config('volume_id', '')

    def run(self, path=""):
        self.check_params(path, check_path=True, check_path_exists=True)

        # Determine output filename
        id = self.myconfig('volume_id', None)
        vss = self.myflag('vss')
        self.partition = id if id else 'p01'  # needed to get inode information
        outfolder = self.myconfig('voutdir') if vss else self.myconfig('outdir')
        check_directory(outfolder, create=True)
        self.outfile = os.path.join(outfolder, 'syscache{}.csv'.format('_{}'.format(id) if id else ''))

        self.logger().debug("Parsing SysCache hive: {}".format(path))
        save_csv(self.parse_SysCache_hive(path), outfile=self.outfile, file_exists='OVERWRITE', quoting=0)
        self.logger().debug("Finished extraction from SysCache")

        return []

    def parse_SysCache_hive(self, path):
        """ Use syscache_csv plugin from regripper to parse SysCache hive """
        ripcmd = self.config.get('plugins.common', 'rip', '/opt/regripper/rip.pl')
        output_text = run_command([ripcmd, "-r", path, "-p", "syscache_csv"], logger=self.logger())

        try:
            timeline = GetTimeline(config=self.config)
        except IOError:
            timeline = None

        for line in output_text.split('\n')[:-1]:
            line = line.split(",")
            fileID = line[1]
            inode = line[1].split('/')[0]
            # Get filename from inode if timeline is present
            name = '' if not timeline else timeline.get_path_from_inode(inode, partition=self.partition)
            try:
                yield OrderedDict([("Date", dateutil.parser.parse(line[0]).strftime("%Y-%m-%dT%H:%M:%SZ")),
                                   ("Name", name), ("FileID", fileID), ("Sha1", line[2])])
            except Exception:
                yield OrderedDict([("Date", dateutil.parser.parse(line[0]).strftime("%Y-%m-%dT%H:%M:%SZ")),
                                   ("Name", name), ("FileID", fileID), ("Sha1", "")])


class AppCompat(base.job.BaseModule):
    """ Get application executed. The timestamp recorded by Windows is the $SI Modification Time, not the execution time """
    # TODO, obtain the executed flag. appcompatcache plugin does not show it

    def read_config(self):
        super().read_config()
        self.set_default_config('path', '')
        self.set_default_config('volume_id', '')
        self.set_default_config('cmd', '')
        self.set_default_config('executable', os.path.join(self.config.config['plugins.windows']['windows_tools_dir'], 'AppCompatCacheParser.exe'))

    def run(self, path=""):
        # Take path from params if not provided as an argument
        if not path:
            path = self.myconfig('path')
        # self.check_params(path, check_path=True, check_path_exists=True)

        # Determine output filename
        id = self.myconfig('volume_id', None)
        vss = self.myflag('vss')
        outfolder = self.myconfig('voutdir') if vss else self.myconfig('outdir')
        check_directory(outfolder, create=True)
        self.outfile = os.path.join(outfolder, 'appcompatcache2{}.csv'.format('_{}'.format(id) if id else ''))

        cmd = self.myconfig('cmd', None)
        self.logger().debug("Parsing appcompatcache on registry hive {}".format(path))
        if not cmd:
            # Use regripper appcompatcache plugin to parse
            save_csv(self.parse_appcompatcache(path), outfile=self.outfile, file_exists='OVERWRITE', quoting=0)
        else:
            # Use the specified command to parse
            cmd_vars = {'executable': windows_format_path(self.myconfig('executable'), enclosed=True),
                        'path': windows_format_path(path, enclosed=True),
                        'outdir': windows_format_path(self.myconfig('outdir'), enclosed=True),
                        'filename': os.path.basename(self.outfile)}
            cmd_args = shlex.split(cmd.format(**cmd_vars))
            run_command(cmd_args)

            # Assuming AppCompatCacheParser is used, rearrange the default output
            tmp_file = os.path.join(os.path.dirname(self.outfile), 'temp_' + os.path.basename(self.outfile))
            run_command("rg -v ',True' {} | awk -F, '{{ print $4\";\"$3\";\"$2\";\"$5 }}' > {}".format(self.outfile, tmp_file))
            run_command('mv {} {}'.format(tmp_file, self.outfile))

        self.logger().debug("Finished extraction from AppCompatCache")

        return []

    # def rnu2(self, path=""):
    #     # Take path from params if not provided as an argument
    #     if not path:
    #         path = self.myconfig('path')
    #
    #     id = self.myconfig('volume_id', None)  # Volume identifier
    #     check_directory(self.myconfig('outdir'), create=True)
    #
    #     cmd = self.myconfig('cmd', None)
    #
    #
    #         output_filename = 'userassist_{}{}.csv'.format(user, '_{}'.format(id) if id else '')
    #         hive = regfiles['ntuser'][user]
    #
    #         cmd_vars = {'executable': windows_format_path(self.myconfig('executable'), enclosed=True),
    #                     'batch_file': windows_format_path(self.myconfig('batch_file'), enclosed=True),
    #                     'hive': windows_format_path(hive, enclosed=True),
    #                     'outdir': windows_format_path(self.myconfig('outdir'), enclosed=True),
    #                     'filename': output_filename}
    #         cmd_args = shlex.split(cmd.format(**cmd_vars))
    #
    #         run_command(cmd_args)
    #         # RECmd.exe creates two files. We only care about the one ending in `UserAssist.csv`
    #         try:
    #             if os.path.exists(os.path.join(self.myconfig('outdir'), output_filename[:-4] + '_UserAssist.csv')):
    #                 shutil.move(os.path.join(self.myconfig('outdir'), output_filename[:-4] + '_UserAssist.csv'),
    #                             os.path.join(self.myconfig('outdir'), output_filename))
    #         except Exception as exc:
    #             raise base.job.RVTError(exc)
    #
    #     return []



    def parse_appcompatcache(self, path):
        """ Use appcompatcache plugin from regripper to parse AppCompatCache key in SYSTEM hive """
        ripcmd = self.config.get('plugins.common', 'rip', '/opt/regripper/rip.pl')
        line_number = 0
        start = 1000
        result = {}
        for line in yield_command([ripcmd, "-r", path, "-p", "appcompatcache"], logger=self.logger()):
            line_number += 1
            if line_number < 5:
                continue
            if line_number > start:
                last_modified = line[-20:].strip()
                # Some entries do not include a time. Process them apart
                if not self._check_valid_time(last_modified):
                    result['Time'] = ''
                    result['Application'] = line.replace('\\', '/').strip()
                    yield result
                else:
                    # The rest have a last modified UTC time
                    result['Time'] = last_modified
                    result['Application'] = line[:-22].replace('\\', '/')
                    yield result
            if line.startswith('LastWrite Time'):
                start = line_number + 1

        return []

    def _check_valid_time(self, time_str, format="%Y-%m-%d %H:%M:%S"):
        try:
            datetime.datetime.strptime(time_str, format)
            return True
        except Exception:
            return False


class ScheduledTasks(base.job.BaseModule):
    """ Parses job files and schedlgu.txt. """

    def run(self, path=""):
        self.check_params(path, check_path=True, check_path_exists=True)
        self.st_dir = path
        self.volume_id = self.myconfig('volume_id')
        # Try to guess volume id/partition from path
        if not self.volume_id:
            assumed_location = os.path.join(self.myconfig('casedir'), self.myconfig('source'), 'mnt')
            if path.find(assumed_location) != -1:
                self.volume_id = path[len(assumed_location) + 1:].split('/')[0]

        self.vss = self.myflag('vss')
        self.outfolder = self.myconfig('voutdir') if self.vss else self.myconfig('outdir')
        check_directory(self.outfolder, create=True)

        self.logger().debug("Parsing artifacts from scheduled tasks files (.job)")
        outfile_jobs = os.path.join(self.outfolder, "jobs_files_{}.csv".format(self.volume_id))
        save_csv(self.parse_Task(), outfile=outfile_jobs, file_exists='APPEND', quoting=0)

        self.logger().debug("Parsing artifacts from Task Scheduler Service log files (schedlgu.txt)")
        outfile_sched = os.path.join(self.outfolder, 'schedlgu_{}.csv'.format(self.volume_id))
        save_csv(self.parse_schedlgu(), config=self.config,
                 outfile=outfile_sched, file_exists='APPEND', quoting=0)
        self.parse_schedlgu()
        return []

    def parse_Task(self):
        """ Parse .job files """
        jobs_files = [os.path.join(self.st_dir, file) for file in os.listdir(self.st_dir) if file.endswith('.job')]

        for file in jobs_files:
            with open(file, "rb") as f:
                data = f.read()
            # Every .job file is a task
            job = jobparser.Job(data)
            yield OrderedDict([("Product Info", jobparser.products.get(job.ProductInfo)),
                               ("File Version", job.FileVersion),
                               ("UUID", job.UUID),
                               ("Maximum Run Time", job.MaxRunTime),
                               ("Exit Code", job.ExitCode),
                               ("Status", jobparser.task_status.get(job.Status, "Unknown Status")),
                               ("Flasgs", job.Flags_verbose),
                               ("Date Run", job.RunDate),
                               ("Running Instances", job.RunningInstanceCount),
                               ("Application", "{} {}".format(job.Name, job.Parameter)),
                               ("Working Directory", job.WorkingDirectory),
                               ("User", job.User),
                               ("Comment", job.Comment),
                               ("Scheduled Date", job.ScheduledDate)])

        self.logger().debug("Finished extraction from scheduled tasks .job")

    def parse_schedlgu(self):
        """ Parse SCHEDLGU.TXT files """
        sched_files = [os.path.join(self.st_dir, file) for file in os.listdir(self.st_dir) if file.lower().endswith('schedlgu.txt')]

        for file in sched_files:
            with open(file, 'r', encoding='utf16') as sched:
                dates = {'start': WINDOWS_TIMESTAMP_ZERO, 'end': WINDOWS_TIMESTAMP_ZERO}
                parsed_entry = False
                for line in sched:
                    if line == '\n':
                        continue
                    elif line.startswith('"'):
                        service = line.rstrip('\n').strip('"')
                        if parsed_entry:
                            yield OrderedDict([('Service', service), ('Started', dates['start']), ('Finished', dates['end'])])
                        parsed_entry = False
                        dates = {'start': WINDOWS_TIMESTAMP_ZERO, 'end': WINDOWS_TIMESTAMP_ZERO}
                        continue
                    for state, words in {'start': ['Started', 'Iniciado'], 'end': ['Finished', 'Finalizado']}.items():
                        for word in words:
                            if line.startswith('\t{}'.format(word)):
                                try:
                                    dates[state] = dateutil.parser.parse(line[re.search(r'\d', line).span()[0]:].rstrip('\n')).strftime("%Y-%m-%d %H:%M:%S")
                                    parsed_entry = True
                                except Exception:
                                    pass
                                break

        self.logger().debug("Finished extraction from schedlgu.txt")


class UserAssist(base.job.BaseModule):
    """ Parses UserAssist registry key in NTUSER.DAT hive.

    Configuration section:
        - **cmd**: external command to parse userassist. It is a Python string template accepting variables "executable", "hive", "outdir", "filename" and "batch_file". Variables "hive" and "file
name" are automatically set by the job. The rest are the same ones specified in parameters
        - **executable**: path to executable app to parse UserAssist. By default is using RECmd.exe. See (https://ericzimmerman.github.io/#!index.md)
        - **batch_file**: configuration file that settles the registry keys to be parsed. Relative to `windows_tools_dir`
    """

    def read_config(self):
        super().read_config()
        self.set_default_config('cmd', 'env WINEDEBUG=fixme-all wine {executable} --bn {batch_file} -f {hive} --csv {outdir} --csvf {filename} --nl')
        self.set_default_config('executable', os.path.join(self.config.config['plugins.windows']['windows_tools_dir'], 'RegistryExplorer/RECmd.exe'))
        self.set_default_config('batch_file', os.path.join(self.config.config['plugins.windows']['windows_tools_dir'], 'RegistryExplorer/BatchExamples/BatchExampleUserAssist.reb'))

    def run(self, path=""):

        # Take path from params if not provided as an argument
        if not path:
            path = self.myconfig('path')

        regfiles = get_hives(path)

        id = self.myconfig('volume_id', None)  # Volume identifier
        if not regfiles:
            self.logger().warning('No valid registry hives provided')
            return []

        check_directory(self.myconfig('outdir'), create=True)

        cmd = self.myconfig('cmd')

        for user in tqdm(regfiles['ntuser'], total=len(regfiles['ntuser']), desc=self.section):
            output_filename = 'userassist_{}{}.csv'.format(user, '_{}'.format(id) if id else '')
            hive = regfiles['ntuser'][user]

            cmd_vars = {'executable': windows_format_path(self.myconfig('executable'), enclosed=True),
                        'batch_file': windows_format_path(self.myconfig('batch_file'), enclosed=True),
                        'hive': windows_format_path(hive, enclosed=True),
                        'outdir': windows_format_path(self.myconfig('outdir'), enclosed=True),
                        'filename': output_filename}
            cmd_args = shlex.split(cmd.format(**cmd_vars))

            run_command(cmd_args)
            # RECmd.exe creates two files. We only care about the one ending in `UserAssist.csv`
            try:
                if os.path.exists(os.path.join(self.myconfig('outdir'), output_filename[:-4] + '_UserAssist.csv')):
                    shutil.move(os.path.join(self.myconfig('outdir'), output_filename[:-4] + '_UserAssist.csv'),
                                os.path.join(self.myconfig('outdir'), output_filename))
            except Exception as exc:
                raise base.job.RVTError(exc)

        return []


class UserAssistAnalysis(base.job.BaseModule):

    def run(self, path=""):
        """ Creates a report based on the output of UserAssist.

            Arguments:
                - ** path **: Path to directory where output files from UserAssist are stored
        """
        check_directory(path, error_missing=True)
        outfile = self.myconfig('outfile')
        check_directory(os.path.dirname(os.path.abspath(outfile)), create=True)

        save_csv(self.report_userassist(path), config=self.config, outfile=outfile, file_exists='OVERWRITE', quoting=0, encoding='utf-8')

        return []

    def report_userassist(self, path):
        """ Create a unique userassist csv for all users """

        fields = ["LastExecuted", "ProgramName", "RunCounter", "FocusCount", "FocusTime"]

        for file in sorted(os.listdir(path)):
            if file.startswith('userassist'):
                # Expected file format: `userassist_user_partition.csv`
                partition = file.split('_')[-1].split('.')[0]
                user = file[11:-(len(partition) + 5)]
                for line in base.job.run_job(self.config,
                                             'base.input.CSVReader',
                                             path=os.path.join(path, file),
                                             extra_config={'delimiter': ',', 'encoding': 'utf-8-sig'}):
                    res = OrderedDict([(field, line.get(field, '')) for field in fields])
                    res.update({'User': user, 'Partition': partition})
                    yield res


class Shellbags(base.job.BaseModule):
    """ Parses Shellbags registry key in NTUSER.DAT and/or usrclass.dat hive.

    Configuration section:
        - **cmd**: external command to parse shellbags. It is a Python string template accepting variables "executable", "hives_dir" and "outdir". Variable "hives_dir" is deduced by the job from "path". The rest are the same ones specified in parameters
        - **executable**: path to executable app to parse shellbags. By default is using SBECmd.exe. See (https://ericzimmerman.github.io/#!index.md)
    """

    def read_config(self):
        super().read_config()
        self.set_default_config('cmd', 'env WINEDEBUG=fixme-all wine {executable} -d {hives_dir} --csv {outdir} --nl --dedupe')
        self.set_default_config('executable', os.path.join(self.config.config['plugins.windows']['windows_tools_dir'], 'ShellBagsExplorer/SBECmd.exe'))

    def run(self, path=""):

        # Take path from params if not provided as an argument
        if not path:
            path = self.myconfig('path')

        # Get NTUSER.DAT and UsrClass.dat hives path for every user
        regfiles = get_hives(path)
        usr_folders = {}
        for user_hive in ['ntuser', 'usrclass']:
            for user, hive in regfiles.get(user_hive, {}).items():
                usr_folders[os.path.dirname(hive)] = user

        id = self.myconfig('volume_id', None)  # Volume identifier
        if not regfiles:
            self.logger().warning('No valid registry hives provided')
            return []

        check_directory(self.myconfig('outdir'), create=True)

        cmd = self.myconfig('cmd')

        for hives_dir in tqdm(usr_folders, total=len(usr_folders), desc=self.section):
            user = usr_folders[hives_dir]
            # Only one user should own a folder with NTUSER.dat or UsrClasss.dat hives. Will overwrite if not.
            output_filename = 'shellbags_{}{}.csv'.format(user, '_{}'.format(id) if id else '')

            cmd_vars = {'executable': windows_format_path(self.myconfig('executable'), enclosed=True),
                        'outdir': windows_format_path(self.myconfig('outdir'), enclosed=True),
                        'hives_dir': windows_format_path(hives_dir, enclosed=True)}
            cmd_args = shlex.split(cmd.format(**cmd_vars))
            run_command(cmd_args)

            # SBECmd.exe saves the output in a file called Deduplicated.csv. Change the name:
            if os.path.exists(os.path.join(self.myconfig('outdir'), 'Deduplicated.csv')):
                shutil.move(os.path.join(self.myconfig('outdir'), 'Deduplicated.csv'),
                            os.path.join(self.myconfig('outdir'), output_filename))

        # Remove summary file created by app
        os.remove(os.path.join(self.myconfig('outdir'), '!SBECmd_Messages.txt'))

        return []


class ShellbagsAnalysis(base.job.BaseModule):

    def run(self, path=""):
        """ Creates a report based on the output of Shellbags.

            Arguments:
                - ** path **: Path to directory where output files from Shellbags are stored
        """
        check_directory(path, error_missing=True)
        outfile = self.myconfig('outfile')
        check_directory(os.path.dirname(os.path.abspath(outfile)), create=True)

        save_csv(self.report_shellbags(path), config=self.config, outfile=outfile, file_exists='OVERWRITE', quoting=0, encoding='utf-8')

        return []

    def report_shellbags(self, path):
        """ Create a unique shellbags csv getting all users together """

        fields = ["LastWriteTime", "AbsolutePath", "FirstInteracted", "LastInteracted", "CreatedOn", "ModifiedOn", "AccessedOn", "HasExplored", "MFTEntry", "MFTSequenceNumber"]

        for file in sorted(os.listdir(path)):
            if file.startswith('shellbags'):
                # Expected file format: `shellbags_user_partition.csv`
                partition = file.split('_')[-1].split('.')[0]
                user = file[10:-(len(partition) + 5)]
                for line in base.job.run_job(self.config,
                                             'base.input.CSVReader',
                                             path=os.path.join(path, file),
                                             extra_config={'delimiter': ',', 'encoding': 'utf-8-sig'}):
                    res = OrderedDict([(field, line.get(field, '')) for field in fields])
                    res.update({'User': user, 'Partition': partition})
                    yield res


class TaskFolder(base.job.BaseModule):

    def run(self, path=""):
        """ Prints prefetch info from folder

        """
        print("Product Info|File Version|UUID|Maximum Run Time|Exit Code|Status|Flags|Date Run|Running Instances|Application|Working Directory|User|Comment|Scheduled Date")

        for fichero in os.listdir(path):
            if fichero.endswith(".job"):
                data = ""
                with open(os.path.join(path, fichero), "rb") as f:
                    data = f.read()
                job = jobparser.Job(data)
                print("{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}".format(jobparser.products.get(job.ProductInfo), job.FileVersion, job.UUID, job.MaxRunTime, job.ExitCode, jobparser.task_status.get(job.Status, "Unknown Status"),
                                                                         job.Flags_verbose, job.RunDate, job.RunningInstanceCount, "{} {}".format(job.Name, job.Parameter), job.WorkingDirectory, job.User, job.Comment, job.ScheduledDate))
