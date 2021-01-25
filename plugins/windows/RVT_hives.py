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

import csv
import os
import re
import datetime
import dateutil.parser
from collections import OrderedDict
from Registry import Registry
from Registry.RegistryParse import parse_windows_timestamp as _parse_windows_timestamp
from tqdm import tqdm

from plugins.external import jobparser
import base.job
from base.utils import check_directory, save_csv, relative_path
from base.commands import run_command, yield_command
from plugins.common.RVT_files import GetFiles
from plugins.common.RVT_filesystem import FileSystem
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

    def run(self, path=""):
        vss = self.myflag('vss')
        self.search = GetFiles(self.config, vss=vss)

        outfolder = self.myconfig('voutdir') if vss else self.myconfig('outdir')
        check_directory(outfolder, create=True)

        amcache_hives = [path] if path else self.search.search("Amcache.hve$")
        for am_file in amcache_hives:
            self.amcache_path = os.path.join(self.myconfig('casedir'), am_file)
            self.partition = am_file.split("/")[2]
            self.logger().debug("Parsing {}".format(am_file))
            self.outfile = os.path.join(outfolder, "amcache_{}.csv".format(self.partition))

            try:
                reg = Registry.Registry(os.path.join(self.myconfig('casedir'), am_file))
                entries = self.parse_amcache_entries(reg)
                save_csv(entries, outfile=self.outfile, file_exists='OVERWRITE', quoting=0)
            except KeyError:
                self.logger().warning("Expected subkeys not found in hive file: {}".format(am_file))
            except Exception as exc:
                self.logger().warning("Problems parsing: {}. Error: {}".format(am_file, exc))

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

        # Hive subkeys may have different relevant subkeys depending on OS version
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
            'Windows 8.1': {'': ['File']}
        }
        structures = {
            'File': self._parse_File_entries,
            'Programs': self._parse_Programs_entries,
            'InventoryApplication': self._parse_IA_entries,
            'InventoryApplicationFile': self._parse_IAF_entries
        }

        os_version = CharacterizeWindows(config=self.config).get_windows_version(partition=self.partition)
        self.logger().debug('Detected OS version {} {} {}'.format(os_version['Name'], os_version['SubVersion'], os_version['BuildNumber']))
        version_to_search = entries_by_version.get(os_version['Name'], {'default': []})
        if os_version['SubVersion'] in version_to_search:
            keys_to_search = version_to_search[os_version['SubVersion']]
        else:
            keys_to_search = version_to_search['default']

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

        if not found_key:
            raise KeyError

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

    def run(self, path=""):
        self.vss = self.myflag('vss')
        self.search = GetFiles(self.config, vss=self.vss)
        self.logger().debug("Parsing ShimCache from registry")

        outfolder = self.myconfig('voutdir') if self.vss else self.myconfig('outdir')
        SYSTEM = list(self.search.search(r"windows/System32/config/SYSTEM$"))
        check_directory(outfolder, create=True)

        partition_list = set()
        for f in SYSTEM:
            aux = re.search(r"([vp\d]*)/windows/System32/config", f, re.I)
            partition_list.add(aux.group(1))

        output_files = {p: os.path.join(outfolder, "shimcache_%s.csv" % p) for p in partition_list}

        for f in SYSTEM:
            save_csv(self.parse_ShimCache_hive(f), outfile=output_files[f.split("/")[2]], file_exists='OVERWRITE', quoting=0)

        self.logger().debug("Finished extraction from ShimCache")
        return []

    def parse_ShimCache_hive(self, sysfile):
        """ Launch shimcache regripper plugin and parse results """
        ripcmd = self.config.get('plugins.common', 'rip', '/opt/regripper/rip.pl')
        date_regex = re.compile(r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}')

        res = run_command([ripcmd, "-r", os.path.join(self.myconfig('casedir'), sysfile), "-p", "shimcache"], logger=self.logger())
        for line in res.split('\n'):
            if ':' not in line[:4]:
                continue
            matches = re.search(date_regex, line)
            if matches:
                path = line[:matches.span()[0] - 2]
                date = str(datetime.datetime.strptime(matches.group(), '%Y-%m-%d %H:%M:%S'))
                executed = bool(len(line[matches.span()[1]:]))
                yield OrderedDict([('LastModified', date), ('AppPath', path), ('Executed', executed)])


class ScheduledTasks(base.job.BaseModule):
    """ Parses job files and schedlgu.txt. """

    def run(self, path=""):
        self.vss = self.myflag('vss')
        self.search = GetFiles(self.config, vss=self.vss)
        self.outfolder = self.myconfig('voutdir') if self.vss else self.myconfig('outdir')
        check_directory(self.outfolder, create=True)

        self.logger().debug("Parsing artifacts from scheduled tasks files (.job)")
        self.parse_Task()
        self.logger().debug("Parsing artifacts from Task Scheduler Service log files (schedlgu.txt)")
        self.parse_schedlgu()
        return []

    def parse_Task(self):
        jobs_files = list(self.search.search(r"\.job$"))
        partition_list = set()
        for f in jobs_files:
            partition_list.add(f.split("/")[2])

        f = {}
        csv_files = {}
        writers = {}

        for p in partition_list:
            csv_files[p] = open(os.path.join(self.outfolder, "jobs_files_%s.csv" % p), "w")
            writers[p] = csv.writer(csv_files[p], delimiter=";", quotechar='"')
            writers[p].writerow(["Product Info", "File Version", "UUID", "Maximum Run Time", "Exit Code", "Status", "Flags", "Date Run",
                                 "Running Instances", "Application", "Working Directory", "User", "Comment", "Scheduled Date"])

        for file in jobs_files:
            partition = file.split("/")[2]
            with open(os.path.join(self.myconfig('casedir'), file), "rb") as f:
                data = f.read()
            job = jobparser.Job(data)
            writers[partition].writerow([jobparser.products.get(job.ProductInfo), job.FileVersion, job.UUID, job.MaxRunTime, job.ExitCode, jobparser.task_status.get(job.Status, "Unknown Status"),
                                         job.Flags_verbose, job.RunDate, job.RunningInstanceCount, "{} {}".format(job.Name, job.Parameter), job.WorkingDirectory, job.User, job.Comment, job.ScheduledDate])
        for csv_file in csv_files.values():
            csv_file.close()

        self.logger().debug("Finished extraction from scheduled tasks .job")

    def parse_schedlgu(self):
        sched_files = list(self.search.search(r"schedlgu\.txt$"))
        for file in sched_files:
            partition = file.split("/")[2]
            save_csv(self._parse_schedlgu(os.path.join(self.myconfig('casedir'), file)),
                     outfile=os.path.join(self.outfolder, 'schedlgu_{}.csv'.format(partition)), file_exists='OVERWRITE', quoting=0)
        self.logger().debug("Finished extraction from schedlgu.txt")

    def _parse_schedlgu(self, file):
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


class SysCache(base.job.BaseModule):

    def run(self, path=""):
        self.search = GetFiles(self.config, vss=self.myflag("vss"))
        self.vss = self.myflag('vss')
        self.logger().debug("Parsing Syscache from registry")
        self.parse_SysCache_hive()
        return []

    def parse_SysCache_hive(self):
        outfolder = self.myconfig('voutdir') if self.vss else self.myconfig('outdir')
        # self.tl_file = os.path.join(self.myconfig('timelinesdir'), "%s_BODY.csv" % self.myconfig('source'))
        check_directory(outfolder, create=True)
        SYSC = self.search.search(r"/System Volume Information/SysCache.hve$")

        ripcmd = self.config.get('plugins.common', 'rip', '/opt/regripper/rip.pl')

        for f in SYSC:
            p = f.split('/')[2]
            output_text = run_command([ripcmd, "-r", os.path.join(self.myconfig('casedir'), f), "-p", "syscache_csv"], logger=self.logger())
            output_file = os.path.join(outfolder, "syscache_%s.csv" % p)

            self.path_from_inode = FileSystem(config=self.config).load_path_from_inode(self.myconfig, p, vss=self.vss)

            save_csv(self.parse_syscache_csv(p, output_text), outfile=output_file, file_exists='OVERWRITE')

        self.logger().debug("Finished extraction from SysCache")

    def parse_syscache_csv(self, partition, text):
        for line in text.split('\n')[:-1]:
            line = line.split(",")
            fileID = line[1]
            inode = line[1].split('/')[0]
            name = self.path_from_inode.get(inode, [''])[0]
            try:
                yield OrderedDict([("Date", dateutil.parser.parse(line[0]).strftime("%Y-%m-%dT%H:%M:%SZ")),
                                   ("Name", name), ("FileID", fileID), ("Sha1", line[2])])
            except Exception:
                yield OrderedDict([("Date", dateutil.parser.parse(line[0]).strftime("%Y-%m-%dT%H:%M:%SZ")),
                                   ("Name", name), ("FileID", fileID), ("Sha1", "")])


class AppCompat(base.job.BaseModule):
    """ Get application executed. The timestamp recorded by Windows is the $SI Modification Time, not the execution time """
    # TODO, obtain the executed flag
    def run(self, path=""):

        if not path:
            self.search = GetFiles(self.config)
            SYSTEM = self.search.search(r"/windows/system32/config/system$")[0]
            path = os.path.join(self.myconfig('casedir'), SYSTEM)

        self.logger().debug("Parsing appcompatcache on registry hive {}".format(path))

        ripcmd = self.config.get('plugins.common', 'rip', '/opt/regripper/rip.pl')
        line_number = 0
        start = 1000
        result = {}
        for line in yield_command([ripcmd, "-r", path, "-p", "appcompatcache"], logger=self.logger()):
            line_number += 1
            if line_number < 5:
                continue
            if line.startswith('LastWrite Time'):
                start = line_number + 2
            if line_number > start:
                result['Time'] = line[-20:].strip()
                result['Application'] = line[:-22].replace('\\', '/')
                yield result

        return []


class UserAssist(base.job.BaseModule):
    """ Parses UserAssist registry key in NTUSER.DAT hive.

    Configuration section:
        - **wine_docker**: path to docker instance running wine
        - **executable**: path to executable app to parse timeline. By default is using RECmd.exe in a dockerized Windows environment. See (https://ericzimmerman.github.io/#!index.md)
        - **batch_file**: configuration file that settles the registry keys to be parsed
    """

    def read_config(self):
        super().read_config()
        self.set_default_config('wine_docker', os.path.join(self.myconfig('rvthome'), 'somewhere_else', 'wine-docker'))
        self.set_default_config('executable', os.path.join(self.myconfig('rvthome'), 'somewhere', 'RECmd.exe'))
        self.set_default_config('batch_file', os.path.join(self.myconfig('rvthome'), 'somewhere', 'RegistryExplorer/BatchExamples/BatchExampleUserAssist.reb'))

    def run(self, path=""):

        # Take path from params if not provided as an argument
        if not path:
            path = self.myconfig('path')

        regfiles = get_hives(path)

        id = self.myconfig('volume_id', None)  # Volume identifier
        if not regfiles:
            self.logger().warning('No valid registry hives provided')
            return []

        output_path = self.myconfig('outdir')
        check_directory(output_path, create=True)
        for user in tqdm(regfiles['ntuser'], total=len(regfiles['ntuser']), desc=self.section):
            output_filename = 'userassist_{}{}.csv'.format(user, '_{}'.format(id) if id else '')

            hive = regfiles['ntuser'][user]
            cmd_args = (self.myconfig('winedocker'), 'wine', self.myconfig('executable'), '--bn', self.myconfig('batch_file'), '-f', hive, '--nl', '--csv', self.myconfig('outdir'), '--csvf', output_filename)
            run_command(*cmd_args)

        return []


class UserAssistAnalysis(base.job.BaseModule):

    def run(self, path=""):
        """ Creates a report based on the output of UserAssist.

            Arguments:
                - ** path **: Path to directory where output files from UserAssist are stored
        """
        check_directory(path, error_missing=True)
        outfile = self.myconfig('outfile')
        check_directory(os.path.basename(outfile), create=True)

        save_csv(self.report_userassist(path), config=self.config, outfile=outfile, quoting=0)

        return []

    def report_userassist(self, path):
        """ Create a unique csv combining output from lnk and jumplists """

        fields = ["LastExecuted", "ProgramName", "RunCounter", "FocusCount", "FocusTime"]

        for file in sorted(os.listdir(path)):
            # Expected file format: `userassist_user_partition.csv`
            partition = file.split('_')[-1].split('.')[0]
            user = file[11:-(len(partition) + 5)]
            for line in base.job.run_job(self.config, 'base.input.CSVReader', path=[os.path.join(path, file)]):
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
