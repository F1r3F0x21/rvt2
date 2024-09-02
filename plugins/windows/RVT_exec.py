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
import logging
import re
import shlex
import struct
import subprocess
import pyscca
import base.job
from datetime import datetime, timedelta
from cim import CIM
from cim.objects import Namespace
from base.utils import check_directory, check_folder, get_windows_user_from_path, save_csv, relative_path
from plugins.common.RVT_files import GetTimeline

def parse_RFC_file(fname):
    """ Parses RecentFileCache.bcf

    Args:
        fname (str): file path
    """
    magics = [b'\xfe\xff\xee\xff', b'\x11\x22\x00\x00', b'\x03\x00\x00\x00', b'\x01\x00\x00\x00']
    entries = []
    filesize = os.path.getsize(fname)
    if filesize <= 20:
        return ''

    with open(fname, "rb") as fh:
        fh.seek(0)
        for i in range(0, len(magics)):
            header = fh.read(4)
            if not header == magics[i]:
                return ''
        fh.read(4)  # Disregard this value

        while fh.tell() < filesize:
            tmp_buffer = fh.read(4)
            entry_len = (struct.unpack('<i', tmp_buffer)[0]) * 2  # For unicode
            entry = fh.read(entry_len)
            entries.append(entry.decode("utf-16"))
            fh.read(2)  # Disregard last two unicode null terminators as they break in decode

    return entries


def parse_prefetch_file(pf_file):
    # Uses an adapted version of Windows Prefetch Parser Based in 505Forensics (http://www.505forensics.com)
    """ Parse individual file. Output is placed in 'output' dictionary

    Args:
        pf_file (str): list of filenames
    Returns:
        dict: dict with prefetch file information
    """
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)

    #logger.debug("Parsing {}".format(pf_file))
    item = {}

    try:
        scca = pyscca.open(pf_file)
        res_loaded = []
        for x in range(scca.get_number_of_file_metrics_entries()):
            res_loaded.append(scca.get_filename(x))
        item["resources loaded"] = res_loaded

        last_run_times = []
        n_runs = 1
        if scca.get_format_version() > 23:
            n_runs = 8

        for x in range(n_runs):
            if scca.get_last_run_time_as_integer(x) > 0:
                last_run_times.append(scca.get_last_run_time(x).strftime("%Y-%m-%d %H:%M:%S"))  # str conversion utilized to change from datetime into human-readable
            else:
                last_run_times.append('')

        item["last run times"] = last_run_times
        item["filename"] = scca.executable_filename
        item["prefetch hash"] = format(scca.prefetch_hash, 'x').upper()
        item["run count"] = str(scca.run_count)

        volumes = []
        for i in range(scca.number_of_volumes):
            volume = [str(scca.get_volume_information(i).device_path), scca.get_volume_information(i).creation_time.strftime(
                "%Y-%m-%d %H:%M:%S"), format(scca.get_volume_information(i).serial_number, 'x').upper()]
            volumes.append(volume)
        item["Volumes"] = volumes

        return item
    except IOError as e:
        logger.error("I/O Error: {}".format(e))
        return -1
    except SystemError as e:
        logger.error("Bad signature for pf file: {}".format(e))
        return -1
    except Exception:
        logger.error("Unexpected error")
        return -1


class Prefetch(base.job.BaseModule):
    """ Parse all prefetch files inside a directory"""

    def read_config(self):
        super().read_config()
        self.set_default_config('volume_id', None)

    def run(self, path=""):
        self.volume_id = self.myconfig('volume_id', None)
        if self.volume_id is None:
            self.volume_id = relative_path(path, self.myconfig('casedir')).split("/")[2]

        if not os.path.isdir(path):
            raise base.job.RVTError('Provided path {} is not a directory'.format(path))

        # Get Prefetch files (.pf) list
        try:
            self.file_list = [os.path.join(path, file) for file in os.listdir(path) if file.endswith(".pf")]
            rel_path_list = [relative_path(os.path.join(path, file), self.myconfig('casedir')) for file in os.listdir(path) if file.endswith(".pf")]
        except IOError:
            raise base.job.RVTError('Unable to list files in directory {}'.format(path))
        except Exception as exc:
            raise base.job.RVTError(exc)
        if len(self.file_list) == 0:
            self.logger().warning('No prefetch files found in {}'.format(path))
            return []

        # Obtain timeline object to retrieve macb times
        try:
            self.tl_files = GetTimeline(config=self.config).get_macb(rel_path_list)
        except IOError:
            self.tl_files = None

        # Define output files
        base_path = self.myconfig('outdir')
        check_directory(base_path, create=True)
        out_file_id = '' if not self.volume_id else '_{}'.format(self.volume_id)
        detailed_csv = os.path.join(base_path, "prefetch_executions{}.csv".format(out_file_id))
        self.single_entry_csv = os.path.join(base_path, "prefetch{}.csv".format(out_file_id))
        self.dump_file = os.path.join(base_path, "prefetch_dump{}.txt".format(out_file_id))
        self.logger().debug('Saving Prefetch information dump to {}'.format(self.dump_file))
        self.logger().debug('Saving Prefetch entries to {}'.format(self.single_entry_csv))
        self.logger().debug('Saving all Prefetch executions to {}'.format(detailed_csv))

        save_csv(self.parse_Prefetch(path), config=self.config, outfile=detailed_csv, file_exists='OVERWRITE', quoting=0, encoding='utf-8')
        self.parse_Prefetch(path)
        return []

    def parse_Prefetch(self, path):

        with open(self.dump_file, "w") as pf_output1:
            with open(self.single_entry_csv, "w") as csv_file:
                writer = csv.writer(csv_file, delimiter=";", quotechar='"')
                header_flag = True
                for prefetch_file in self.file_list:
                    prefetch_rel_path = relative_path(prefetch_file, self.myconfig('casedir'))
                    filename = relative_path(prefetch_file, path)

                    if os.path.getsize(prefetch_file) == 0:  # Parse only non empty .pf files
                        continue

                    # If timeline has been generated, take prefetch file birth date from there
                    birth_date = ''
                    mod_date = ''
                    if self.tl_files and prefetch_rel_path in self.tl_files:
                        birth_date = self.tl_files[prefetch_rel_path]['b']
                        mod_date = self.tl_files[prefetch_rel_path]['m']

                    item = parse_prefetch_file(prefetch_file)

                    if item == -1:
                        self.logger().warn("Problems parsing {}".format(prefetch_file))
                        pf_output1.write("Filename:\t\t{}\nBirth date:\t\t{}\nPrefetch Hash:\t\t\nExecutable Filename:\t\nRun count:\t\t\n".format(
                            filename, birth_date))
                        pf_output1.write("\n################################################\n")
                        writer.writerow([filename, "", "", birth_date, mod_date] + [""] * 7)
                        continue

                    if header_flag:
                        headers = ["Filename", "Executable", "Run count", "Birth time"] + ["Run time {}".format(str(i)) for i in range(len(item["last run times"]))]
                        writer.writerow(headers)
                        header_flag = False

                    # Write information in dump file
                    pf_output1.write("Filename:\t\t{}\nBirth date:\t\t{}\nPrefetch Hash:\t\t{}\nExecutable Filename:\t{}\nRun count:\t\t{}\n".format(
                        filename, birth_date, item["prefetch hash"], item["filename"], item["run count"]))
                    for i, run_date in enumerate(item["last run times"]):
                        pf_output1.write("\tRun time {}:\t\t{}\n".format(str(i), run_date))
                    pf_output1.write("\nResources\nResources Loaded:\t{}\n".format(str(len(item["resources loaded"]))))
                    for i in item["resources loaded"]:
                        pf_output1.write("\t{}\n".format(i))
                    pf_output1.write("\nVolumes\nNumber of Volumes:\t{}\n".format(str(len(item["Volumes"]))))
                    for v in item["Volumes"]:
                        pf_output1.write("\tDevice path:\t{}\n\tCreation time:\t{}\n\tSerial Number:\t{}\n\n".format(v[0], v[1], v[2]))
                    pf_output1.write("################################################\n")

                    # Write a single entry for each item in csv
                    writer.writerow([filename, item["filename"], item["run count"], birth_date] + [i for i in item["last run times"]])

                    # Yield an event for every execution time
                    data = {'RunTime': "",
                            'PrefecthFile': filename,
                            'Executable': item["filename"],
                            'BirthDate': birth_date,
                            'VolumeSN': item["Volumes"][0][2],
                            'Partition': self.volume_id,
                            'RunTotal': item["run count"],}
                    for i, execution_time in enumerate(item["last run times"]):
                        if not execution_time:
                            continue
                        data['RunTime'] = execution_time
                        data['RunCount'] = i + 1
                        yield data

        self.logger().debug("Prefetch parsing for {} finished".format(path))


class RFC(base.job.BaseModule):
    """ Parses RecentFileCache.bcf. It contains the path of binaries executed between the last execution date of ProgramDataUpdater and the current time"""

    def read_config(self):
        super().read_config()
        self.set_default_config('volume_id', None)

    def run(self, path=""):
        base_path = self.myconfig('outdir')
        check_directory(base_path, create=True)
        volume_id = self.myconfig('volume_id')
        if volume_id is None:
            volume_id = relative_path(path, self.myconfig('casedir')).split("/")[2]

        self.logger().debug("Parsing {}".format(path))
        out_file_id = '' if not volume_id else '_{}'.format(volume_id)
        outfile = os.path.join(base_path, "rfc{}.csv".format(out_file_id))
        try:
            rfc = ({'Application': i} for i in parse_RFC_file(path))
            save_csv(rfc, config=self.config, outfile=outfile, quoting=0, file_exists='OVERWRITE')
        except Exception:
            self.logger().warning("Problems parsing {}".format(path))

        self.logger().debug("Parsing RecentFileCache.bcf finished")

        return []


class CCM(base.job.BaseModule):
    """ Parses SCCM Software Metering history.
        Module based on https://github.com/fireeye/flare-wmi/blob/master/python-cim/samples/show_CCM_RecentlyUsedApps.py
    """

    def read_config(self):
        super().read_config()
        self.set_default_config('volume_id', None)

    def run(self, path=""):

        self.type_ = 'win7'

        # Parse CCM for recently used apps
        results = self.show_CCM_RecentlyUsedApps(path)

        # Organize output by volume
        volume_id = self.myconfig('volume_id')
        if volume_id is None:
            volume_id = relative_path(path, self.myconfig('casedir')).split("/")[2]
        out_file_id = '' if not volume_id else '_{}'.format(volume_id)
        csv_out = os.path.join(self.myconfig('outdir'), 'CCM{}.csv'.format(out_file_id))

        # Write output files
        if not results:
            self.logger().info('No results obtained while parsing {}'.format(path))
            return []
        self.logger().debug('Saving output to file {}'.format(csv_out))
        save_csv(results, config=self.config, outfile=csv_out, quoting=0, file_exists='OVERWRITE')

    def show_CCM_RecentlyUsedApps(self, path):
        if self.type_ not in ("xp", "win7"):
            raise RuntimeError("Invalid mapping type: {:s}".format(self.type_))

        Values = ["FolderPath", "ExplorerFileName", "FileSize", "LastUserName", "LastUsedTime", "TimeZoneOffset",
                  "LaunchCount", "OriginalFileName", "FileDescription", "CompanyName", "ProductName", "ProductVersion",
                  "FileVersion", "AdditionalProductCodes", "msiVersion", "msiDisplayName", "ProductCode",
                  "SoftwarePropertiesHash", "ProductLanguage", "FilePropertiesHash", "msiPublisher"]

        c = CIM(self.type_, path)
        try:
            ret_items = []
            with Namespace(c, "root\\ccm\\SoftwareMeteringAgent") as ns:
                for RUA in ns.class_("CCM_RecentlyUsedApps").instances:
                    RUAValues = {}
                    for Value in Values:
                        try:
                            if Value == "LastUsedTime":
                                Time = str(RUA.properties[Value].value)
                                ExcelTime = "{}-{}-{} {}:{}:{}".format(Time[0:4], Time[4:6], Time[6:8], Time[8:10],
                                                                       Time[10:12], Time[12:14])
                                RUAValues[Value] = ExcelTime
                            elif Value == "TimeZoneOffset":
                                Time = str(RUA.properties[Value].value)
                                TimeOffset = '="{}"'.format(Time[-4:])
                                RUAValues[Value] = TimeOffset
                            else:
                                RUAValues[Value] = str(RUA.properties[Value].value).replace('\\', '/')
                        except KeyError:
                            RUAValues[Value] = ""
                    ret_items.append(RUAValues)
            return ret_items
        except IndexError:
            raise RuntimeError("CCM Software Metering Agent path 'root\\\\ccm\\\\SoftwareMeteringAgent' not found.")


class PSHistory(base.job.BaseModule):

    """ Get the PowerShell History """

    def read_config(self):
        super().read_config()
        self.set_default_config('outdir', None)
        
    def run(self, path=None):
        base_path = self.myconfig('outdir')
        user = get_windows_user_from_path(path, logger=self.logger())
        
        file_out = os.path.join(base_path, "powershell_history_" + user + '.txt')
        check_folder(base_path)
        
        command = "cp -r " + path + " " + file_out
        args = shlex.split(command)
        process = subprocess.Popen(args,  stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        output = process.stderr.readline().strip()
        if output:
            self.logger().error(output)

class PSAnalysisCache(base.job.BaseModule):

    """ Get the PowerShell Module Analysis Cache metadata
    """
    class Command:
        def __init__(self, command_length, command_string, command_type):
            self.command_length = command_length
            self.command_string = command_string.decode('utf-8')
            self.command_type = command_type

        def to_dict(self):
            return self.command_string

        def __repr__(self):
            return str(self.to_dict())

    class Type:
        def __init__(self, type_length, type_string, type_attributes):
            self.type_length = type_length
            self.type_string = type_string
            self.type_attributes = type_attributes

        def to_dict(self):
            return {
                "type_length": self.type_length,
                "type_string": self.type_string.decode('utf-8'),
                "type_attributes": self.type_attributes
            }

        def __repr__(self):
            return str(self.to_dict())

    class Entry:

        suspicious_content_list = ["Add-Type", "AddSecurityPackage", "AdjustTokenPrivileges", "AllocHGlobal", 
                                    "BindingFlags", "Bypass", "CloseHandle", "CreateDecryptor", "CreateEncryptor", 
                                    "CreateProcessWithToken", "CreateRemoteThread", "CreateThread", "CreateType",
                                    "CreateUserThread", "Cryptography", "CryptoServiceProvider", "CryptoStream",
                                    "DangerousGetHandle", "DeclaringMethod", "DeclaringType", "DefineConstructor",
                                    "DefineDynamicAssembly", "DefineDynamicModule", "DefineEnum", "DefineField", 
                                    "DefineLiteral", "DefinePInvokeMethod", "DefineType", "DeflateStream", 
                                    "DeviceIoControl", "DllImport", "DuplicateTokenEx", "Emit", "EncodedCommand", 
                                    "EnumerateSecurityPackages", "ExpandString", "FreeHGlobal", "FreeLibrary", 
                                    "FromBase64String", "GetAssemblies", "GetAsyncKeyState", "GetConstructor", 
                                    "GetConstructors", "GetDefaultMembers", "GetDelegateForFunctionPointer", 
                                    "GetEvent", "GetEvents", "GetField", "GetFields", "GetForegroundWindow", 
                                    "GetInterface", "GetInterfaceMap", "GetInterfaces", "GetKeyboardState", 
                                    "GetLogonSessionData", "GetMember", "GetMembers", "GetMethod", "GetMethods", 
                                    "GetModuleHandle", "GetNestedType", "GetNestedTypes", "GetPowerShell", 
                                    "GetProcAddress", "GetProcessHandle", "GetProperties", "GetProperty", 
                                    "GetTokenInformation", "GetTypes", "ILGenerator", "ImpersonateLoggedOnUser", 
                                    "InteropServices", "IntPtr", "InvokeMember", "kernel32", "LoadLibrary", 
                                    "LogPipelineExecutionDetails", "MakeArrayType", "MakeByRefType", "MakeGenericType", 
                                    "MakePointerType", "Marshal", "memcpy", "MemoryStream", "Methods", "MiniDumpWriteDump", 
                                    "NonPublic", "OpenDesktop", "OpenProcess", "OpenProcessToken", "OpenThreadToken", 
                                    "OpenWindowStation", "PasswordDeriveBytes", "Properties", "ProtectedEventLogging", 
                                    "PtrToString", "PtrToStructure", "ReadProcessMemory", "ReflectedType", "RevertToSelf", 
                                    "RijndaelManaged", "ScriptBlockLogging", "SetInformationProcess", "SetThreadToken", 
                                    "SHA1Managed", "StructureToPtr", "ToBase64String", "TransformFinalBlock", "TypeHandle", 
                                    "TypeInitializer", "UnderlyingSystemType", "UnverifiableCodeAttribute", "VirtualAlloc", 
                                    "VirtualFree", "VirtualProtect", "WriteByte", "WriteInt32", "WriteProcessMemory", 
                                    "ZeroFreeGlobalAllocUnicode"]

        def __init__(self, ticks, path, commands, types):
            # Ticks to datetime
            epoch_start = datetime(1, 1, 1)
            self.date = epoch_start + timedelta(microseconds=ticks // 10)
            self.path = path
            self.commands = commands
            self.types = types

        def to_dict(self):
            return {
                "date": self.date.isoformat(),
                "path": self.path.decode('utf-8'),
                "commands": "" if len(self.commands) == 0 else [command for command in self.commands],
                "suspicious": sum(str(item1).strip() in (str(item2).strip() for item2 in self.suspicious_content_list) for item1 in self.commands),
                "types": "" if len(self.types) == 0 else [type_obj.to_dict() for type_obj in self.types]
            }

        def __repr__(self):
            return str(self.to_dict())

    def read_config(self):
        super().read_config()

    def parse_string(self, f, length):
        """Parses a string of length 'length' from the file."""
        return f.read(length)

    def parse_command(self, f):
        """Parses a Command structure."""
        command_length = struct.unpack('<I', f.read(4))[0]
        command_string = self.parse_string(f, command_length)
        command_types = struct.unpack('<I', f.read(4))[0]
        return self.Command(command_length, command_string, command_types)

    def parse_type(self, f):
        """Parses a Type structure."""
        type_length = struct.unpack('<I', f.read(4))[0]
        type_string = self.parse_string(f, type_length)
        type_attributes = struct.unpack('<I', f.read(4))[0]
        return self.Type(type_length, type_string, type_attributes)

    def parse_entry(self, f):
        """Parses an Entry structure."""
        date = struct.unpack('<Q', f.read(8))[0]  # assuming the date is a 4-byte integer
        str_length = struct.unpack('<I', f.read(4))[0]
        path = self.parse_string(f, str_length)

        # Parsing the list of Commands
        num_commands = struct.unpack('<I', f.read(4))[0]
        commands = []
        for _ in range(num_commands):
            commands.append(self.parse_command(f))
        commands = tuple(commands)

        # Parsing the list of Types
        num_types = struct.unpack('<i', f.read(4))[0] # '<i' signed integer
        types = []
        if num_types != -1:
            for _ in range(num_types):
                types.append(self.parse_type(f))
        types = tuple(types)
        return self.Entry(date, path, commands, types)

    def parse_file(self, file_path):
        with open(file_path, 'rb') as f:
            magicheader = f.read(13)
            version = struct.unpack('<B', f.read(1))[0]
            num_entries = struct.unpack('<I', f.read(4))[0]
            for _ in range(num_entries):
                entry = self.parse_entry(f)
                yield entry.to_dict()

    def run(self, path=None):
        yield from self.parse_file(path)


class PSAnalysisCache(base.job.BaseModule):
    """ Get the PowerShell Module Analysis Cache metadata """

    class Command:
        def __init__(self, command_length, command_string, command_type):
            self.command_length = command_length
            self.command_string = command_string.decode('utf-8')
            self.command_type = command_type

        def to_dict(self):
            return self.command_string

        def __repr__(self):
            return str(self.to_dict())

    class Type:
        def __init__(self, type_length, type_string, type_attributes):
            self.type_length = type_length
            self.type_string = type_string
            self.type_attributes = type_attributes

        def to_dict(self):
            return {
                "type_length": self.type_length,
                "type_string": self.type_string.decode('utf-8'),
                "type_attributes": self.type_attributes
            }

        def __repr__(self):
            return str(self.to_dict())

    class Entry:
        def __init__(self, ticks, path, commands, types):
            # Ticks to datetime
            epoch_start = datetime(1, 1, 1)
            self.date = epoch_start + timedelta(microseconds=ticks // 10)
            self.path = path
            self.commands = commands
            self.types = types

        def to_dict(self):
            return {
                "Date": self.date.isoformat(),
                "Path": self.path.decode('utf-8'),
                "Commands": "" if len(self.commands) == 0 else [command for command in self.commands],
                "Types": "" if len(self.types) == 0 else [type_obj.to_dict() for type_obj in self.types]
            }

        def __repr__(self):
            return str(self.to_dict())

    def read_config(self):
        super().read_config()

    def parse_string(self, f, length):
        """Parses a string of length 'length' from the file."""
        return f.read(length)

    def parse_command(self, f):
        """Parses a Command structure."""
        command_length = struct.unpack('<I', f.read(4))[0]
        command_string = self.parse_string(f, command_length)
        command_types = struct.unpack('<I', f.read(4))[0]
        return self.Command(command_length, command_string, command_types)

    def parse_type(self, f):
        """Parses a Type structure."""
        type_length = struct.unpack('<I', f.read(4))[0]
        type_string = self.parse_string(f, type_length)
        type_attributes = struct.unpack('<I', f.read(4))[0]
        return self.Type(type_length, type_string, type_attributes)

    def parse_entry(self, f):
        """Parses an Entry structure."""
        date = struct.unpack('<Q', f.read(8))[0]  # assuming the date is a 4-byte integer
        str_length = struct.unpack('<I', f.read(4))[0]
        path = self.parse_string(f, str_length)

        # Parsing the list of Commands
        num_commands = struct.unpack('<I', f.read(4))[0]
        commands = []
        for _ in range(num_commands):
            commands.append(self.parse_command(f))
        commands = tuple(commands)

        # Parsing the list of Types
        num_types = struct.unpack('<i', f.read(4))[0] # '<i' signed integer
        types = []
        if num_types != -1:
            for _ in range(num_types):
                types.append(self.parse_type(f))
        types = tuple(types)
        return self.Entry(date, path, commands, types)

    def parse_file(self, file_path):
        with open(file_path, 'rb') as f:
            magicheader = f.read(13)
            version = struct.unpack('<B', f.read(1))[0]
            num_entries = struct.unpack('<I', f.read(4))[0]
            for _ in range(num_entries):
                entry = self.parse_entry(f)
                yield entry.to_dict()

    def run(self, path=None):
        user = get_windows_user_from_path(path, logger=self.logger())
        for result in self.parse_file(path):
            result['User'] = user
            yield result


class PCARecord(base.job.BaseModule):

    """ Assign status string to Program Compatibility Assistan artifact results """
        
    def run(self, path=None):

        status = {
            0 : "Installer failed",
            1 : "Driver was Blocked",
            2 : "Abnormal Process Exit",
            3 : "PCA Resolve is Called"
        }

        for line in self.from_module.run(path):
            number = int(line["Status"])
            line["status"] = status.get(number, number)
            yield line