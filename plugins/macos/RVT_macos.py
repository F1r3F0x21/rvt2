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
import biplist
import datetime
import base.job
from plugins.external.OSX_QuickLook_Parser import quicklook_parser_v_3_5mod
from plugins.common.RVT_files import GetFiles
from base.utils import check_folder

# Preferences:
# https://github.com/ydkhatri/mac_apt/tree/master/plugins


class QuickLook(base.job.BaseModule):

    def run(self, path=""):
        """ Main function to extract quick look information

        """

        if not os.path.isdir(self.myconfig('mountdir')):
            raise base.job.RVTError(f"Folder {self.myconfig('mountdir')} not exists")

        ql_path = self.myconfig("outdir")

        check_folder(ql_path)

        search = GetFiles(self.config)

        ql_list = search.search("QuickLook.thumbnailcache$")

        for i in ql_list:
            self.logger().info(f"Extracting quicklook data from {i}")
            out_path = os.path.join(ql_path, i.split("/")[-3])
            if not os.path.isdir(out_path):
                os.mkdir(out_path)
            quicklook_parser_v_3_5mod.process_database(os.path.join(self.myconfig('casedir'), i), out_path)
        self.logger().info("Done QuickLook")
        return []


class ParsePlist(base.job.BaseModule):

    def run(self, path=""):
        if not os.path.isdir(self.myconfig('mountdir')):
            raise base.job.RVTError(f"Folder {self.myconfig('mountdir')} not exists")

        search = GetFiles(self.config)
        plist_files = search.search(r"\.plist$")

        plist_num = 0
        with open(os.path.join(self.myconfig('outdir'), "plist_dump.txt"), 'wb') as output:
            for pl in plist_files:
                plist_num += 1
                output.write(f"{pl}\n-------------------------------\n".encode())

                try:
                    plist = biplist.readPlist(os.path.join(self.myconfig('casedir'), pl))
                    output.write(self.pprint(plist) + b"\n\n")
                except (biplist.InvalidPlistException, biplist.NotBinaryPlistException):
                    self.logger().info(f"{pl} not a plist file or is corrupted")
                    output.write(b"\n\n")
                except Exception:
                    self.logger().info(f"Problems with file {pl}")

        self.logger().info(f"Founded {plist_num} plist files")
        self.logger().info("Done parsing Plist")
        return []

    def pprint(self, data, indent=0):
        if isinstance(data, dict):
            text = b"    " * indent + b"{\n"
            for k in sorted(data.keys()):
                if isinstance(data[k], dict) or isinstance(data[k], list):
                    text += b"    " * (indent + 1) + k.encode() + b": " + self.pprint(data[k], indent + 1) + b"\n"
                else:
                    text += b"    " * (indent + 1) + k.encode() + b": " + self.pprint(data[k], 0) + b"\n"
            text += b"    " * indent + b"}"
            return text
        elif isinstance(data, list):
            text = b"[\n"
            for k in data:
                text += self.pprint(k, indent + 1) + b"\n"
            text += b"    " * indent + b"]"
            return text
        elif isinstance(data, bytes):
            return b"    " * indent + data
        elif isinstance(data, str):
            return b"    " * indent + data.encode()
        else:
            return b"    " * indent + str(data).encode()


class BasicInfo(base.job.BaseModule):

    def run(self, path=""):

        with open(os.path.join(self.myconfig('outdir'), 'basic_info.md'), 'w') as out:
            self.logger().info("Extracting basic info")

            for p in sorted(os.listdir(self.myconfig('mountdir'))):
                base_path = os.path.join(self.myconfig('mountdir'), p)
                if len(os.listdir(base_path)) == 2 and os.path.isdir(os.path.join(base_path, "root")) and os.path.isdir(os.path.join(base_path, "private_dir")):
                    base_path = os.path.join(self.myconfig('mountdir'), p, "root")

                # version
                sysver = os.path.join(base_path, "System/Library/CoreServices/SystemVersion.plist")
                if not os.path.isfile(sysver):  # some APFS partitions have root or Private as root folders
                    base_path = os.path.join(self.myconfig('mountdir'), p, "root")
                    sysver = os.path.join(base_path, "System/Library/CoreServices/SystemVersion.plist")
                if not os.path.isfile(sysver):
                    continue

                out.write(f"# Information of partition {p}\n")
                plist = biplist.readPlist(sysver)
                out.write(f'Product Name:\t\t{plist["ProductName"]}\nProduct Build Version:\t{plist["ProductBuildVersion"]}\nProduct Version:\t{plist["ProductVersion"]}\n')

                # Install date
                try:
                    out.write(f'Install date:\t{datetime.datetime.fromtimestamp(os.path.getmtime(os.path.join(base_path, "var/db/.AppleSetupDone")), datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}\n\n')
                except Exception:
                    pass

                lastlog_file = os.path.join(base_path, "Library/Preferences/com.apple.loginwindow.plist")
                if os.path.isfile(lastlog_file):
                    plist = biplist.readPlist(lastlog_file)
                    out.write(f'Last User:\t{plist["lastUser"]}\nLast User Name:\t{plist["lastUserName"]}\n\n')

                aux_path = os.path.join(base_path, "var/db/dslocal/nodes/Default/users")
                if os.path.isdir(aux_path):
                    out.write("User|Creation date|change pass date\n--|--|--\n")
                    for file in sorted(os.listdir(aux_path)):
                        if not file.startswith("_"):
                            table_data = [file[:-6], "", ""]
                            try:
                                plist = biplist.readPlist(os.path.join(aux_path, file))
                                pl2 = biplist.readPlistFromString(plist['accountPolicyData'][0])
                                if "creationTime" in pl2.keys():
                                    table_data[1] = datetime.datetime.fromtimestamp(pl2["creationTime"], datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                                if "passwordLastSetTime" in pl2.keys():
                                    table_data[2] = datetime.datetime.fromtimestamp(pl2["passwordLastSetTime"], datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                            except Exception:
                                pass
                            if table_data[1] != "" or table_data[2] != "":
                                out.write(f'{table_data[0]}|{table_data[1]}|{table_data[2]}\n')
                            else:
                                self.logger().warning(f"Problems extracting userinfo from file {file}")
                out.write('\n')

        self.logger().info("MacOS Basic Info done")
        return []
