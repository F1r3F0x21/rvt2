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

import ast
import os
import re
import base
from datetime import datetime
from base.utils import check_directory, date_to_iso, save_csv
from plugins.linux import get_timezone


class LinuxDpkgLog(base.job.BaseModule):
    
    """ Extract the Dpkg

    Module description:
        - **from_module**: Data dict.
        - **yields**: The updated dict data.
    """

    def read_config(self):
        super().read_config()

    def run(self, path=None):
        pattern = r'(\d+-\d+-\d+\s\d+:\d+:\d+)\s(.*)'
        tz = get_timezone(self.myconfig('mountdir'))
        prog = re.compile(pattern)
        filename = os.path.basename(path)
        
        for line in self.from_module.run(path):
            match = prog.match(line)
            if match:
                timestamp, action = match.groups()
                log_entry_dict = {
                    "@timestamp": timestamp,
                    "action": action,
                    "filename": filename
                }
                actual_date = datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")
                 # Parse the timestamp and convert it to ISO format
                output_string_utc = date_to_iso(actual_date, input_timezone=tz, output_timezone="UTC")
                log_entry_dict['@timestamp'] = output_string_utc

                yield log_entry_dict

            else:
                self.logger().warning("Regex pattern failed with some logline input " + line)


class LinuxAptHistoryLog(base.job.BaseModule):
    
    """ Extract the Dpkg

    Module description:
        - **from_module**: Data dict.
        - **yields**: The updated dict data.
    """

    def read_config(self):
        super().read_config()

    def run(self, path=None):
        aux_dict = {}
        for line in self.from_module.run(path):
            if line:
                linesplited = line.split(":", 1)
                if linesplited[0] == "Start-Date":
                    aux_dict = {}
                    timestamp = linesplited[1].strip()
                    localdate = datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")
                    isodate = date_to_iso(localdate, input_timezone = get_timezone(self.myconfig('mountdir')))
                    aux_dict["@timestamp"] = isodate
                elif linesplited[0] == "End-Date":
                        timestamp = linesplited[1].strip()
                        localdate = datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")
                        isodate = date_to_iso(localdate, input_timezone = get_timezone(self.myconfig('mountdir')))
                        aux_dict[linesplited[0]] = isodate
                        yield aux_dict
                elif linesplited[0] == "Commandline":
                    aux_dict[linesplited[0]] = linesplited[1]
                else:
                    if "action" in aux_dict:
                        aux_list =  list(aux_dict["action"])
                        aux_list.append({linesplited[0]:linesplited[1]})
                        aux_dict["action"] = aux_list
                    else:
                        aux_dict["action"] = [{linesplited[0]:linesplited[1]}]


class AnalysisLinuxAptHistoryLog(base.job.BaseModule):
    """ Analysis the Apt History log

    Module description:
        - **from_module**: Data dict.
        - **yields**: The updated dict data.
    """
    def read_config(self):
        super().read_config()
    
    def run(self, path=None):
        pkg_pattern = r'([\w\.-]+):(.+)\s\(([\d\~\w\.-]*).*\)'
        pkg_prog = re.compile(pkg_pattern)
        upgrade_list = []
        remove_list = []
        purge_list = []

        for line in self.from_module.run(path):
            user_responsible = '' 
            action_list = ast.literal_eval(line["action"])
            if any("Requested-By" in x for x in action_list):
                user_responsible = [x["Requested-By"] for x in action_list if "Requested-By" in x]

            for action in action_list:
                package_action, package = list(action.items())[0]
                if not package_action == "Requested-By":
                    for package_name in package.split("),"):
                        if not str(package_name).endswith(")"):
                            package_name += ")"
                        match_pkg = pkg_prog.match(package_name.strip())
                        if match_pkg:
                            package_name, package_architecture, package_version = match_pkg.groups()
                            data_dict = {
                                '@timestamp': line['@timestamp'],
                                'package.name' : package_name,
                                'package.architecture' : package_architecture,
                                'package.version' : package_version,
                                'username' : user_responsible
                            }

                            if package_action == "Install":
                                yield data_dict
                            elif package_action == "Upgrade":
                                upgrade_list.append(data_dict)
                            elif package_action == "Remove":
                                remove_list.append(data_dict)
                            elif package_action == "Purge":
                                purge_list.append(data_dict)
                        else:
                            self.logger().warning("Regex pattern failed with some package name: " + package_name)

        # Save upgraded, removed and purged packages in diferent csv
        analysisdir = self.myconfig('analysisdir')
        check_directory(analysisdir, create=True)

        if upgrade_list:
            csv_upgrade_out = os.path.join(analysisdir, 'apt_packages_upgraded.csv')
            save_csv(upgrade_list, outfile=csv_upgrade_out)
        
        if remove_list:
            csv_remove_out = os.path.join(analysisdir, 'apt_packages_removed.csv')
            save_csv(remove_list, outfile=csv_remove_out)

        if purge_list:
            csv_purge_out = os.path.join(analysisdir, 'apt_packages_purged.csv')
            save_csv(purge_list, outfile=csv_purge_out)


class AnalysisLinuxDpkgLog(base.job.BaseModule):
    """ Analysis the Dpkg log

    Module description:
        - **from_module**: Data dict.
        - **yields**: The updated dict data.
    """
    def read_config(self):
        super().read_config()
    
    def run(self, path=None):
        pkg_installed = r'status\sinstalled\s(.*):(\w+)+\s(.*)'
        pkg_prog = re.compile(pkg_installed)

        for line in self.from_module.run(path):
            match_pkg_installed = pkg_prog.match(line["action"])
            if match_pkg_installed:
                package_name, package_architecture, package_version = match_pkg_installed.groups()
                data_dict = {
                    '@timestamp': line['@timestamp'],
                    'package.name' : package_name,
                    'package.architecture' : package_architecture,
                    'package.version' : package_version
                }
                yield data_dict