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
import sys
import csv
import yaml
import json
from tqdm import tqdm

from base.utils import check_directory
from plugins.windows.RVT_hives import get_hives
import base.job


class Regsmoker(base.job.BaseModule):
    """ Uses multiple regsmoker plugins to parse the Windows registry and create a series of reports organized by theme.

    Configuration:
        - **path**: Hives location directory. Expected inputs:
            - Directory where registry hive files are stored, such as 'Windows/System32/config/' or 'Windows/AppCompat/Programs/'
            - Main volume directory --> Root directory, where 'Documents and Settings' or 'Users' folders are expected
            - Custom folder containing hives. Warning: 'ntuser.dat' are expected to be stored in a username folder.
        - **outdir**: output directory for generated files
        - **pluginshives**: path to json file associating each regripper plugin with a list of hives
        - **volume_id**: volume identifier, such as partition number. Ex: 'p03'
    """

    def __init__(self, config=None, section=None, local_config=None, from_module=None):
        super().__init__(config, section, local_config, from_module)
        self.regsmoker_path = self.config.config['plugins.windows']['regsmokerdir']
        # Import the regsmoker project
        try:
            if os.path.exists(self.regsmoker_path):
                sys.path.insert(1, self.regsmoker_path)
                import reg_plugin
                import reg_sigma
                self.reg_plugin = reg_plugin
                self.reg_sigma = reg_sigma
        except ImportError as exc:
            self.logger().error(f"Error importing regsmoker project at {self.regsmoker_path}: {exc}")

    def read_config(self):
        super().read_config()
        self.set_default_config('pluginshives', os.path.join(self.config.config['windows']['plugindir'], 'resmoker_plugins.yaml'))
        self.set_default_config('volume_id', 'p01')

    def run(self, path=""):
        """ Main function to generate report files """

        if not path:
            path = self.myconfig('path', '')
        id = self.myconfig('volume_id', None)
        # Get the hives present in 'path'
        regfiles = get_hives(path)

        # Parse registry hives in 'path' and generate output files
        self.generate_registry_output(regfiles, id)

        # Use sigma rules to detect suspicious behaviour
        self.rules_dict = self.get_rules()
        self.generate_sigma_output(regfiles, id)

        return []

    def generate_registry_output(self, regfiles, id=None):
        """ Generates registry output files for a partition

        Arguments:
            id (str): Volume identifier, such as partition number. Ex: 'p03'
        """

        if not regfiles:
            raise base.job.RVTError('No valid registry hives provided')

        output_path = self.myconfig('outdir')
        check_directory(output_path, create=True)

        # Get the hive related to each plugin
        pluginshives = self.myconfig('pluginshives')
        with open(pluginshives, 'r') as f_in:
            self.hivedict = yaml.safe_load(f_in)

        # Initialize variable to store all empty output files to be deleted
        to_remove = {}

        # Iterate through all available regsmoker plugins
        for hive, hivefile in regfiles.items():
            if hive in ('security', 'system', 'software', 'amcache', 'sam', 'bcd', 'syscache'):
                for plugin, values in tqdm(self.hivedict[hive].items()):
                    try:
                        output_filename = os.path.join(output_path, values['filename'])
                        check_directory(os.path.dirname(output_filename), create=True)
                        with open(output_filename, 'w') as f_out:
                            self.logger().debug('Launching plugin {} over {}'.format(plugin, hivefile))
                            self.logger().debug("writting file {}".format(output_filename))
                            # Initialize CSV object if the output must be a CSV
                            if "output" in values.keys() and values["output"] in ('json_to_csv', 'csv'):
                                write = csv.writer(f_out, quoting=2, delimiter=';', quotechar='"', escapechar='\\')
                            # Include header in the case "json_to_csv"
                            if "output" in values.keys() and values["output"] == "json_to_csv":
                                write.writerow(["Data", "Value"])
                            for item in self.get_data(hivefile, plugin):
                                if "output" in values.keys() and values["output"] == "json_to_csv":
                                    write.writerows(self.json_to_csv(item))
                                elif "output" in values.keys() and values["output"] == "csv":
                                    write.writerow(item)
                                else:
                                    f_out.write(f"{json.dumps(item)}\n")
                    except Exception as exc:
                        self.logger().warning(f"Problems with plugin {plugin} over file {hivefile}. {exc}")
            elif hive in ('ntuser', 'usrclass'):
                for username, file in hivefile.items():
                    for plugin, values in tqdm(self.hivedict[hive].items()):
                        try:
                            output_filename = os.path.join(output_path, f"{values['filename'].replace('_user', '_%s' % username)}")
                            check_directory(os.path.dirname(output_filename), create=True)
                            if output_filename not in to_remove.keys():
                                if os.path.exists(output_filename):
                                    to_remove[output_filename] = False
                                else:
                                    to_remove[output_filename] = True
                            with open(output_filename, 'w') as f_out:
                                self.logger().debug('Launching plugin {} over {}'.format(plugin, file))
                                self.logger().debug("writting file {}".format(output_filename))
                                if "output" in values.keys() and values["output"] in ('json_to_csv', 'csv'):
                                    write = csv.writer(f_out, quoting=2, delimiter=';', quotechar='"', escapechar='\\')
                                if "output" in values.keys() and values["output"] == "json_to_csv":
                                    write.writerow(["Data", "Value"])
                                nlines = False
                                for e, item in enumerate(self.get_data(file, plugin)):
                                    nlines = True
                                    if "output" in values.keys() and values["output"] == "json_to_csv":
                                        write.writerows(self.json_to_md(item))
                                    elif "output" in values.keys() and values["output"] == "csv":
                                        if e == 0:
                                            nlines = False
                                        write.writerow(item)
                                    else:
                                        f_out.write(json.dumps(item))
                                if nlines:
                                    to_remove[output_filename] = False
                        except Exception as exc:
                            self.logger().warning(f"Problems with plugin {plugin} against file {file}. {exc}")
            elif hive in ('user', 'userclass'):
                if hive == 'user':
                    hive = 'ntuser'
                else:
                    hive = 'usrclass'
                for username, files in hivefile.items():
                    for plugin, values in tqdm(self.hivedict[hive].items()):
                        for file in files:
                            try:
                                output_filename = os.path.join(output_path, f"{values['filename'].replace('_user', '_%s' % username)}")
                                check_directory(os.path.dirname(output_filename), create=True)
                                if output_filename not in to_remove.keys():
                                    if os.path.exists(output_filename):
                                        to_remove[output_filename] = False
                                    else:
                                        to_remove[output_filename] = True
                                with open(output_filename, 'a') as f_out:
                                    self.logger().debug('Launching plugin {} against {}'.format(plugin, file))
                                    self.logger().debug("writting file {}".format(output_filename))
                                    if "output" in values.keys() and values["output"] in ('json_to_csv', 'csv'):
                                        write = csv.writer(f_out, quoting=2, delimiter=';', quotechar='"', escapechar='\\')
                                    if "output" in values.keys() and values["output"] == "json_to_csv":
                                        if os.path.exists(output_filename) and os.path.getsize(output_filename) == 0:
                                            write.writerow(["Data", "Value"])
                                    nlines = False
                                    for e, item in enumerate(self.get_data(file, plugin)):
                                        nlines = True
                                        if "output" in values.keys() and values["output"] == "json_to_csv":
                                            if os.path.exists(output_filename) and os.path.getsize(output_filename) > 0:
                                                write.writerows(self.json_to_md(item)[1:])
                                            else:
                                                write.writerows(self.json_to_md(item))
                                        elif "output" in values.keys() and values["output"] == "csv":
                                            if e == 0:
                                                nlines = False
                                            if os.path.exists(output_filename) and os.path.getsize(output_filename) > 0 and e == 0:
                                                continue
                                            write.writerow(item)
                                        else:
                                            f_out.write(json.dumps(item))
                                    if nlines:
                                        to_remove[output_filename] = False
                            except Exception as exc:
                                self.logger().warning(f"Problems with plugin {plugin} against file {file}. {exc}")
        for f, status in to_remove.items():
            if status:
                self.logger().debug(f'Removing empty output file {f}')
                os.remove(f)

        return []

    def generate_sigma_output(self, regfiles, id=None):
        """ Generates sigma rules output for a partition

        Arguments:
            id (str): Volume identifier, such as partition number. Ex: 'p03'
        """

        if not regfiles:
            raise base.job.RVTError('No valid registry hives provided')

        output_path = self.myconfig('outdir')
        check_directory(output_path, create=True)

        # Get rules associated with each hive
        sigma_path = os.path.join(self.regsmoker_path, 'sigma')

        with open(os.path.join(output_path, 'rules.json'), 'a') as f_out:
            for hive, hivefile in regfiles.items():
                if hive in ('security', 'system', 'software', 'amcache', 'sam', 'bcd'):
                    for fname, values in self.rules_dict.items():
                        if hive.lower() in values:
                            try:
                                sigma = self.reg_sigma.Sigma(hivefile, os.path.join(sigma_path, fname))
                                if sigma.check_conditions():
                                    f_out.write(f"{json.dumps(sigma.get_result())}\n")
                            except Exception as exc:
                                self.logger().warning(f"Problems applying rule {fname} against file {hivefile}. {exc}")
                elif hive in ('ntuser', 'usrclass'):
                    for hfile in hivefile.values():
                        for fname, values in self.rules_dict.items():
                            if hive.lower() in values:
                                try:
                                    sigma = self.reg_sigma.Sigma(hfile, os.path.join(sigma_path, fname))
                                    if sigma.check_conditions():
                                        f_out.write(f"{json.dumps(sigma.get_result())}\n")
                                except Exception as exc:
                                    self.logger().warning(f"Problems applying rule {fname} against file {hfile}. {exc}")
                elif hive in ('user', 'userclass'):
                    if hive == 'user':
                        hive = 'ntuser'
                    else:
                        hive = 'usrclass'
                    for hfiles in hivefile.values():
                        for fnames, values in self.rules_dict.items():
                            if hive.lower() in values:
                                for hfile in hfiles:
                                    try:
                                        sigma = self.reg_sigma.Sigma(hfile, os.path.join(sigma_path, fname))
                                        if sigma.check_conditions():
                                            f_out.write(f"{json.dumps(sigma.get_result())}\n")
                                    except Exception as exc:
                                        self.logger().warning(f"Problems applying rule {fname} against file {hfile}. {exc}")
        return []

    def get_rules(self):
        """ Get rule files and returns a dict with file and related hives """

        sigma_path = os.path.join(self.regsmoker_path, 'sigma')
        rules_dict = {}
        for fil in os.listdir(sigma_path):
            with open(os.path.join(sigma_path, fil), 'r') as f_in:
                data = yaml.safe_load(f_in)
            rules_dict[fil] = data['logsource']['service'].lower()
        return rules_dict

    def get_data(self, filename, plugin_name, skip_lastwrite=False, skip_empty_keys=False):

        plugin = self.reg_plugin.Plugin(filename, os.path.join(self.regsmoker_path, os.path.join('plugins', f"{plugin_name}.yaml")))
        plugin.get_data()

        for res in plugin.data:
            if not skip_lastwrite and not skip_empty_keys:
                yield res
            elif skip_lastwrite and skip_empty_keys:
                new_res = {}
                for k in res:
                    if len(res[k]) == 1:
                        continue
                    else:
                        new_res = res
                        yield new_res.pop('lastwrite')
            else:
                yield json.dumps(res)

    def json_to_csv(self, item, swap_fields=False):

        results = []

        for k, v in item.items():
            if swap_fields:
                results.append([v, k])
            else:
                results.append([k, v])
        return results
