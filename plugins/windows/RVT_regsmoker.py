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
import csv
import sys
import logging
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
        - **errorfile**: path to log file to register regripper errors
        - **ripplugins**: path to json file containing the organized list of regripper plugins to run
        - **pluginshives**: path to json file associating each regripper plugin with a list of hives
        - **volume_id**: volume identifier, such as partition number. Ex: 'p03'
    """

    def read_config(self):
        super().read_config()
        self.set_default_config('pluginshives', os.path.join(self.config.config['windows']['plugindir'], 'resmoker_plugins.yaml'))
        self.set_default_config('errorfile', os.path.join(self.myconfig('sourcedir'), "{}_aux.log".format(self.myconfig('source'))))
        self.set_default_config('volume_id', 'p01')

    def run(self, path=""):
        """ Main function to generate report files """

        if not path:
            path = self.myconfig('path', '')
        regfiles = get_hives(path)
        id = self.myconfig('volume_id', None)
        self.generate_registry_output(regfiles, id)
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

        # Get the hives associated with each plugin
        pluginshives = self.myconfig('pluginshives')

        with open(pluginshives, 'r') as f_in:
            self.hivedict = yaml.safe_load(f_in)

        for hive, hivefile in regfiles.items():
            if hive in ('security', 'system', 'software', 'amcache', 'sam', 'bcd'):
                for plugin, values in tqdm(self.hivedict[hive].items()):
                    try:
                        output_filename = os.path.join(output_path, values['filename'])
                        check_directory(os.path.dirname(output_filename), create=True)
                        with open(output_filename, 'w') as f_out:
                            self.logger().debug('Launching plugin {} against {}'.format(plugin, hivefile))
                            self.logger().debug("writting file {}".format(output_filename))
                            if "output" in values.keys() and values["output"] in ('json_to_csv', 'csv'):
                                write = csv.writer(f_out, quoting=2, delimiter=';', quotechar='"', escapechar='\\')
                            if "output" in values.keys() and values["output"] == "json_to_csv":
                                write.writerow(["Data", "Value"])
                            for item in self.get_data(hivefile, plugin):
                                if "output" in values.keys() and values["output"] == "json_to_csv":
                                    write.writerows(self.json_to_csv(item))
                                elif "output" in values.keys() and values["output"] == "csv":
                                    write.writerow(item)
                                else:
                                    f_out.write(f"{json.dumps(item)}\n")
                    except Exception:
                        self.logger().warning(f"Problems with plugin {plugin} against file {hivefile}")
            elif hive in ('ntuser', 'usrclass'):
                for username, file in hivefile.items():
                    for plugin, values in tqdm(self.hivedict[hive].items()):
                        try:
                            output_filename = os.path.join(output_path, f"{values['filename'].replace('_user', '_%s' % username)}")
                            check_directory(os.path.dirname(output_filename), create=True)
                            to_remove = []
                            with open(output_filename, 'w') as f_out:
                                self.logger().debug('Launching plugin {} against {}'.format(plugin, file))
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
                                if not nlines:
                                    to_remove.append(output_filename)
                            for f in to_remove:
                                self.logger().debug('file {} has no lines'.format(output_filename))
                                os.remove(f)
                        except Exception:
                            self.logger().warning(f"Problems with plugin {plugin} against file {file}")

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

        regsmoker_path = self.config.config['plugins.windows']['regsmokerdir']
        sigma_path = os.path.join(regsmoker_path, 'sigma')
        sys.path.insert(1, regsmoker_path)
        import reg_sigma

        with open(os.path.join(output_path, 'rules.json'), 'a') as f_out:
            for hive, hivefile in regfiles.items():
                if hive in ('security', 'system', 'software', 'amcache', 'sam', 'bcd'):
                    for fname, values in self.rules_dict.items():
                        if hive.lower() in values:
                            sigma = reg_sigma.Sigma(hivefile, os.path.join(sigma_path, fname))
                            if sigma.check_conditions():
                                f_out.write(f"{json.dumps(sigma.get_result())}\n")
                elif hive in ('ntuser', 'usrclass'):
                    for hfile in hivefile.values():
                        for fname, values in self.rules_dict.items():
                            if hive.lower() in values:
                                sigma = reg_sigma.Sigma(hfile, os.path.join(sigma_path, fname))
                                if sigma.check_conditions():
                                    f_out.write(f"{json.dumps(sigma.get_result())}\n")
        return []

    def get_rules(self):
        """ gets rule files and returns a dict with file and related hives """

        regsmoker_path = self.config.config['plugins.windows']['regsmokerdir']
        sigma_path = os.path.join(regsmoker_path, 'sigma')
        rules_dict = {}
        for fil in os.listdir(sigma_path):
            with open(os.path.join(sigma_path, fil), 'r') as f_in:
                data = yaml.safe_load(f_in)
            rules_dict[fil] = data['logsource']['service'].lower()
        return rules_dict

    def get_data(self, filename, plugin_name, skip_lastwrite=False, skip_empty_keys=False):
        regsmoker_path = self.config.config['plugins.windows']['regsmokerdir']
        sys.path.insert(1, regsmoker_path)
        import reg_plugin
        plugin = reg_plugin.Plugin(filename, os.path.join(regsmoker_path, os.path.join('plugins', f"{plugin_name}.yaml")))
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
