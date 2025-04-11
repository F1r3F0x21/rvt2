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
import xmltodict

import base.job
from base.utils import check_directory


class PowerEffiencyDiagnostic(base.job.BaseModule):

    def run(self, path=""):
        """ Extracts Power Efficiency Diagnostics artifacts of a disk """

        out_folder = self.myconfig('outdir')
        out_filename = os.path.join(out_folder, 'PowerEffiencyDiagnostic.txt')
        check_directory(out_folder, create=True)

        for filename in os.listdir(path):
            if not filename.endswith(".xml"):
                continue
            data = ""
            with open(os.path.join(path, filename)) as f_in:
                data = f_in.read()

            content = xmltodict.parse(data)
            with open(out_filename, 'a') as f_out:
                f_out.write(f"*********{filename}**********\n")
                for tshot in content["EnergyReport"]['Troubleshooter']:
                    if isinstance(tshot["AnalysisLog"]["LogEntry"], dict):
                        continue
                    for entry in tshot["AnalysisLog"]["LogEntry"]:
                        if entry['Name'] == "Timer Request Stack":
                            if isinstance(entry['Details']['Detail'], dict):
                                continue
                            for dt in entry['Details']['Detail']:
                                if dt['Name'] in ("Requesting Process ID", "Requesting Process Path", "Calling Module", "Process Name", "PID", "Average Utilization (%)", "Module"):
                                    f_out.write(f"{dt['Name']}, {dt['Value']}\n")
                        elif entry['Name'] == 'Individual process with significant processor utilization.':
                            isprocess = True
                            process = {}
                            modules = []
                            for dt in entry['Details']['Detail']:
                                if isprocess and dt['Name'] in ('Process Name', 'PID', 'Average Utilization (%)'):
                                    process[dt['Name']] = dt['Value']
                                elif isprocess and dt['Name'] == 'Module':
                                    isprocess = False
                                    modules.append(f"{dt['Name']}: {dt['Value']}")
                                elif not isprocess:
                                    modules.append(f"{dt['Name']}: {dt['Value']}")
                            f_out.write(f"\nProcess Name: {process['Process Name']}\nPID: {process.get('PID', '')}\nAverage Utilization (%): {process.get('Average Utilization (%)', '')}\nModules:\n")
                            for mod in zip(modules[::2], modules[1::2]):
                                f_out.write(f"\t{mod[0]}: {mod[1]}\n")
                f_out.write('\n')
        return []
