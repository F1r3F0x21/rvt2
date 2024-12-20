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
import datetime
import base.job
from pathlib import Path
import json
import csv
from datetime import datetime, timedelta, timezone
from plugins.common.RVT_files import GetFiles
from base.utils import check_folder, check_directory, save_csv, relative_path
class WerParser(base.job.BaseModule):
    """ Class to parse information from a Report.wer file.
    Arguments:
        :infile (str): absolute path to wer file
    """
    def __init__(self, *args, **kwargs):
        #print("Hello world from __init__")
        super().__init__(*args, **kwargs)
    #    #self.dicID = load_appID(myconfig=self.myconfig)
        self.encoding = self.myconfig('encoding', 'cp1252')

    def run(self, path=""):
        #print("Hello world")

        self.logger().debug('"Input path to ReportArchive: " {}'.format(path))
        self.check_params(path, check_path=True, check_path_exists=True)

        # Define output file
        base_path = self.myconfig('outdir')
        check_folder(base_path)
        self.volume_id = self.myconfig('volume_id')
        #self.username = self.myconfig('username')

        if not os.path.isdir(path):
            raise base.job.RVTError('Provided path {} is not a directory'.format(path))


        check_directory(base_path, create=True)
        out_file_id = '' if not self.volume_id else '_{}'.format(self.volume_id)
        detailed_csv = os.path.join(base_path, "wer{}.csv".format(out_file_id))
        self.logger().debug('Saving all Windows Error reports to {}'.format(detailed_csv))
        '''
        save_csv(self.wer_parser(path), config=self.config, outfile=detailed_csv, file_exists='OVERWRITE',
                 quoting=0, encoding='utf-8')
        self.wer_parser(path)

        
        for artifact, properties in artifacts.items():
            for file in os.listdir(path):
                if file.lower().endswith(properties['ending']):
                    files[artifact].append(os.path.abspath(os.path.join(path, file)))
            out_file = os.path.join(self.myconfig('outdir'), "{}_{}_{}.csv".format(
                self.volume_id, self.username, artifact))
            if len(files[artifact]) > 0:
                self.logger().info("Founded {} {} files".format(len(files[artifact]), artifact))
                save_csv(properties['function'](files[artifact]), config=self.config, outfile=out_file, quoting=0, file_exists='APPEND')
                self.logger().info("{} extraction done".format(artifact))
            else:
                self.logger().debug('No {} files found'.format(artifact))
        '''

        wer_dir = Path(path)
        #wer_dir = Path("C:\\ProgramData\\Microsoft\\Windows\\WER\\ReportArchive")
        # C:/Users/*/AppData/Local/Microsoft/Windows/WER/ReportArchive"

        wer_results = []
        if wer_dir.exists():
            for item in wer_dir.iterdir():
                if item.is_dir():
                    report_path = Path(item, "Report.wer")
                    try:
                        if report_path.exists():
                            result = self.parse_wer_file(report_path)
                            if result:
                                try:
                                    wer_results.append(result)
                                except Exception as e:
                                    print(f"Error parsing file {report_path}. {e}")
                    except PermissionError as e:
                        print(f"Permission denied to {report_path}")

        if wer_results:
            #with Path(f"wer_results.csv").open("w", newline='') as csv_file:


            with Path(detailed_csv).open("a", newline='') as csv_file:
                csv_writer = csv.DictWriter(csv_file,
                                            fieldnames=["AppPath", "EventTime", "SHA1", "AppName", "NsAppName",
                                                        "OriginalFilename", "EventType", "FriendlyEventName",
                                                        "ReportType"], extrasaction="ignore")

                # If file is empty
                if Path(detailed_csv).stat().st_size == 0:
                    csv_writer.writeheader()
                csv_writer.writerows(wer_results)

        return []

    def read_config(self):
        super().read_config()

    def from_filetime(self, filetime: int):
        return datetime(1601, 1, 1).replace(tzinfo=timezone.utc) + timedelta(microseconds=filetime / 10)

    def parse_wer_file(self, filepath: Path):
        if filepath.exists() and filepath.name.lower() == "report.wer":
            wer_report = {}
            with filepath.open("r", encoding="utf-16") as f:
                last_key_name = ""
                for line in f:
                    line = line.strip()
                    sl = line.split("=", 1)
                    if "[" in sl[0] and "]" in sl[0]:
                        if "." in sl[0]:
                            field_name = sl[0].split("[", 1)[0]
                            if field_name not in wer_report:
                                wer_report[field_name] = {}

                            if ".Name" in sl[0] or ".Key" in sl[0]:
                                wer_report[field_name][sl[1].replace(" ", "")] = ""
                                last_key_name = sl[1].replace(" ", "")
                            else:
                                wer_report[field_name][last_key_name] = sl[1]
                        else:
                            field_name = sl[0].split("[", 1)[0]
                            field_value = sl[1]
                            if field_name == "LoadedModule":
                                field_value = field_value.lower()
                            if field_name in wer_report:
                                wer_report[field_name].append(field_value)
                            else:
                                wer_report[field_name] = [field_value]
                    elif "." in sl[0]:
                        field_name = sl[0].split(".", 1)
                        if field_name[0] not in wer_report:
                            wer_report[field_name[0]] = {field_name[1]: sl[1]}
                        else:
                            wer_report[field_name[0]][field_name[1]] = sl[1]
                    else:
                        wer_report[sl[0]] = sl[1]

            # Parse out SHA1 of executable. Same format as hash in AmCache. Only first 31,457,280 bytes of file get hashed
            if "TargetAppId" in wer_report and wer_report["TargetAppId"].startswith("W:"):
                tai_split = wer_report["TargetAppId"].split("!")
                if tai_split[1].startswith("0000"):
                    wer_report["SHA1"] = tai_split[1][4:]

            if "EventTime" in wer_report:
                wer_report["EventTime"] = self.from_filetime(int(wer_report["EventTime"]))
            if "UploadTime" in wer_report:
                wer_report["UploadTime"] = self.from_filetime(int(wer_report["UploadTime"]))

            return wer_report
        else:
            return None
