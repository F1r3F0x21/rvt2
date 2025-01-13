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
from datetime import datetime, timedelta, timezone
from base.utils import check_folder, check_directory, parse_microsoft_timestamp


class WerParser(base.job.BaseModule):
    """ Class to parse information from a Report.wer file.
    Arguments:
        :infile (str): absolute path to wer file
    """

    def run(self, path=""):
        self.logger().debug('"Input path to ReportArchive: " {}'.format(path))
        self.check_params(path, check_path=True, check_path_exists=True)

        # Define output file
        base_path = self.myconfig('outdir')
        check_folder(base_path)

        if not os.path.isdir(path):
            raise base.job.RVTError('Provided path {} is not a directory'.format(path))

        check_directory(base_path, create=True)

        wer_dir = Path(path)
        # wer_dir = Path("C:\\ProgramData\\Microsoft\\Windows\\WER\\ReportArchive")
        # C:/Users/*/AppData/Local/Microsoft/Windows/WER/ReportArchive"

        wer_results = []
        if not wer_dir.exists():
            return []
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
                                self.logger().error(f"Permission denied to {report_path}")
                except PermissionError as e:
                    self.logger().error(f"Permission denied to {report_path}")

        if wer_results:
            for w in wer_results:
                yield w

        return []

    def read_config(self):
        super().read_config()
        self.set_default_config('encoding', 'utf-16')

    def parse_wer_file(self, filepath: Path):
        encoding = self.myconfig('encoding')
        if filepath.exists() and filepath.name.lower() == "report.wer":
            wer_report = {}
            with filepath.open("r", encoding=encoding) as f:
                last_key_name = ""
                for line in f:
                    line = line.strip()     # remove newlines, leading and trailing whitespace
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
                    elif "." in sl[0]: # e.g. Response.BucketId = some_val
                        field_name = sl[0].split(".", 1)
                        if field_name[0] not in wer_report:
                            wer_report[field_name[0]] = {field_name[1]: sl[1]}
                        else:
                            wer_report[field_name[0]][field_name[1]] = sl[1]
                    else: # base case, Line uses simple encoding of KEY=VALUE
                        wer_report[sl[0]] = sl[1]

            # Parse out SHA1 of executable. Same format as hash in AmCache. Only first 31,457,280 bytes of file get hashed
            if "TargetAppId" in wer_report and wer_report["TargetAppId"].startswith("W:"):
                tai_split = wer_report["TargetAppId"].split("!")
                if tai_split[1].startswith("0000"):
                    wer_report["SHA1"] = tai_split[1][4:4 + 40]

            if "EventTime" in wer_report:
                wer_report["EventTime"] = parse_microsoft_timestamp(int(wer_report["EventTime"]))
            if "UploadTime" in wer_report:
                wer_report["UploadTime"] = parse_microsoft_timestamp(int(wer_report["UploadTime"]))

            return wer_report
        else:
            return None