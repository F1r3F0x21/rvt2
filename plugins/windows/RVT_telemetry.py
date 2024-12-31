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
import struct
import zlib
import json
import ast
import re

import base.job
from base.utils import check_directory, parse_microsoft_timestamp


class Telemetry(base.job.BaseModule):

    def run(self, path=""):
        """ Parses Windows Telemetry rbs files """

        self.check_params(path, check_path=True, check_path_exists=True)
        base_path = self.myconfig('outdir')
        check_directory(base_path, create=True)
        item = RBS(path)

        stats_file = os.path.join(base_path, 'stats.csv')
        exists_stats = os.path.exists(stats_file)

        with open(stats_file, 'a') as f_out:
            if not exists_stats:
                f_out.write('Filename;date;elements\n')
            f_out.write(f'{path};{item.headers["time"]};{item.headers["num_elements"]}\n')

        for entry in item.items:
            yield entry
        return []


structure = {'UTCRBES3': {'fileheaders': '<q16xII2x',
                          'fieldheaders': ['time', 'num_elements', 'num_elements2'],
                          'itemsheaders': '<12xII2x',
                          'fielditems': ['size', 'ktype']},
             'UTCRBES5': {'fileheaders': '<q20xI13x',
                          'fieldheaders': ['time', 'num_elements'],
                          'itemsheaders': '<20xII1x',
                          'fielditems': ['size', 'ktype']},
             'UTCRBES7': {'fileheaders': '<qIIIIII13x',
                          'fieldheaders': ['time', 'offset1', 'offset2', 'size1', 'size2', 'num_elements', 'num_elements2'],
                          'itemsheaders': '<12sIIIHHI2x',
                          'fielditems': ['logID', 'blk_id', 'encoded_size', 'unkn', 'size', 'size2', 'ktype']},
             'UTCRBES8': {'fileheaders': '<qIIIIII13x',
                          'fieldheaders': ['time', 'offset1', 'offset2', 'size1', 'size2', 'num_elements', 'num_elements2'],
                          'itemsheaders': '<12sIIIHHI2x',
                          'fielditems': ['logID', 'blk_id', 'encoded_size', 'unkn', 'size', 'size2', 'ktype']}}


class Filter_Events(base.job.BaseModule):
    """ Filters events """

    def run(self, path=None):
        event_names = ast.literal_eval(self.config.config[self.config.job_name]['event_names'])
        regex = re.compile(f"({'|'.join(event_names)})")

        for event in self.from_module.run(path):
            if regex.search(event['name']):
                yield event


class ProductState(base.job.BaseModule):
    def run(self, path):
        """ Transforms data.ProductState """

        for event in self.from_module.run(path):
            data = event['data']['ProductState']
            state = ""
            if data & 0x3000 == 0x3000:
                state = "EXPIRED"
            elif data & 0x2000 == 0x2000:
                state = "SNOOZED"
            elif data & 0x1000 == 0x1000:
                state = "ON"
            else:
                state = "OFF"

            if data & 0x10 == 0x10:
                state += ", OUT_OF_DATA"
            else:
                state += ", UP_TO_DATE"

            if data & 0x100 == 0x100:
                state += ", MICROSOFT_PRODUCT"
            else:
                state += ", NON_MICROSOFT_PRODUCT"
            event['data']['ProductState'] = state
            yield event


class Split_AppId_Field(base.job.BaseModule):
    def run(self, path):
        """ gets relevant data of ApplicationExecution """

        for event in self.from_module.run(path):
            if 'AppId' in event['data'].keys():
                temp_binary_list = event['data']['AppId'].split('!')
                app_ver = event['data']['AppVersion']
            else:
                temp_binary_list = event['appId'].split('!')
                app_ver = event['appVer']

            if temp_binary_list[0][0] == "W":
                binary_hash = temp_binary_list[1][4:]
                compiler_timestamp = app_ver.split('!')[0].replace("/", "-").replace(":", " ", 1)
                binary_name = app_ver.split('!')[2]
            elif temp_binary_list[0][0] == "U":
                binary_hash = ""
                compiler_timestamp = app_ver.split('!')[1].replace("/", "-").replace(":", " ", 1)
                binary_name = app_ver.split('!')[3]

            event.update({'binary_name': binary_name, 'binary_hash': binary_hash, 'compiler_timestamp': compiler_timestamp})
            yield event


class RBS(object):
    """
    Parses rbs files from Windows Telemetry

    https://www.researchgate.net/profile/Jaehyeok-Han-2/publication/339615989_Forensic_analysis_of_the_Windows_telemetry_for_diagnostics/links/6180a5053c987366c3165138/Forensic-analysis-of-the-Windows-telemetry-for-diagnostics.pdf
    """

    def __init__(self, fname=None):
        self.headers = {}
        self.items = []
        self.item_frmt = None
        self.item_fields = None
        if fname is not None:
            self.parse(fname)
        self.headers.pop('r_date_values')

    def parse(self, fname):
        f_in = open(fname, 'rb')
        magic = f_in.read(8).decode()
        self.get_headers(magic, f_in)
        for item in range(max(self.headers['num_elements'], self.headers['num_elements2'])):
            item_header = f_in.read(struct.calcsize(self.item_frmt))
            if len(item_header) < 1:
                break
            self.get_item(item_header, f_in)
        f_in.close()

    def get_headers(self, magic, f_in):
        if magic not in structure.keys():
            exit(1)
        frmt = structure[magic]['fileheaders']
        buf = f_in.read(struct.calcsize(frmt))
        self.headers['r_date_values'] = buf[6:8]  # value to find in case getting items fails
        aux = struct.unpack(frmt, buf)
        for e, item in enumerate(structure[magic]['fieldheaders']):
            if item == 'time':
                self.headers[item] = parse_microsoft_timestamp(aux[e]).strftime("%Y-%m-%d %H:%M:%S")
            else:
                self.headers[item] = aux[e]
        self.item_frmt = structure[magic]['itemsheaders']
        self.item_fields = structure[magic]['fielditems']

    def get_item(self, item, f_in):
        aux = struct.unpack(self.item_frmt, item)
        size = aux[self.item_fields.index('size')]
        act_position = f_in.tell()
        f_in.read(aux[self.item_fields.index('encoded_size')])
        data = f_in.read(size)
        try:
            uncompressed = zlib.decompress(data, wbits=-zlib.MAX_WBITS).rstrip().split(b'\r\n')
        except Exception:
            return
        for i in uncompressed:
            self.items.append(json.loads(i.decode()))

    def __str__(self):
        str_out = json.dumps(self.headers)
        for item in self.items:
            str_out = f"{str_out}\n{json.dumps(item)}"
        return str_out
