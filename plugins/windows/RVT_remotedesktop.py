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


import datetime
import re
import os
import xmltodict
import base64
import base.job
from base.utils import check_folder, save_csv


class Teamviewer_connections(base.job.BaseModule):
    """ Extracts teamviewer connections information """

    def run(self, path=None):
        """
        Attrs:
            path (str): Absolute path to the Connections_incoming.txt or Connections.txt file
        """

        self.check_params(path, check_path=True, check_path_exists=True)

        partition = ''
        user = ''

        srch = re.search(r'/(p\d{1,2})/', path)
        if srch:
            partition = srch.group(1)
        srch = re.search(r'/p\d{1,2}/Users/([^/]*)/', path)
        if srch:
            user = srch.group(1)

        lfields = False

        if path.endswith('incoming.txt'):
            srch = re.compile(r'^(\d+)\s+([^\t]+)\s+(\d{2}-\d{2}-\d{4} \d{2}:\d{2}:\d{2})\s+(\d{2}-\d{2}-\d{4} \d{2}:\d{2}:\d{2})\s+(\S+)\s+(\w+)')
            lfields = True
        else:
            srch = re.compile(r'^(\d+)\s+(\d{2}-\d{2}-\d{4} \d{2}:\d{2}:\d{2})\s+(\d{2}-\d{2}-\d{4} \d{2}:\d{2}:\d{2})\s+(\S+)\s+(\w+)')

        with open(path, 'r') as fin:
            for line in fin:
                if len(line) < 2:
                    continue
                fields = srch.search(line)
                if not fields:
                    self.logger().warning(f'Unable to parse line: {line}')
                    continue
                if lfields:
                    yield {
                        'startdate': str(datetime.datetime.strptime(fields.group(3), "%d-%m-%Y %H:%M:%S")),
                        'enddate': str(datetime.datetime.strptime(fields.group(4), "%d-%m-%Y %H:%M:%S")),
                        'teamviewer.hostname': fields.group(2).strip(),
                        'id_connection': fields.group(1),
                        'machine.hostname': fields.group(5),
                        'mode': fields.group(6),
                        'partition': partition}
                else:
                    yield {
                        'startdate': str(datetime.datetime.strptime(fields.group(2), "%d-%m-%Y %H:%M:%S")),
                        'enddate': str(datetime.datetime.strptime(fields.group(3), "%d-%m-%Y %H:%M:%S")),
                        'machine.hostname': fields.group(4),
                        'id.connection': fields.group(1),
                        'mode': fields.group(5),
                        'partition': partition,
                        'winuser': user}


class Anydesk(base.job.BaseModule):
    """ Extracts information about anydesk logs """

    def run(self, path=None):
        """
        Attrs:
            path (str): Absolute path to the ad.trace file
        """

        self.check_params(path, check_path=True, check_path_exists=True)
        base_path = self.myconfig('outdir')
        check_folder(base_path)

        # Induce "partition" and "user" from "path". If path is in ProgramData, no user is assigned
        partition = ''
        user = ''
        srch = re.search(r'/(p\d{1,2})/', path)
        if srch:
            partition = srch.group(1)
        srch = re.search(r'/p\d{1,2}/Users/([^/]*)/', path)
        if srch:
            user = srch.group(1)
        outfile = os.path.join(base_path, 'anydesk_{}{}.csv'.format(partition, f'_{user}' if user else ''))
        save_csv(self._process_anydesk_log(path), outfile=outfile, file_exists='OVERWRITE', quoting=0)

    def _process_anydesk_log(self, path):
        # Get only significant events and skip the rest
        regex = re.compile(r'(External address|anynet.connection_mgr|Incoming session|Sending a connection request|Client-ID|app.prepare_task|Files|Logged|Connecting to|Accept request from|New user data)')

        result = {}
        with open(path, 'r') as fin:
            for line in fin:
                if regex.search(line):
                    result['log.level'] = line[:8].strip()
                    result['@timestamp'] = line[8:31]
                    result['log.syslog.appname'] = line[31:42].strip()
                    # result['id1'] = line[43:49].strip()
                    # result['id2'] = line[50:56].strip()
                    result['log.logger'] = line[56:94].strip()
                    result['message'] = line[97:].strip()
                    yield result


class RemoteDesktopApp(base.job.BaseModule):
    """ Extracts information about remotedesktop app """

    def run(self, path=None):
        """
        Attrs:
            path (str): Absolute path to the Users/<user>/AppData/Local/Packages/Microsoft.RemoteDesktop_8wekyb3d8bbwe folder
        """

        self.check_params(path, check_path=True, check_path_exists=True)
        base_path = self.myconfig('outdir')
        check_folder(base_path)

        partition = ''
        user = ''

        srch = re.search(r'/(p\d{1,2})/', path)
        if srch:
            partition = srch.group(1)
        srch = re.search(r'/p\d{1,2}/Users/([^/]*)/', path)
        if srch:
            user = srch.group(1)
        outfile = os.path.join(base_path, 'remotedesktopapp_jumplist_{}{}.csv'.format(partition, f'_{user}' if user else ''))
        save_csv(self._process_files(os.path.join(path, 'LocalState', 'RemoteDesktopData', 'JumpListConnectionArgs'), ['a:ConnectionId', 'a:Description', 'a:LastLaunch', 'a:DisplayName']), outfile=outfile, file_exists='OVERWRITE', quoting=0)
        outfile = os.path.join(base_path, 'remotedesktopapp_credentials_{}{}.csv'.format(partition, f'_{user}' if user else ''))
        save_csv(self._process_files(os.path.join(path, 'LocalState', 'RemoteDesktopData', 'credentials'), ['a:FriendlyName', 'a:PasswordVaultResourceID', 'a:Username']), outfile=outfile, file_exists='OVERWRITE', quoting=0)
        outfile = os.path.join(base_path, 'remotedesktopapp_connections_{}{}.csv'.format(partition, f'_{user}' if user else ''))
        save_csv(self._process_files(os.path.join(path, 'LocalState', 'RemoteDesktopData', 'LocalWorkspace', 'connections'), ['a:CredentialsId', 'a:FriendlyName', 'a:HostName']), outfile=outfile, file_exists='OVERWRITE', quoting=0)
        self._process_thumbnails(os.path.join(path, 'LocalState', 'RemoteDesktopData', 'RemoteResourceThumbnails'), base_path)

    def _process_files(self, dirpath, fields):
        if os.path.isdir(dirpath):
            for fname in os.listdir(dirpath):
                if not fname.endswith('.model'):
                    continue
                b = ''
                with open(os.path.join(dirpath, fname), 'r') as fin:
                    b = fin.read()
                b = xmltodict.parse(b)
                result = {'filename': fname}
                for field in fields:
                    result[field[2:]] = b['SerializableModel'].get(field, '')
                yield result

    def _process_thumbnails(self, thumbnailpath, outpath):
        if os.path.isdir(thumbnailpath):
            for fname in os.listdir(thumbnailpath):
                if not fname.endswith('.model'):
                    continue
                b = ''
                with open(os.path.join(thumbnailpath, fname), 'r') as fin:
                    b = fin.read()
                b = xmltodict.parse(b)
                if len(b) > 1 and 'EncodedThumbnail' in b['SerializableModel'].keys():
                    with open(os.path.join(outpath, f"remotedesktop_thumb_{fname[:-5]}.jpg"), 'wb') as fout:
                        fout.write(base64.b64decode(b['SerializableModel']['EncodedThumbnail']))
