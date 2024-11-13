#!/usr/bin/env python3
#
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
import dateutil.parser
import urllib.parse
from os.path import splitext
import base.job
from base.utils import sanitize_ip

# ECS Reference: https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html
# There are 4 categorization fields for events: event.kind, event.category, event.type, event.outcome
# At least the first 3 should be defined for every event


def to_date(strtimestamp):
    """ Converts a timestamp string in UNIX into a date """
    return datetime.datetime.fromtimestamp(int(strtimestamp), datetime.timezone.utc).isoformat()


def to_iso_format(timestring):
    """ Converts a date string into iso format date """
    if not timestring or timestring == 'Never' or timestring == '-':
        return datetime.datetime.fromtimestamp(0, datetime.timezone.utc).isoformat()
    try:
        return datetime.datetime.strptime(timestring, '%Y-%m-%d %H:%M:%S').isoformat()
    except Exception:
        try:
            return datetime.datetime.strptime(timestring, '%Y-%m-%d T%H:%M:%SZ').isoformat()
        except Exception:
            return dateutil.parser.parse(timestring).isoformat()


def to_geolocation(lon_lat_string):
    """ Converts geo coordinates to ElasticSearch suitable format """
    # TODO: Yet to implement in case input format is not accepted
    # https://www.elastic.co/guide/en/elasticsearch/reference/current/geo-point.html
    return lon_lat_string


def permissions_to_octal(tsk_permisssion):
    """ Convert a tsk permission string to octal format """
    equivalence = {
        "---": "0",
        "--x": "1",
        "-w-": "2",
        "-wx": "3",
        "r--": "4",
        "r-x": "5",
        "rw-": "6",
        "rwx": "7"
    }
    permission = ['0'] * 4
    try:
        permission[1] = equivalence[tsk_permisssion[-9:-6]]
        permission[2] = equivalence[tsk_permisssion[-6:-3]]
        permission[3] = equivalence[tsk_permisssion[-3:]]
        return ''.join(permission)
    except KeyError:
        return '0000'
    return permission


def filetype(tsk_permisssion):
    """ Get file type from a tsk permission string """
    # File mode by tsk: https://wiki.sleuthkit.org/index.php?title=Fls
    types = {
        "-": "unknown",
        "r": "file",
        "d": "dir",
        "c": "character",
        "b": "block",
        "l": "symlink",
        "p": "fifo",
        "s": "shadow",
        "h": "socket",
        "w": "whiteout",
        "v": "Virtual"
    }
    return types.get(tsk_permisssion[0], 'unknown')


def decompose_url(full_url):
    """ Returns a dictionary with multiple fields for a full url using Elastic Common Schema """
    new_fields = {}
    url_fields = {'scheme': 'url.scheme', 'netloc': 'url.domain', 'path': 'url.path',
                  'query': 'url.query', 'fragment': 'url.fragment', 'username': 'url.username',
                  'password': 'url.password', 'port': 'url.port'}
    url = urllib.parse.urlparse(full_url)

    for k, v in zip(url._fields, url):  # url is a namedtuple
        if k in url_fields and v:
            new_fields[url_fields[k]] = v
    _, ext = splitext(url.path)
    if ext:
        new_fields['url.extension'] = ext.lstrip('.')
    return new_fields


class SuperTimeline(base.job.BaseModule):
    """ Main class to adapt any forensic source containing timestamped events to
        JSON format suitable for Elastic Common Schema (ECS)

        Configuration section:
            - **classify**: If True, categorize the files in the output.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._classifier = False

    def read_config(self):
        super().read_config()
        self.set_default_config('classify', 'True')

    def common_fields(self, kind='event', category=[''], type=[''], module=''):
        """ Get a new dictionary of mandatory fields for all sources """
        return {'host.domain': self.myconfig('client'),
                'host.name': self.myconfig('source'),
                'event.kind': kind,  # one of: alert, event, metric, state, pipeline_error, signal
                'event.category': category,  # one or more of: authentication, database, driver, file, host, intrusion_detection, malware, package, process, web
                'event.type': type,  # one or more of: access, change, creation, deletion, end, error, info, installation, start
                'event.module': module}

    def filegroup(self, entry, classify=True):
        """ Return the category group given an extension, path or content_type """
        if self._classifier is False:
            if classify:
                self._classifier = base.job.load_module(self.config, 'base.directory.FileClassifier')
            else:
                self._classifier = None

        if self._classifier is None:
            return ''

        return self._classifier.classify(entry)

    def run(self, path=None):
        try:
            self.check_params(path, check_from_module=True, check_path=True, check_path_exists=True)
        except base.job.RVTErrorNotExistingPath as exc:
            self.logger().warning('{} events will not be generated: {}'.format(self.__class__.__name__, exc))
            return []
        # raise NotImplementedError


class ECSFields(SuperTimeline):
    """ Adds ECS common fields to an event

    Configuration section:
        - **module** (str): event.module field.
        - **category** (list): event.category field. One or more of: authentication, database, driver, file, host, intrusion_detection, malware, package, process, web
        - **type** (list): event.type field. One or more of: access, change, creation, deletion, end, error, info, installation, start
        - **kind** (str): event.kind field. One of: alert, event, metric, state, pipeline_error, signal
    """

    def read_config(self):
        super().read_config()
        self.set_default_config('module', '')
        self.set_default_config('kind', 'event')
        self.set_default_config('category', [''])
        self.set_default_config('type', [''])

    def run(self, path=None):
        for d in self.from_module.run(path):
            common = self.common_fields(kind=self.myconfig('kind'),
                                        category=self.myconfig('category'),
                                        type=self.myconfig('type'),
                                        module=self.myconfig('module'))
            common.update(d)
            yield common


class Timeline(SuperTimeline):
    """
    Convert a BODY file to events. After this, you can save this file using events.save

    Configuration section:
        - **include_filename**: if True, include FILENAME entries in the output.
        - **classify**: If True, categorize the files in the output.
    """

    def read_config(self):
        super().read_config()
        self.set_default_config('include_filename', 'False')
        self.set_default_config('classify', 'True')

    def run(self, path=None):
        """ Converts a BODY file read from from_module into an Elastic Common Schema document. """
        super().run(path)

        for d in self.from_module.run(path):
            filename = os.path.basename(d['path'])
            # do not include FILE_NAME entries if the option is on
            if (not self.myflag('include_filename')) and '$FILE_NAME' in filename:
                continue
            # Get the deleted status of the file and strip the termination
            deleted = 'false'
            if filename.endswith(' (deleted)'):
                filename = filename[: - len(' (deleted)')]
                deleted = 'true'
            elif filename.endswith(' (deleted-realloc)'):
                filename = filename[: - len(' (deleted-realloc)')]
                deleted = 'true'

            common = self.common_fields()
            common.update({
                'tags': ['fs'],
                'event.category': ['file'],
                'event.module': 'filesystem',
                'event.dataset': 'MFT',
                'file.path': d['path'],
                'file.directory': os.path.dirname(d['path']),
                'file.extension': os.path.splitext(filename)[1].lstrip('.'),
                'file.name': filename,
                'file.accessed': to_date(d['file_access']),
                'file.created': to_date(d['file_birth']),
                'file.mtime': to_date(d['file_modified']),
                'file.ctime': to_date(d['file_changerecord']),
                'file.size': d['file_size'],
                'file.inode': d['file_inode'],
                'file.uid': d['file_uid'],
                'file.gid': d['file_gid'],
                'file.mode': permissions_to_octal(d['file_mode']),
                'file.type': filetype(d['file_mode']),
                'file.group': self.filegroup(d, self.myflag('classify')) or '',
                'file.deleted': deleted
            })

            common.update({
                '@timestamp': to_date(d['file_birth']),
                'message': 'File birth: ' + d['path'],
                'event.action': 'file-birth',
                'event.type': ['creation']
            })
            yield common
            common.update({
                '@timestamp': to_date(d['file_modified']),
                'message': 'File modified: ' + d['path'],
                'event.action': 'file-modified',
                'event.type': ['change']
            })
            yield common
            common.update({
                '@timestamp': to_date(d['file_changerecord']),
                'message': 'File change record: ' + d['path'],
                'event.action': 'file-changed',
                'event.type': ['change']
            })
            yield common
            common.update({
                '@timestamp': to_date(d['file_access']),
                'message': 'File access: ' + d['path'],
                'event.action': 'file-accessed',
                'event.type': ['access']
            })
            yield common


class Characterize(SuperTimeline):
    """ Converts OS characterization to ECS suitable events
    """

    def run(self, path=None):
        super().run(path)

        fields = {
            'host.architecture': 'ProcessorArchitecture',
            'host.id': 'ProductId',
            # 'host.mac': 'NONE',
            'host.type': 'InstallationType',
            'os.full': 'ProductName',
            'os.kernel': 'CurrentBuild',
            'os.name': 'ComputerName',
            'os.type': 'windows',
            # 'os.version': 'CurrentVersion',
            # 'os.family': 'NONE',
            'event.timezone': 'TimeZone',
            'user.name': 'RegisteredOwner',
            'user.domain': 'RegisteredOrganization',
            'host.ip': 'IpAddress'
        }

        for d in self.from_module.run(path):

            common = self.common_fields()
            common.update({
                'tags': ['characterize'],
                'event.category': ['configuration'],
                'event.type': ['info'],
                'event.module': 'characterize',
                'event.dataset': 'characterize',
            })

            # General OS information extracted from the registry
            for p_name, partition in d.items():
                common['container.id'] = p_name
                for ecs_field, rvt_field in fields.items():
                    common[ecs_field] = partition.get(rvt_field, "")
                # OS installation date and last standard shutdown date
                common['event.created'] = to_iso_format(partition.get('InstallDate', None))
                common['event.end'] = to_iso_format(partition.get('ShutdownTime', None))
                common['@timestamp'] = common['event.created']
                yield common

                # Users information
                for user, details in partition.get('users', []).items():
                    common = self.common_fields()
                    common.update({
                        'tags': ['users'],
                        'event.category': ['configuration'],
                        'event.type': ['info'],
                        'event.module': 'characterize',
                        'event.dataset': 'characterize',
                        'user.name': user,
                        'file.created': to_iso_format(details.get('creation_time', None)),
                        'file.mtime': to_iso_format(details.get('last_write', None)),
                        '@timestamp': to_iso_format(details.get('last_write', None))
                    })
                    yield common
                for user, details in partition.get('user_profiles', []).items():
                    common = self.common_fields()
                    common.update({
                        'tags': ['users'],
                        'event.category': ['configuration'],
                        'event.type': ['info'],
                        'event.module': 'characterize',
                        'event.dataset': 'characterize',
                        'user.name': user,
                        'user.id': details.get('sid', ""),
                        'file.created': to_iso_format(details.get('creation_time', None)),
                        'file.mtime': to_iso_format(details.get('last_write', None)),
                        '@timestamp': to_iso_format(details.get('creation_time', None))
                    })
                    yield common


class Status_GRR(SuperTimeline):
    """ Converts GRR status to ECS suitable events
    """

    def run(self, path=None):
        super().run(path)

        for d in self.from_module.run(path):

            common = self.common_fields()
            common.update({
                'host.name': d.get('info', dict()).get('host', d.get('client_id', "")),
                '@timestamp': to_iso_format(d.get('info', dict()).get('first_seen', None)),
                'tags': ['characterize'],
                'event.category': ['configuration'],
                'event.type': ['info'],
                'event.module': 'characterize',
                'event.dataset': 'grr',
                'agent.id': d.get('client_id', ""),
                'client.address': d.get('info', dict()).get('addresses', list()),
                'os.family': d.get('info', dict()).get('system', list()),
                'agent.version': d.get('info', dict()).get('agent_version', list()),
            })

            # General client information
            yield common

            # Volumes (drives) information
            common['tags'] = ['volumes']
            for v in d.get('info', {}).get('volumes', list()):
                common.update({
                    'file.drive_letter': v.get('drive_letter', ""),
                    'event.data.DriveSize': v.get('size', ""),
                    'package.type': v.get('drive_type', ""),
                    'event.data.FileSystem': v.get('file_system_type', ""),
                })
                yield common

            # Flows information
            common = self.common_fields()
            common.update({
                'host.name': d.get('info', dict()).get('host', d.get('client_id', "")),
                'tags': ['flows'],
                'event.category': ['configuration'],
                'event.type': ['info'],
                'event.module': 'characterize',
                'event.dataset': 'grr',
                'agent.id': d.get('client_id', ""),
                'client.address': d.get('info', dict()).get('addresses', list()),
                'agent.version': d.get('info', dict()).get('agent_version', list()),
            })
            for f_name, flow in d.get('flows', dict()).items():
                common.update({
                    '@timestamp': to_iso_format(flow.get('started_at')),
                    'event.data.FlowLastChecked': to_iso_format(flow.get('last_checked')),
                    'event.data.FlowFinishedAt': to_iso_format(flow.get('finished_at')),
                    'event.data.FlowId': f_name,
                    'event.data.FlowName': flow.get('default_flow', ""),
                    'event.data.FlowState': flow.get('state', ""),
                    'user.name': flow.get('creator', ""),
                })
                yield common


class RDPIncoming(SuperTimeline):
    """ Converts event logs output files for RDP incoming connections to events. After this, you can save this file using events.save.
    """

    def run(self, path=None):

        for d in self.from_module.run(path):

            common = self.common_fields()
            common.update({
                'tags': ['rdp'],
                'event.category': ['session'],
                'event.module': 'event_logs',
                'event.dataset': 'rdp',
                'network.direction': 'inbound',
                'event.start': to_iso_format(d.get('LoginDate', None)),
                'event.end': to_iso_format(d.get('LogoffDate', None)),
                'user.name': d.get('User', ''),
                'source.ip': d.get('SourceAddress', None),
                'source.address': d.get('SourceAddress', None),
                'event.data.ConnectionType': d.get('Comments', '')
            })

            if d.get('LoginDate', None):
                common.update({
                    '@timestamp': common['event.start'],
                    'event.action': 'incoming-session-start',
                    'message': 'Incoming RDP session started',
                    'event.type': ['connection', 'start']
                })
                yield common
            if d.get('LogoffDate', None):
                common.update({
                    '@timestamp': common['event.end'],
                    'event.action': 'incoming-session-end',
                    'message': 'Incoming RDP session finished',
                    'event.type': ['connection', 'end']
                })
                yield common


class RDPOutgoing(SuperTimeline):
    """ Converts event logs output files for RDP outgoing connections to events. After this, you can save this file using events.save.
    """

    def run(self, path=None):

        for d in self.from_module.run(path):

            common = self.common_fields()
            common.update({
                'tags': ['rdp'],
                'event.category': ['session'],
                'event.module': 'event_logs',
                'event.dataset': 'rdp',
                'network.direction': 'outbound',
                'event.start': to_iso_format(d.get('LoginDate', None)),
                'event.end': to_iso_format(d.get('LogoffDate', None)),
                'user.name': d.get('User', ''),
                'user.id': d.get('SID', ''),
                'destination.ip': d.get('Address', None),
                'destination.address': d.get('Address', None)
            })

            if d.get('LoginDate', None):
                common.update({
                    '@timestamp': common['event.start'],
                    'event.action': 'outgoing-session-start',
                    'message': 'Outgoing RDP session started',
                    'event.type': ['connection', 'start']
                })
                yield common
            if d.get('LogoffDate', None):
                common.update({
                    '@timestamp': common['event.end'],
                    'event.action': 'outgoing-session-end',
                    'message': 'Outgoing RDP session finished',
                    'event.type': ['connection', 'end']
                })
                yield common


class RecentFiles(SuperTimeline):
    """ Converts Lnk and Jumplists to events. After this, you can save this file using events.save.

    Configuration section:
        - **classify**: If True, categorize the files in the output.
    """

    def read_config(self):
        super().read_config()
        self.set_default_config('classify', 'True')

    def run(self, path=None):
        super().run(path)

        for d in self.from_module.run(path):

            common = self.common_fields()
            common.update({
                'tags': ['recentfiles'],
                'event.category': ['file'],
                'event.type': ['access'],
                'event.module': 'recentfiles',
                'event.dataset': d['artifact'],
                'process.name': d['application'],
                'recent.last_open': to_iso_format(d['last_open_date']),
                'recent.first_open': to_iso_format(d['first_open_date']),
                'volume.device_type': d['drive_type'],
                'volume.serial_number': d['drive_sn'],
                'volume.device_name': d['machine_id'],
                'log.file.path': d['file'],
                'user.name': d['user'],
                'file.size': d['size'],
            })

            if d['path']:
                common.update({
                    'file.path': d['path'],
                    'file.directory': os.path.dirname(d['path']),
                    'file.extension': os.path.splitext(d['path'])[1].lstrip('.'),
                    'file.name': os.path.basename(d['path']),
                    'file.group': self.filegroup(d, self.myflag('classify')) or ''
                })

            if d['artifact'] == 'lnk':
                common.update({
                    '@timestamp': to_iso_format(d['last_open_date']),
                    'message': 'File last opened: ' + d['path'],
                    'event.action': 'file-last-opened'
                })
                yield common
                common.update({
                    '@timestamp': to_iso_format(d['first_open_date']),
                    'message': 'File first opened: ' + d['path'],
                    'event.action': 'file-first-opened'
                })
                yield common

            elif d['artifact'] == 'jlauto':
                common.update({
                    '@timestamp': to_iso_format(d['last_open_date']),
                    'message': 'File last opened: ' + d['path'],
                    'event.action': 'file-last-opened'
                })
                yield common

            elif d['artifact'] == 'jlcustom':
                common.update({
                    '@timestamp': datetime.datetime.fromtimestamp(0).isoformat(),  # No timestamp. Set to LINUX epoch
                    'message': 'File last opened: ' + d['path'],
                    'event.action': 'file-last-opened'
                })
                yield common


class BrowsersHistory(SuperTimeline):
    """ Converts browsers history to events. After this, you can save this file using events.save.
    """

    def run(self, path=None):
        super().run(path)

        for d in self.from_module.run(path):

            common = self.common_fields()
            common.update({
                'tags': ['browsers'],
                'user.name': d['user'],
                'event.category': ['web'],
                'event.type': ['access'],
                'event.module': 'browsers',
                'event.dataset': 'history',
                'event.action': 'url-last-visited',
                'user_agent.name': d['browser'],
                'url.full': d['url'],
                'url.last_visit': to_iso_format(d['last_visit']),
                'message': 'Url visited: ' + d['url']
            })
            # Expand URL information. WebCache may include also files visited and not only urls
            if d['browser'] != 'edge':
                common.update(decompose_url(d['url']))

            # Edge legacy format is equal to Chrome
            if d['browser'] == 'chrome' or d['browser'] == 'edge_legacy':
                common.update({
                    '@timestamp': to_iso_format(d['visit_date']),
                    'url.title': d['title'],
                    'url.visit_count': d['visit_count'],
                    'url.visit_type': d['visit_type'],
                    'url.visit_type_description': d['type_description'],
                    'url.visit_duration': d['visit_duration']
                })
                yield common

            elif d['browser'] == 'firefox':
                common.update({
                    '@timestamp': to_iso_format(d['last_visit']),
                    'url.title': d['title'],
                    'url.visit_count': d['visit_count'],
                    'url.visit_type': d['visit_type'],
                    'url.visit_type_description': d['type_description']
                })
                yield common

            elif d['browser'] == 'safari':
                common.update({
                    '@timestamp': to_iso_format(d['last_visit']),
                    'url.title': d['title']
                })
                yield common

            elif d['browser'] == 'ie':
                common.update({
                    '@timestamp': to_iso_format(d['last_visit']),
                    'url.last_checked': d['last_checked']
                })
                yield common

            elif d['browser'] == 'edge':
                common['@timestamp'] = to_iso_format(d['last_visit'])
                url_extended = decompose_url(d['url'])
                # WebCache content may include access to files with Windows Explorer
                if d['url'].startswith('file:'):
                    file_path = urllib.parse.unquote(url_extended['url.path'][1:])
                    common.update({
                        'event.action': 'file-last-opened',
                        'event.category': ['file'],
                        'file.path': file_path,
                        'file.directory': os.path.dirname(file_path),
                        'file.extension': os.path.splitext(file_path)[1].lstrip('.'),
                        'file.name': os.path.basename(file_path),
                        'file.group': self.filegroup(dict({'path': file_path}), self.myflag('classify')) or '',
                        'url.visit_count': d.get('visit_count','0')
                    })
                # Entries starting with "Host:" are always followed by another entry with the actual visit. Can be skipped
                elif d['url'].startswith(':Host:'):
                    continue
                else:
                    common.update(url_extended)
                    common.update({
                        'file.mtime': to_iso_format(d['modified']),
                        'url.visit_count': d.get('visit_count','0')
                    })
                yield common


class BrowsersCookies(SuperTimeline):
    """ Converts browsers cookies to events. After this, you can save this file using events.save.
    """

    def run(self, path=None):
        super().run(path)

        for d in self.from_module.run(path):

            common = self.common_fields()
            common.update({
                'tags': ['browsers'],
                'user.name': d['user'],
                'event.category': ['web'],
                'event.module': 'browsers',
                'event.dataset': 'cookies',
                'user_agent.name': d['browser'],
                'url.original': d['url'],
                'cookie.name': d.get('cookie_name', ''),
                'cookie.value': d.get('cookie_value', ''),
                'cookie.created': to_iso_format(d.get('creation', '1970-01-01 01:00:00'))
            })
            if 'accessed' in d:
                common.update({'cookie.accessed': to_iso_format(d.get('accessed', '1970-01-01 01:00:00'))})

            # One of Edge formats is equal to Chrome. Not the other
            if d['browser'] in ['chrome', 'firefox', 'edge'] and 'cookie_name' in d:
                common.update({
                    '@timestamp': to_iso_format(d['accessed']),
                    'event.type': ['access'],
                    'event.action': 'cookie-accessed',
                    'message': 'Cookie accessed for: ' + d['url'],
                })
                yield common
                common.update({
                    '@timestamp': to_iso_format(d['creation']),
                    'event.type': ['creation'],
                    'event.action': 'cookie-created',
                    'message': 'Cookie created for: ' + d['url'],
                })
                yield common

            elif d['browser'] == 'safari':
                common.update({
                    '@timestamp': to_iso_format(d['creation']),
                    'event.type': ['creation'],
                    'event.action': 'cookie-created',
                    'message': 'Cookie created for: ' + d['url'],
                    'cookie.expires': to_iso_format(d['expires']),
                    'cookie.path': d['path']
                })
                yield common

            elif d['browser'] == 'edge' and 'cookie_name' not in d:
                common.update({
                    '@timestamp': to_iso_format(d['creation']),
                    'event.type': ['creation'],
                    'event.action': 'cookie-created',
                    'message': 'Cookie created for: ' + d['url'],
                    'cookie.expires': to_iso_format(d['expires'])
                })
                yield common
                common.update({
                    '@timestamp': to_iso_format(d['accessed']),
                    'event.type': ['access'],
                    'event.action': 'cookie-accessed',
                    'message': 'Cookie accessed for: ' + d['url'],
                })
                yield common


class BrowsersDownloads(SuperTimeline):
    """ Converts browsers downloads to events. After this, you can save this file using events.save.
    """

    def run(self, path=None):
        # Warning: Output differs too much for browser type.
        super().run(path)

        for d in self.from_module.run(path):

            common = self.common_fields()
            common.update({
                'tags': ['browsers'],
                'user.name': d['user'],
                'event.category': ['web'],
                'event.module': 'browsers',
                'event.dataset': 'downloads',
                'user_agent.name': d['browser'],
                'url.original': d['url'],
            })

            if d['browser'] == 'safari':
                # Safari does not have timestamps
                continue

            elif d['browser'] == 'firefox':
                common.update({
                    '@timestamp': to_iso_format(d['date_added']),
                    'event.type': ['start'],
                    'event.action': 'download-started',
                    'message': 'Download started from: ' + d['url'],
                    'event.data.DownloadedContent': d.get('content', '')
                })
                yield common

                common.update({
                    '@timestamp': to_iso_format(d['modified']),
                    'event.type': ['change'],
                    'event.action': 'download-modified',
                    'message': 'Download modified from: ' + d['url']
                })
                yield common

            elif d['browser'] in ['chrome', 'edge']:
                common.update({
                    '@timestamp': to_iso_format(d['start']),
                    'event.type': ['start'],
                    'event.action': 'download-started',
                    'message': 'Download started from: ' + d['url'],
                    'file.path': d['path'],
                    'file.size': d['size']
                })
                yield common

                common.update({
                    '@timestamp': to_iso_format(d['end']),
                    'event.type': ['end'],
                    'event.action': 'download-finished',
                    'message': 'Download finished from: ' + d['url']
                })
                yield common

            if d['browser'] == 'edge' and d.get('modified', '1601-01-01 T00:00:00Z') != '1601-01-01 T00:00:00Z':
                common.update({
                    '@timestamp': to_iso_format(d['modified']),
                    'event.type': ['change'],
                    'event.action': 'download-modified',
                    'message': 'Download modified from: ' + d['url']
                })
                yield common


class EventLogs(SuperTimeline):
    """ Adapts windows event logs to Elastic. After this, you can save this file using events.save.
    """

    def run(self, path=None):
        super().run(path)

        for d in self.from_module.run(path):

            common = self.common_fields()
            common.update({
                '@timestamp': to_iso_format(d['event.created']),
                'tags': ['event_logs'],
                'event.module': 'event_logs',
                'event.code': d['event.code'],
                'event.dataset': d['event.dataset'],
                'event.provider': d['event.provider']
            })

            common['message'] = d.get('message', "Event Code: {} ({})".format(d['event.code'], d['event.dataset']))
            parsed_fields = set(['event.created', 'event.code', 'event.dataset', 'event.provider', 'message'])

            # Optional fields
            for field in ['event.category', 'event.type', 'event.action', 'process.pid', 'process.thread.id']:
                if field in d:
                    common[field] = d[field]
                    parsed_fields.add(field)

            # EventData and UserData only exist in parsed event_logs when are not specific event codes
            # All this fields are indexed as a single field, even if they contain many subfields, due to Elastic total field limitations per index
            if 'EventData' in d:
                common.update({'event.data.Data': str(d['EventData'])})
            if 'UserData' in d:
                # Sometimes UserData only contains a dict with key 'EventData' or 'EventXML'
                if 'EventData' in d['UserData']:
                    common.update({'event.data.Data': str(d['UserData']['EventData'])})
                elif 'EventXML' in d['UserData']:
                    common.update({'event.data.Data': str(d['UserData']['EventXML'])})
                else:
                    common.update({'event.data.Data': str(d['UserData'])})
            parsed_fields.update(['EventData', 'UserData'])

            # Selected data fields
            for field in [f for f in d if f not in parsed_fields]:
                if field.startswith('data.'):
                    common.update({'event.{}'.format(field): d[field]})
                else:
                    common.update({field: d[field]})

            # Make sure some fields adjust the expected type:
            additional_fields = {}
            if 'url' in common:  # in conflict with ECS
                common['url.full'] = common['url']
                del common['url']
            for field in common:
                if field.endswith('ip'):
                    ip, port = sanitize_ip(common[field], logger=self.logger())
                    common[field] = ip
                    if port:
                        additional_fields[field[:-2] + 'port'] = port
                elif field.endswith('port'):
                    common[field] = common[field] if common[field] != '-' else None
            for additional_field in additional_fields:
                common[additional_field] = additional_fields[additional_field]

            yield common


class Prefetch(SuperTimeline):
    """ Converts prefetch execution times to events. After this, you can save this file using events.save.
    """

    def run(self, path=None):

        for d in self.from_module.run(path):

            common = self.common_fields()
            common.update({
                '@timestamp': to_iso_format(d['RunTime']),
                'process.start': to_iso_format(d['RunTime']),
                'tags': ['execution'],
                'event.category': ['package'],
                'event.module': 'prefetch',
                'event.dataset': 'prefetch',
                'event.action': 'application-executed',
                'event.type': ['start'],
                'message': "Executed process: {}".format(d['Executable']),
                'file.name': d['PrefecthFile'],
                'file.group': 'plain',
                'process.executable': d['Executable'],
                'process.run_count': d['RunCount'],
                'process.run_total': d['RunTotal'],
                'process.first_run': d['BirthDate'],
                'container.id': d['Partition'],
                'device.id': d['VolumeSN']
            })
            yield common


class AmCache(SuperTimeline):
    """ Converts amcache execution times to events. After this, you can save this file using events.save.
    """

    def run(self, path=None):

        for d in self.from_module.run(path):

            common = self.common_fields()
            common.update({
                'tags': ['execution'],
                'event.category': ['package'],
                'event.module': 'registry',
                'event.dataset': 'amcache',
                'registry.hive': 'amcache',
                'process.executable': d['AppPath'],
                'file.hash.sha1': d['Sha1Hash'],
                'event.data.VolumeGUID': d['GUID']
            })

            for time_field, action, message, ev_type in zip(
                    ['KeyLastWrite', 'Created', 'LastModified'],
                    ['application-first-executed', 'application-created', 'application-last-modified'],
                    ['First execution of process: {}', 'Creation of executable file {}', 'Last modification of executable file {}'],
                    ['start', 'creation', 'change']):
                if d[time_field] == '1601-01-01 00:00:00':
                    continue
                common.update({
                    '@timestamp': to_iso_format(d['KeyLastWrite']),
                    'event.action': action,
                    'message': message.format(d['AppPath']),
                    'event.type': [ev_type]
                })
                yield common


class AppCompatCache(SuperTimeline):
    """ Converts AppCompatCache/Shimcache to events. After this, you can save this file using events.save.

    Configuration section:
        - **classify**: If True, categorize the files in the output.
    """

    def read_config(self):
        super().read_config()
        self.set_default_config('classify', 'False')

    def run(self, path=None):
        # Column fields depend on which parser is used:
        #   regripper appcompatcache plugin --> LastModified;AppPath;Executed
        #   AppCompatCacheParser --> LastModifiedTimeUTC;Path;CacheEntryPosition;Executed
        for d in self.from_module.run(path):
            common = self.common_fields()
            common.update({
                '@timestamp': to_iso_format(d.get('LastModifiedTimeUTC', None) or d.get('LastModified', "")),
                'tags': ['appcompat'],
                'event.category': ['file'],
                'event.type': ['start'],
                'event.module': 'registry',
                'event.dataset': 'appcompat',
                'registry.hive': 'system',
                'event.action': 'file-modified',
                'message': 'File modified: ' + (d.get('Path', '') or d.get('AppPath', '')),
                'process.executable': (d.get('Path', '') or d.get('AppPath', ''))
            })

            if d.get('Executed', ''):
                common['event.data.Executed'] = d['Executed']
            if d.get('CacheEntryPosition', ''):
                common['event.data.CacheEntryPosition'] = d['CacheEntryPosition']

            yield common


class CCM(SuperTimeline):
    """ Converts SCCM Software Metering last executed applications to events. After this, you can save this file using events.save.
    """

    def run(self, path=None):

        for d in self.from_module.run(path):

            common = self.common_fields()
            common.update({
                'tags': ['execution'],
                'event.category': ['package'],
                'event.module': 'ccm',
                'event.dataset': 'cim',
                'event.action': 'application-executed',
                'event.type': ['start'],
                'message': "Executed process: {}".format(d['ExplorerFileName']),
            })

            if not d['LastUsedTime']:
                continue
            common['@timestamp'] = to_iso_format(d['LastUsedTime'])

            original_fields = ["FolderPath", "ExplorerFileName", "FileSize", "LastUserName", "LaunchCount", "OriginalFileName", "FileDescription", "ProductName", "ProductVersion"]
            translations = ['package.path', 'process.executable', 'package.size', 'user.name', 'process.run_count', 'package.original_file_name', 'package.description', 'package.name', 'package.version']
            for original_field, translation in zip(original_fields, translations):
                common[translation] = d[original_field]

            yield common


class UserAssist(SuperTimeline):
    """ Converts UserAssist key in registry to events. After this, you can save this file using events.save.

    Configuration section:
        - **classify**: If True, categorize the files in the output.
    """

    def read_config(self):
        super().read_config()
        self.set_default_config('classify', 'False')

    def run(self, path=None):

        for d in self.from_module.run(path):
            # UserAssist can provide information about aplications without a timestamp.
            # Although useful, an event requires a timestamp
            if not d.get('LastExecuted', ''):
                continue

            common = self.common_fields()
            common.update({
                '@timestamp': to_iso_format(d['LastExecuted']),
                'tags': ['execution'],
                'event.category': ['package'],
                'event.module': 'registry',
                'event.dataset': 'userassist',
                'event.action': 'application-executed',
                'event.type': ['start'],
                'message': "Process last executed: {}".format(d['ProgramName']),
                'process.executable': d['ProgramName'],
                'user.name': d['User']})

            for field_in, field_out in zip(['RunCounter', 'FocusCount', 'FocusTime'], ['event.data.RunCount', 'event.data.FocusCount', 'process.uptime']):
                if field_in in d:
                    common[field_out] = d[field_in]

            yield common


class Shellbags(SuperTimeline):
    """ Converts Shellbags to events. After this, you can save this file using events.save.

    Configuration section:
        - **classify**: If True, categorize the files in the output.
    """

    def read_config(self):
        super().read_config()
        self.set_default_config('classify', 'False')

    def run(self, path=None):

        for d in self.from_module.run(path):
            common = self.common_fields()
            common.update({
                'tags': ['shellbags'],
                'event.category': ['file'],
                'event.type': ['access'],
                'event.module': 'registry',
                'event.dataset': 'shellbags',
                'file.directory': d.get('AbsolutePath', ''),
                'file.accessed': to_iso_format(d.get('AccessedOn', '')),
                'file.created': to_iso_format(d.get('CreatedOn', '')),
                'file.mtime': to_iso_format(d.get('ModifiedOn', '')),
                'file.inode': d.get('MFTEntry', ''),
                'registry.last_write': to_iso_format(d.get('LastWriteTime', '')),
                'user.name': d['User']
            })

            if d.get('FirstInteracted', ''):
                common.update({
                    '@timestamp': to_iso_format(d['FirstInteracted']),
                    'event.action': 'directory-first-interacted',
                    'message': 'Directory first interacted: {}'.format(d.get('AbsolutePath', ''))})
                yield common

            if d.get('LastInteracted', ''):
                common.update({
                    '@timestamp': to_iso_format(d['LastInteracted']),
                    'event.action': 'directory-last-interacted',
                    'message': 'Directory last interacted: {}'.format(d.get('AbsolutePath', ''))})
                yield common


class RegistryTasks(SuperTimeline):
    """ Converts registry tasks keys to ecs format. After this, you can save this file using events.save.
    """

    def run(self, path=None):

        for d in self.from_module.run(path):
            common = self.common_fields()
            common.update({
                '@timestamp': to_iso_format(d.get('@timestamp', None)),
                'tags': ['tasks'],
                'event.category': ['registry'],
                'event.module': 'registry',
                'event.dataset': 'tasks',
                'event.data.Author': d.get('Author'),
                'event.data.TaskName': d.get('Task'),
                'event.data.Description': d.get('Description')
            })

            if d.get('LastExecuted', None):
                common.update({
                    '@timestamp': to_iso_format(d['LastExecuted']),
                    'event.action': 'task-last-executed',
                    'message': 'Task last executed: {}'.format(d.get('Task', ''))})
                yield common

            if d.get('LastCompleted', None):
                common.update({
                    '@timestamp': to_iso_format(d['LastExecuted']),
                    'event.action': 'task-last-execution-completed',
                    'message': 'Task last execution completed: {}'.format(d.get('Task', ''))})
                yield common

            if d.get('Created', None):
                common.update({
                    '@timestamp': to_iso_format(d['Created']),
                    'event.action': 'task-created',
                    'message': 'Task created: {}'.format(d.get('Task', ''))})
                yield common


class Tasks(SuperTimeline):
    """ Converts scheduled tasks files to ecs format. After this, you can save this file using events.save.
    """

    def run(self, path=None):

        for d in self.from_module.run(path):
            common = self.common_fields()
            common.update({
                '@timestamp': '',
                'tags': ['tasks'],
                'event.category': ['file'],
                'event.module': 'tasks',
                'event.dataset': 'scheduled',
                'user.id': d.get('UserId', None),
                'user.name': d.get('User', None),
                'event.data.TaskName': d.get('TaskName', ''),
                'event.data.TaskDescription': d.get('Description', ''),
                'event.data.RunLevel': d.get('RunLevel', ''),
                'event.data.Hidden': d.get('Hidden', ''),
                'event.data.Enabled': d.get('Enabled', ''),
                'process.command_line': d.get('Command', ''),
                'process.args': [d.get('Arguments', '')],
                'message': 'Scheduled Task'
            })

            for time_field in ["StartBoundary", "RegistrationDate", "FileCreation", "FileModification"]:
                if d.get(time_field, None):
                    common.update({'@timestamp': to_iso_format(d.get(time_field, None)),
                                   'message': f'{time_field} for Scheduled Task  {d.get("TaskName", "")}'
                                })
                    yield common


class UsnJrnl(SuperTimeline):
    """ Adapts windows usnjrnl to Elastic. After this, you can save this file using events.save.
    """

    def run(self, path=None):

        # CSV fields: Date;Filename;Full Path;File Attributes;Reason;MFT Entry;Parent MFT Entry;Reliable Path
        for d in self.from_module.run(path):

            common = self.common_fields()
            common.update({
                '@timestamp': to_iso_format(d['Date']),
                'tags': ['journal'],
                'event.category': ['package'],
                'event.module': 'usnjrnl',
                'event.dataset': 'usnjrnl',
                'file.path': d['Full Path'],
                'file.name': d['Filename'],
                'file.directory': os.path.dirname(d['Full Path']),
                'file.inode': d['MFT Entry'],
                'file.group': self.filegroup(dict({'path': d['Full Path']}), self.myflag('classify')) or '',
                'file.attributes': self.attributes(d['File Attributes']),
                'event.action': self.reasons(d['Reason'])
            })

            deleted = common['event.action'] == 'file-deleted'
            common['file.deleted'] = deleted
            event_types_messages = {'file-created': (['creation'], "File created"),
                                    'file-deleted': (['deletion'], 'File deleted'),
                                    'file-renamed-old-name': (['change'], 'File renamed. Old name'),
                                    'file-renamed-new-name': (['change'], 'File renamed. New name')}
            common['event.type'] = event_types_messages.get(common['event.action'], [''])[0]
            common['message'] = "{}: {}".format(event_types_messages.get(common['event.action'], ['', ''])[1], d['Full Path'])

            yield common

    def attributes(self, attributes):
        """ Converts a string of attributes into a list:

        Example:
        'ARCHIVE NOT_CONTENT_INDEXED ' -> ["archive", "not_content_indexed"]
        """

        attr = attributes.split(' ')
        return [a.lower() for a in attr[:-1]]

    def reasons(self, reasons):
        """ Parse a string of reasons into a suitable event.action:

        Example:
        'DATA_EXTEND FILE_CREATE CLOSE ' -> 'file-created'
        """

        outcome = {'FILE_CREATE': 'file-created',
                   'FILE_DELETE': 'file-deleted',
                   'RENAME_OLD_NAME': 'file-renamed-old-name',
                   'RENAME_NEW_NAME': 'file-renamed-new-name'}
        actions = [s for s in reasons.split(' ')[:-1]]
        for a in actions:
            if a in outcome:
                return outcome[a]
        return []


class USB(SuperTimeline):
    """ Adapts usb setup.api to Elastic. After this, you can save this file using events.save.
    """

    def run(self, path=None):

        for d in self.from_module.run(path):
            common = self.common_fields()
            common.update({
                'tags': ['usb'],
                'event.category': ['driver'],
                'event.module': 'usb',
                'event.dataset': 'setupapi',
                'package.name': d['Device'],
                'package.description': d['DevDesc']
            })

            common.update({
                '@timestamp': to_iso_format(d['Start']),
                'event.type': ['installation', 'start'],
                'event.action': 'driver-installation-started',
                'message': 'Driver installation start: {}'.format(d['Device'])
            })
            yield common

            common.update({
                '@timestamp': to_iso_format(d['End']),
                'package.installed': to_iso_format(d['End']),
                'event.action': 'driver-installation-ended',
                'message': 'Driver installation end: {}'.format(d['Device']),
                'event.type': ['installation', 'end']
            })
            yield common


class NetworkUsage(SuperTimeline):
    """ Adapts SRUM Network Usage information to Elastic. After this, you can save this file using events.save.
    """

    def run(self, path=None):

        for d in self.from_module.run(path):
            common = self.common_fields()
            common.update({
                '@timestamp': to_iso_format(d['SRUM ENTRY CREATION']),
                'event.kind': "metric",
                'tags': ['network'],
                'event.category': ['web'],
                'event.module': 'srum',
                'event.dataset': 'network-usage',
                'event.action': 'network-usage-summary',
                'event.type': ['info'],
                'network.application': d['Application'],
                'network.name': d['Profile'],
                'network.type': d['Interface'],
                'source.bytes': d['Bytes Sent'],
                'destination.bytes': d['Bytes Received'],
                'message': "Application {} uploaded/downloaded {} / {} bytes in last summary period".format(
                    d['Application'], d['Bytes Sent'], d['Bytes Received'])
            })

            user = d.get('User SID', '').split(' ')
            common['user.id']: user[0]
            if len(user) > 1:
                common['user.name'] = ' '.join(user[1:]).lstrip('(').rstrip(')')

            yield common


class NetworkConnections(SuperTimeline):
    """ Adapts SRUM Network Connections information to Elastic. After this, you can save this file using events.save.
    """

    def run(self, path=None):

        for d in self.from_module.run(path):
            common = self.common_fields()
            common.update({
                '@timestamp': to_iso_format(d['ConnectStartTime']),
                'tags': ['network'],
                'event.category': ['web'],
                'event.module': 'srum',
                'event.dataset': 'network-connections',
                'event.action': 'connection-started',
                'event.type': ['start'],
                'network.application': d['Application'],
                'network.name': d['L2ProfileId'],
                'network.type': d['InterfaceLuid'],
                'network.connected_time': d['ConnectedTime'],  # in seconds
                'message': 'Started a {} network connection{}'.format(
                    d['InterfaceLuid'], ' on {}'.format(d['L2ProfileId']) if d['L2ProfileId'] else '')
            })

            user = d.get('User SID', '').split(' ')
            if user[0]:
                common['user.id']: user[0]
            if len(user) > 1:
                common['user.name'] = ' '.join(user[1:]).lstrip('(').rstrip(')')

            yield common


class Registry(SuperTimeline):
    """ Adapts Windows Registry information to Elastic. After this, you can save this file using events.save. """

    def run(self, path=""):
        super().run(path)

        for d in self.from_module.run(path):
            if 'values' not in d:  # No value set, just subkey description
                continue

            common = self.common_fields()
            common.update({
                '@timestamp': d['timestamp'],
                'tags': ['registry'],
                'event.category': ['database'],
                'event.module': 'registry',
                'event.dataset': d['hive_name'],
                'event.action': 'registry value-set',
                'event.type': ['change'],  # could be also creation
                'registry.path': d['path'],
                'registry.key': d['subkey']
            })

            if d.get('user', ''):
                common['user.name'] = d['user']

            for v in d['values']:
                for sub_value, data in v.items():
                    common['registry.{}'.format(sub_value)] = data
                common['message'] = 'Registry value {} set at subkey {}'.format(v['value'], d['subkey'])
                yield common


class RecycleBin(SuperTimeline):
    """ Converts files in Recycle Bin to events. After this, you can save this file using events.save.

    Configuration section:
        - **classify**: If True, categorize the files in the output.
    """

    def read_config(self):
        super().read_config()
        self.set_default_config('classify', 'True')

    def run(self, path=None):

        for d in self.from_module.run(path):

            common = self.common_fields()
            common.update({
                '@timestamp': to_iso_format(d['Date']),
                'tags': ['recyclebin'],
                'event.category': ['file'],
                'event.type': ['deletion'],
                'event.module': 'recyclebin',
                'event.dataset': d['recyclebin'],
                'event.action': 'file-deleted',
                'file.deleted': 'False' if d['Status'] == 'allocated' else 'True',
                'file.inode': d['Inode'],
                'user.name': d['User'],
                'file.path': d['File'],
                'file.size': d['Size'],
                'file.directory': os.path.dirname(d['OriginalName']),
                'file.extension': os.path.splitext(d['OriginalName'])[1].lstrip('.'),
                'file.name': os.path.basename(d['OriginalName']),
                'file.group': self.filegroup(dict({'path': d['OriginalName']}), self.myflag('classify')) or '',
                'message': 'File sent to RecycleBin: {}'.format(d['OriginalName'])
            })

            yield common


class WhatsApp(SuperTimeline):
    """ Convert WhatsApp messages to events. After this, you can save this file using events.save.

    Configuration section:
        - **classify**: If True, categorize the files in the output.
    """

    def read_config(self):
        super().read_config()
        self.set_default_config('classify', 'False')

    def run(self, path=None):

        for d in self.from_module.run(path):

            common = self.common_fields()
            common.update({
                'tags': ['whatsapp'],
                'event.category': ['network'],
                'event.module': 'whatsapp',
                # 'event.dataset': d['whatsapp'],
                'communication.id': d['message_id'],
                'communication.from': d['message_from'],
                'communication.to': d['message_to'],
                'communication.text': d['message'],
                'communication.type': d['message_type'],
                'communication.group': d['message_group'],
                'communication.direction': 'sent' if d['is_from_me'] == '1' else 'received',
                'communication.to_number': d['message_phonenumber'],
                'communication.created': to_iso_format(d['date_creation']),
                'message': 'WhatsApp message: {}'.format(d['message'])
            })

            if d['lon_lat']:
                common['geo_location'] = to_geolocation(d['lon_lat'])
            if d['message_media_location']:
                common['file.name'] = d['message_media_location']
            if d['message_media_title']:
                common['communication.text'] = d['message_media_title']

            if d['date_sent'] != '0':
                common.update({
                    '@timestamp': to_iso_format(d['date_sent']),
                    'event.action': 'message-sent',
                    'event.type': ['start']
                })
                yield common

            elif d['date_delivered'] != '0':
                common.update({
                    '@timestamp': to_iso_format(d['date_delivered']),
                    'event.action': 'message-delivered',
                    'event.type': ['end']
                })
                yield common

            else:
                common.update({
                    '@timestamp': to_iso_format(d['date_creation']),
                    'event.action': 'message-created',
                    'event.type': ['creation']
                })
                yield common
