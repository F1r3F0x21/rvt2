#!/usr/bin/env python3
# -*- coding: utf-8 -*-
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

""" Utility functions to the rest of the system. """

import os
import shutil
import uuid
import hashlib
import json
import re
import logging
import base.job
import base.config

from pathlib import Path, PureWindowsPath

__maintainer__ = 'Juanvi Vera'


def check_folder(path):
    """ Check is a path is a folder and create if not exists.

    Equivalent to ``check_directory(path, create=True)``
    """
    check_directory(path, create=True)


def check_directory(path, create=False, delete_exists=False, error_exists=False, error_missing=False):
    """ Check if a directory exists.

    Parameters:
        error_exists (Boolean): If True and the directory exits, raise a RVTError
        error_missing (Boolean): If True and the file does not exist, raise a RVTError
        create (Boolean): If True and the directory does not exist, create it
        delete_exists (Boolean): If True, delete the directory and create a new one.

    Returns:
        True if the directory exists at the end of this function.
    """
    if os.path.exists(path):
        if error_exists:
            raise base.job.RVTError('{} exists'.format(path))
        if not os.path.isdir(path):
            raise base.job.RVTError('{} exists and it is not a directory'.format(path))
        if delete_exists:
            shutil.rmtree(path)
    else:
        if error_missing:
            raise base.job.RVTError('{} does not exist'.format(path))
    if create:
        os.makedirs(path, exist_ok=True)
    return os.path.exists(path)


def check_file(path, error_missing=False, error_exists=False, delete_exists=False, create_parent=False):
    """ Check if a file exists, and optionally removes it.

    Parameters:
        error_exists (Boolean): If True and the file exists, raise a RVTError
        error_missing (Boolean): If True and the file does not exist, raise a RVTError
        delete_exists (Boolean): If True, delete the file if exists
        create_parent (Boolean): If True, create the parent directory

    Raises:
        RVTError if the path is not a file, or the file does not exist and error_exists is set to True

    Returns:
        True if the file exists at the end of this function.
    """
    if os.path.lexists(path):
        if error_exists:
            raise base.job.RVTError('{} exists'.format(path))
        if not (os.path.isfile(path) or os.path.islink(path)):
            raise base.job.RVTError('{} exists and it is not a file'.format(path))
        if delete_exists:
            os.remove(path)
    else:
        if error_missing:
            raise base.job.RVTError('{} does not exist'.format(path))
    if create_parent:
        check_directory(os.path.dirname(path), create=True)
    return os.path.lexists(path)


def relative_path(path, start):
    """
    Transform a path to be relative to a start path.

    Todo:
        We don't want to go outside the starting path. Check that.

    Returns:
        path relative to start path.

    >>> relative_path('/morgue/112234-casename/01/23', '/morgue/112234-casename')
    '01/23'
    >>> relative_path('/another/112234-casename/01/23', '/morgue/112234-casename')
    '../../another/112234-casename/01/23'
    >>> relative_path(None, '/morgue/11223344-casename') is None
    True
    """
    try:
        return os.path.normpath(os.path.relpath(path, start=start))
    except ValueError:
        return None


def save_output(data, config=None, output_module='base.output.CSVSink', **kwargs):
    """
    Save data in some standard output format file. This is a convenient function to run a ``base.output`` modules from inside another module.

    Parameters:
        data: The data to be saved. It can be a generator (such as list or tuple) or a `base.job.BaseModule`. In the last case, the module is run and saved.
        config (base.config.Config): The global configuration object, or None to use default configuration.
        output_module (str): Name of the output module. Ex: 'base.output.CSVSink'
        kwargs (dict): The extra configuration for the `base.output` module. You'd want to set, at least, `outfile`.
    """
    if config is None:
        config = base.config.default_config
    m = base.job.load_module(
        config, output_module,
        extra_config=kwargs,
        from_module=data
    )
    list(m.run())


def save_csv(data, config=None, **kwargs):
    """
    Save data in a CSV file. This is a convenient function to run a ``base.output.CSVSink`` module from inside another module.

    Parameters:
        data: The data to be saved. It can be a generator (such as list or tuple) or a `base.job.BaseModule`. In the last case, the module is run and saved.
        config (base.config.Config): The global configuration object, or None to use default configuration.
        kwargs (dict): The extra configuration for the `base.output.CSVSink` module. You'd want to set, at least, `outfile`.
    """
    save_output(data, config, 'base.output.CSVSink', **kwargs)


def save_json(data, config=None, **kwargs):
    """
    Save data in a JSON file. This is a convenient function to run a ``base.output.JSONSink`` module from inside another module.

    Parameters:
        data: The data to be saved. It can be a generator (such as list or tuple) or a `base.job.BaseModule`. In the last case, the module is run and saved.
        config (base.config.Config): The global configuration object, or None to use default configuration.
        kwargs (dict): The extra configuration for the `base.output.JSONSink` module. You'd want to set, at least, `outfile`.
    """
    save_output(data, config, 'base.output.JSONSink', **kwargs)


def save_md_table(data, config=None, **kwargs):
    """
    Save data in a markdown file. This is a convenient function to run a ``base.output.MDTableSink`` module from inside another module.

    Parameters:
        data: The data to be saved. It can be a generator (such as list or tuple) or a `base.job.BaseModule`. In the last case, the module is run and saved.
        config (base.config.Config): The global configuration object, or None to use default configuration.
        kwargs (dict): The extra configuration for the `base.output.CSVSink` module. You'd want to set, at least, `outfile`.
    """
    save_output(data, config, 'base.output.MDTableSink', **kwargs)


def generate_id(data=None):
    """ Generate a unique ID for a piece of data. If data is None, returns a random indentifier.

    The identifier is created using::

        uuid.uuid5(uuid.NAMESPACE_URL, 'file:///{}/{}?{}'.format(dirname, filename, embedded_path))

    If the data already provides and identifier in an field ``_id``, pop this field from data and return it.
    """

    if not data:
        return uuid.uuid4()

    if '_id' in data:
        return data.pop('_id')

    dirname = data.get('dirname', None)
    if dirname is not None:
        dirname = dirname.encode(errors='backslashreplace').decode()
    filename = data.get('filename', None)
    if filename is not None:
        filename = filename.encode(errors='backslashreplace').decode()
    embedded_path = data.get('embedded_path', None)
    if embedded_path is not None:
        embedded_path = embedded_path.encode(errors='backslashreplace').decode()
    if dirname and filename:
        if embedded_path:
            return uuid.uuid5(uuid.NAMESPACE_URL, 'file:///{}/{}?{}'.format(dirname, filename, embedded_path))
        else:
            return uuid.uuid5(uuid.NAMESPACE_URL, 'file:///{}/{}'.format(dirname, filename))
    else:
        # not enough information: random ID
        return uuid.uuid4()


def generate_hash(data=None):
    """ Generate an MD5 for a dictionary. If data is None, returns a random indentifier.

    The identifier is created using the encoded input data.

    If the data already provides and identifier in an field ``_id``, pop this field from data and return it.
    """

    if not data:
        return uuid.uuid4()

    if '_id' in data:
        return data.pop('_id')

    dhash = hashlib.md5()
    encoded = json.dumps(data, sort_keys=True).encode()
    dhash.update(encoded)
    return dhash.hexdigest()


def human_readable_size(num):
    """ Converts bytes to human readable magnitudes """

    for unit in ['', 'K', 'M', 'G', 'T', 'P']:
        if abs(num) < 1024.0:
            return "%3.1f%s" % (num, unit)
        num /= 1024.0
    return "%.1f%s" % (num, 'Yi')


def windows_format_path(path, enclosed=False):
    """ Return a Windows format path. If 'enclosed', sorround by semicolons so shlex or other functions can process the full path as one """
    path = str(PureWindowsPath(Path(path)))
    if enclosed:
        return '"' + path + '"'
    return path


def sanitize_ip(value):
    """ Adapt IP fields to Elastic IPv4 or IPv6 addresses format (see https://www.elastic.co/guide/en/elasticsearch/reference/current/ip.html)

    Possible inputs to convert:
    - ''                        --> null (Ipfield throws error when processing empty string)
    - `-`                       --> null
    - [123.123.123.123]         --> 123.123.123.123
    - ::ffff:10.100.1.87        --> 10.100.1.87 (Revert the default IPv4 toIPv6 convention to simplify reading)
    - 123.123.123.123::1980     --> ip=123.123.123.123, port=1980 (Ports are treated as separated field)
    - ::1234:5678:1.2.3.4:443   --> ip=::1234:5678:1.2.3.4, port=443
    - 2603:10a6:7:94:cafe::d6:3 --> ip=2603:10a6:7:94:cafe::d6, port=3
    - 123.123.123.123           --> 123.123.123.123 (Valid IPv4 format. No changes)
    - 2001:db8:1::ab9:C0A8:102  --> 2001:db8:1::ab9:C0A8:102 (Valid IPv6 format. No changes)
    - ::1234:5678:1.2.3.4       --> ::1234:5678:1.2.3.4 (Valid dual IPv6 format. No changes)

    Any other escenario will return null as IP value.

    Returns tuple (ip, port)
    """

    value = value.replace('[', '').replace(']', '')
    if value == '-' or value == '':
        return (None, None)

    semicolons = value.count(':')
    if not semicolons:  # Single IPv4 address
        if not is_valid_ipv4_address(value):
            logging.warning(f'IP value {value} is not a valid IP')
            return (None, None)
        return (value, None)
    terms = value.split(':')
    if (semicolons == 1 or (semicolons == 2 and terms[0])):  # IPv4:port or IPv4::por escenarios
        ip = terms[0]
        if not is_valid_ipv4_address(ip):
            logging.warning(f'IP value {value} is not a valid IP')
            ip = None
        return ip, check_integer(terms[1])
    elif semicolons == 2 and not terms[0]:  # Empty IPv6 address (::) or ::IPv4 scenario
        if not terms[2]:
            return (None,None)
        if not is_valid_ipv4_address(terms[2]):
            logging.warning(f'IP value {terms[2]} is not a valid IP')
            return (None, None)
        return (terms[2], None)
    elif semicolons == 3 and value.lower().startswith('::ffff:') and terms[3]:  # ::ffff:IPv4 scenario
        if not is_valid_ipv4_address(terms[3]):
            logging.warning(f'IP value {terms[3]} is not a valid IP')
            return (None, None)
        return (terms[3], None)
    elif semicolons >= 3 and '.' in terms[-2]:  # IPv6:IPv4:port scenario
        port = check_integer(terms[-1])
        ip = ':'.join(terms[:-1])
        if not is_valid_ipv4_address(terms[-2]):
            logging.warning(f'IP value {ip} is not a valid IP')
            return (None, None)
        # TODO: Check if first IPv6 part is valid
        return (ip, port)
    elif semicolons == 7:  # IPv6:port scenario
        ip = ':'.join(terms[:-1])
        if not is_valid_ipv6_address(ip):
            logging.warning(f'IP value {ip} is not a valid IP')
            return (None, None)
        return ip, check_integer(terms[-1])
    else:
        return (None, None)


def is_valid_ipv4_address(address):
    # Regular expression pattern for a valid IPv4 address
    pattern = r'^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'

    if re.match(pattern, address):
        return True
    else:
        return False


def is_valid_ipv6_address(address):
    # Regular expression pattern for a valid IPv6 address
    pattern = r'^(([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:))$'

    if re.match(pattern, address):
        return True
    else:
        return False


def check_integer(value):
    """ Check if an object can be casted to an integer. Return the casted object or None. """
    try:
        return int(value)
    except ValueError:
        return None


class WaitForJob(base.job.BaseModule):
    """ Manages concurrency of repeated jobs.
        If there is still an instance running of a job that is to be executed, then the new job waits the first one to finish.

        configuration:
        - **job_name** : name of the job to check it's running. By default it will be the present job name itself.
        - **exclude_present_job**: Exclude the present job id in the search, since it will always be registered before the present functions is executed.
        - **step** : time (in seconds) between consecutive state asking.
        - **timeout** : maximum time (in seconds) to wait. After that, the new job is cancelled.
    """

    def read_config(self):
        super().read_config()
        self.set_default_config('job_name', None)
        self.set_default_config('exclude_present_job', True)
        self.set_default_config('step', '30')
        self.set_default_config('timeout', '600')

    def run(self, path=""):
        base.job.wait_for_job(self.config,
                              self,
                              step=int(self.myconfig('step')),
                              timeout=int(self.myconfig('timeout')),
                              job_name=self.myconfig('job_name'),
                              exclude_present_job=self.myflag('exclude_present_job'))

        return []


class MirrorOptions(base.job.BaseModule):
    """ Return the value of the local options.

        Configuration:
        - **include_section**: If true, include also the configuration in the section.
        - **relative_path**: If true, return the path relative to casedir.
    """

    def read_config(self):
        super().read_config()
        self.set_default_config('include_section', 'False')
        self.set_default_config('relative_path', 'True')

    def run(self, path=None):
        if self.myflag('relative_path'):
            params = dict(path=base.utils.relative_path(path, self.myconfig('casedir')))
        else:
            params = dict(path=path)
        if self.local_config:
            params.update(self.local_config)
        if self.myflag('include_section') and hasattr(self, 'section') and hasattr(self, 'config'):
            if self.config.has_section(self.section):
                for option in self.config.options(self.section):
                    params[option] = self.config.get(self.section, option)
        # Remove two not useful parameters
        params.pop('logger_name')
        params.pop('include_section')
        return [params]
