#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (C) 2019, INCIDE Digital Data S.L.
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


"""
Modules to mutate data yielded by other modules: converte using specific convertes, remove fields, set fields to default values...
"""

import base.job
import base.utils
import dateutil.parser
import datetime
import os
import ast
import pytz
from textwrap import wrap
from plugins.windows.RVT_os_info import CharacterizeWindows


class DateFields(base.job.BaseModule):
    """ Converts or creates some fields into ISO date strings.

    Fields might be:

    - An integer, or a string representing an integer: it is a UNIX timestamp.
    - A string: the module will use the *datetutil* package to parse it

    If the field cannot be converted and stop_on_error is not set, the field is popped out from the data.

    Module description:
        - **path**: not used, passed to *from_module*.
        - **from_module**: mandatory. Get data and udpate fields.
        - **yields**: The modified data.

    Configuration:
        - **fields**: A space separated list of fields to check to convert
        - **new_fields**: A space separated list of new fields to create. If not set, original fields will be converted. If `fields` is set, must have the same number of items as `new_fields`
        - **sep**: Parameter used by datetime.isoformat. One-character separator, placed between the date and time portions of the result
        - **timespec**: Parameter used by datetime.isoformat. Specifies the number of additional components of the time to include
        - **tz_name**: tzdata/Olsen timezone name to set for the dates. Examples: `Europe/Berlin`, `America/New_York`, `UTC`. If `local` is set, timezone will be searched on the registry
        - **hide_tz**: If True, do not output a timezone offset with the result
        - **missing_action**: what to do when no date field is present. One of (IGNORE, SKIP_ANY, SKIP_ALL, EPOCH, NOW)
    """
    def read_config(self):
        super().read_config()
        self.set_default_config('fields', 'date_creation')
        self.set_default_config('new_fields', '')
        self.set_default_config('sep', 'T')
        self.set_default_config('timespec', 'auto')
        self.set_default_config('tz_name', 'UTC')
        self.set_default_config('hide_tz', False)
        self.set_default_config('missing_action', 'IGNORE')

    def run(self, path=None):
        """ The path will be passed to the mandatory from_module """
        self.check_params(path, check_from_module=True)
        sep = self.myconfig('sep')
        timespec = self.myconfig('timespec')
        hide_tz = self.myflag('hide_tz')
        fields = self.myarray('fields')
        new_fields = self.myarray('new_fields')
        tz_name = self.myconfig('tz_name')
        missing_action = self.myconfig('missing_action').upper()
        if missing_action not in ['IGNORE', 'SKIP_ANY', 'SKIP_ALL', 'EPOCH', 'NOW']:
            raise base.job.RVTError('`missing_action` must be one of IGNORE, SKIP, EPOCH, NOW')

        time_limits = {'EPOCH': datetime.datetime.fromtimestamp(0).isoformat(sep=sep, timespec=timespec),
                       'NOW': datetime.datetime.utcnow().isoformat(sep=sep, timespec=timespec)}

        if new_fields and len(new_fields) != len(fields):
            raise base.job.RVTError('`fields` and `new_fields` must have the same number of items. Fields: {}; New fields: {}'.format(fields, new_fields))

        if tz_name.lower() == 'local':
            tz_name, offset = CharacterizeWindows(config=self.config).get_timezone()  # partition ???

        for data in self.from_module.run(path):
            found = False
            skip = False
            for i, field in enumerate(fields):
                if skip:
                    continue
                if field not in data:
                    if missing_action in ('IGNORE', 'SKIP_ALL'):
                        continue
                    if missing_action == 'SKIP_ANY':
                        skip = True
                        continue
                if field in data:
                    found = True
                    converted_date = self.__convert_date(data[field], sep=sep, timespec=timespec, tz_name=tz_name, hide_tz=hide_tz)
                else:
                    converted_date = time_limits[missing_action]
                if converted_date and not new_fields:
                    data[field] = converted_date
                elif converted_date and new_fields:
                    data[new_fields[i]] = converted_date
                else:
                    data.pop(field)

            if not found and missing_action == 'SKIP_ALL':
                skip = True

            if not skip:
                yield data

    def __convert_date(self, source, sep='T', timespec='auto', tz_name='UTC', hide_tz=False):
        try:
            if type(source) == int:
                # convert an integer to a date
                dt = datetime.datetime.utcfromtimestamp(source)
            elif type(source) == str and source.isdigit():
                # convert an string as an integer to a date
                dt = datetime.datetime.utcfromtimestamp(int(source))
            else:
                # default: use dateutil
                dt = dateutil.parser.parse(source)

            # Assume input date is in UTC when no tzinfo is set:
            if not dt.tzinfo:
                dt = dt.replace(tzinfo=pytz.utc)
            tz = pytz.timezone(tz_name)
            # Convert the datetime to the specified timezone
            dt = dt.astimezone(tz)
            # Display in isoformat
            return dt.replace(tzinfo=dt.tzinfo if not hide_tz else None).isoformat(sep=sep, timespec=timespec)

        except Exception:
            if self.myflag('stop_on_error'):
                raise
            return None


class RemoveFields(base.job.BaseModule):
    """ Drops some fields from data.

    Module description:
        - **path**: not used, passed to *from_module*.
        - **from_module**: mandatory. Get data and remove fields.
        - **yields**: The modified data.

    Configuration:
        - **fields**: List of fields to drop.
    """
    def read_config(self):
        super().read_config()
        self.set_default_config('fields', '')

    def run(self, path=None):
        self.check_params(path, check_from_module=True)

        fields = self.myarray('fields')
        for data in self.from_module.run(path):
            for field in fields:
                # remove the field only if it already exists
                if field in data:
                    data.pop(field)
            yield data


class CommonFields(base.job.BaseModule):
    """
        Adds common fields for a document: *path*, *filename*, *dirname*, *extension*, *content_type* and *_id* if they don't exist yet.

        Module description:
            - **path**: not used, passed to *from_module*.
            - **from_module**: mandatory. Copy the information sent by from_module and add fields if they don't exist yet.
            - **yields**: the modified data.

        Configuration:
            - **calculate_id**: if True, calls base.utils.generate_id to generate an identifier in the *_id* field.
            - **disabled**: if True, do not add anything and just yield the result. Useful in configurable module chains
    """
    def read_config(self):
        super().read_config()
        self.set_default_config('generate_id', 'False')
        self.set_default_config('disabled', 'False')

    def run(self, path=None):
        self.check_params(path, check_from_module=True)
        if self.myflag('disabled'):
            for data in self.from_module.run(path):
                yield data
            return []
        for data in self.from_module.run(path):
            newdata = self._common_fields(data.get('path', path))
            # fields already in data take precedence
            newdata.update(data)
            # generate the identifier
            if self.myflag('generate_id'):
                newdata['_id'] = base.utils.generate_id(newdata)
            yield newdata

    def _common_fields(self, path):
        """ Return common fields for a document in a path: path, filename, dirname and extension.
        These values must be utf-8 and relative to the casename  """
        safe_path = path.encode('utf-8', errors='backslashreplace').decode()
        if os.path.isabs(path) or safe_path.startswith('.'):
            relfilepath = base.utils.relative_path(safe_path, self.myconfig('casedir'))
        else:
            relfilepath = safe_path
        cfields = dict(
            path=relfilepath,
            filename=os.path.basename(relfilepath),
            dirname=os.path.dirname(relfilepath),
            extension=os.path.splitext(relfilepath)[1]
        )

        content_type = self.myconfig('content_type')
        if content_type:
            cfields['content_type'] = content_type

        return cfields


class ForEach(base.job.BaseModule):
    """ Runs a job for each data yielded by from_module. The data is passed as params of the job.

    Module description:
        - **path**: not used, passed to *from_module*.
        - **from_module**: mandatory. The data is passed to ``run_job`` as its extra_config parameter.
        - **yields**: None

    Configuration:
        - **run_job**: The name of he job to run
    """
    def read_config(self):
        super().read_config()
        self.set_default_config('run_job', '')

    def run(self, path=None):
        self.check_params(self, check_from_module=True)

        run_job = self.myconfig('run_job')
        if not run_job:
            raise base.job.RVTError('run_job cannot be empty')

        for data in self.from_module.run(path):
            new_path = data.get('path', None)
            list(base.job.run_job(self.config, run_job, path=new_path, extra_config=data))
        return []


class SetFields(base.job.BaseModule):
    """ Get data from from_module, set or update some of its fields and yield again.

    Module description:
        - **path**: not used, passed to *from_module*.
        - **from_module**: mandatory. Data is updated.
        - **yields**: The updated data.

    Configuration:
        - **presets**: A dictionary of fields to be set, unless already set by data yielded by from_module.
        - **fields**: A dictionary of fields to be set. `fields` will be managed as a string template, passing the data yielded by from_module as parameter.
    """

    def read_config(self):
        super().read_config()
        self.set_default_config('presets', '')
        self.set_default_config('fields', '')

    def run(self, path=None):
        self.check_params(path, check_from_module=True)

        presetsStr = self.myconfig('presets')
        fieldsStr = self.myconfig('fields')
        presets = ast.literal_eval(presetsStr) if presetsStr else {}

        for data in self.from_module.run(path):
            newdata = dict(presets) if presets else {}
            newdata.update(data)
            if fieldsStr:
                try:
                    newdata.update(ast.literal_eval(fieldsStr.format(**data)))
                except KeyError as exc:
                    if self.myflag('stop_on_error'):
                        raise
                    self.logger().warning('Key not found: %s', exc)
            yield newdata


class Collapse(base.job.BaseModule):
    """ Collapse different documents sent by from_module with a common field into just one document.

    Warning: the collapse may take many time and memory

    Configuration section:
        - **field**: collapse documents using this field name as the common field.
    """
    def read_config(self):
        super().read_config()
        self.set_default_config('field', '_id')

    def run(self, path=None):
        self.check_params(path, check_from_module=True)
        field = self.myconfig('field')
        collapsed_data = {}
        for data in self.from_module.run(path):
            # data without the common field is yielded immediately
            data_field = data.get(field, None)
            # data with the common field is saved in memory. New data updates old data
            if not data_field:
                yield data
            if data_field in collapsed_data:
                collapsed_data[data_field].update(data)
            else:
                collapsed_data[data_field] = data
        # yield all data in memory
        for data in collapsed_data.keys():
            yield collapsed_data[data]


class AddFields(base.job.BaseModule):
    """ Get data from from_module, add some new fields loaded from configuration and yield again.

    Module description:
        - **path**: not used, passed to *from_module*.
        - **from_module**: Data is updated.
        - **yields**: The updated data.

    Configuration:
        - **section**: Section from configuration where new values are to be retrieved
        - **fields**: A dictionary of fields to be set. `fields` will be managed as a string template, passing the options from the configuration section as parameter.
    """

    def read_config(self):
        super().read_config()
        self.set_default_config('section', 'DEFAULT')
        self.set_default_config('fields', '')

    def run(self, path=None):
        self.check_params(path, check_from_module=True)

        fieldsStr = self.myconfig('fields')
        conf_section = self.myconfig('section')

        for data in self.from_module.run(path):
            newdata = data
            if fieldsStr:
                try:
                    newdata.update(ast.literal_eval(fieldsStr.format(**self.config.config[conf_section])))
                except KeyError as exc:
                    if self.myflag('stop_on_error'):
                        raise
                    self.logger().warning('Key not found: %s', exc)
            yield newdata


class GetFields(base.job.BaseModule):
    """ Get data from from_module, yield fields specified.

    Module description:
        - **path**: not used, passed to *from_module*.
        - **from_module**: Data dict.
        - **yields**: The updated dict data.

    Configuration:
        - **section**: Section from configuration where new values are to be retrieved
        - **fields**: A list of fields to be yielded.
    """

    def read_config(self):
        super().read_config()
        self.set_default_config('section', 'DEFAULT')
        self.set_default_config('fields', '')

    def run(self, path=None):
        self.check_params(path, check_from_module=True)

        fields = self.myarray('fields')

        results = self.from_module.run(path)
        if results is not None:
            for data in results:
                yield {k: data.get(k, '') for k in fields}
        else:
            return []


class RenameFields(base.job.BaseModule):
    """ Rename the specified field names with the provided new names.

    Module description:
        - **path**: not used, passed to *from_module*.
        - **from_module**: Data dict.
        - **yields**: The updated dict data.

    Configuration:
        - **fields**: List of key names to be renamed
        - **new_fields**: List of new key names
    """

    def read_config(self):
        super().read_config()
        self.set_default_config('section', 'DEFAULT')
        self.set_default_config('fields', '')
        self.set_default_config('new_fields', '')

    def run(self, path=None):
        self.check_params(path, check_from_module=True)

        fields = self.myarray('fields')
        new_fields = self.myarray('new_fields')

        if not fields:
            yield from self.from_module.run(path)
            return []

        if len(fields) != len(new_fields):
            raise base.job.RVTError('`fields` and `new_fields` must have the same number of items. Fields: {}; New fields: {}'.format(fields, new_fields))

        repl = dict(zip(fields, new_fields))
        for data in self.from_module.run(path):
            yield {repl.get(k, k): data[k] for k in data}


class SortResults(base.job.BaseModule):
    """ Sort the data from from_module, and yields results again.
    Take note that this operation loses some benefits of using generators,
    since sort operation must know all the items and the generator is consumed

    Warning: Sorting is not safe when sorting keys values are not strings

    Configuration:
        - **fields**: Space separated keys to sort by
        - **reverse**: Sort order
    """

    def read_config(self):
        super().read_config()
        self.set_default_config('fields', '')
        self.set_default_config('reverse', False)

    def run(self, path=None):
        self.check_params(path, check_from_module=True)
        fields = self.myarray('fields')
        reverse = self.myflag('reverse')

        if not fields:
            yield from self.from_module.run(path)
        else:
            yield from sorted(self.from_module.run(path), key=safe_string_itemgetter(*fields), reverse=reverse)


class SpaceText(base.job.BaseModule):
    """ Add spaces to text field every `steps` characters, so it is easy to read

    Configuration:
        - **fields**: Space separated keys to clean the hash
        - **steps**: Number of caharacters per chunck. If there is only one, it will be used for all fields. Otherwise, the number of items must be the same as fields to convert
    """

    def read_config(self):
        super().read_config()
        self.set_default_config('fields', '')
        self.set_default_config('steps', '20')

    def run(self, path=None):
        self.check_params(path, check_from_module=True)
        fields = self.myarray('fields')

        if not fields:
            yield from self.from_module.run(path)
            return []

        steps = self.myarray('steps')
        try:
            steps = [int(step) for step in steps]
        except ValueError:
            raise base.job.RVTError('`steps` must contain integers. Steps: {}'.format(steps))
        if len(steps) == 1:
            steps = [steps[0]] * len(fields)
        if len(fields) != len(steps):
            raise base.job.RVTError('`fields` and `steps` must have the same number of items. Fields: {}; Steps: {}'.format(fields, steps))

        for data in self.from_module.run(path):
            for i, field in enumerate(fields):
                if field in data:
                    data[field] = ' '.join(wrap(data[field], steps[i]))
            yield data


def safe_string_itemgetter(*items):
    """ Variation from operator itemgetter that helps to sort missing keys at first place"""
    if len(items) == 1:
        item = items[0]

        def g(obj):
            return obj.get(item, '')
    else:
        def g(obj):
            return tuple(obj.get(item, '') for item in items)
    return g
