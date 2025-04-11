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


""" Some simple file readers to be used as input for other modules. """

import os
import csv
import sqlite3
import ujson as json
import sys
import zipfile
import gzip
import mmap
from tqdm import tqdm

import base.job
from base.commands import estimate_iterations


class DummyReader(base.job.BaseModule):
    """ A dummy reader that creates as many empty dictionaries as requested in _number_.

    Use for debugging.

    Configuration:
        - **number**: Yields this many of empty dictionaries
    """

    def read_config(self):
        super().read_config()
        self.set_default_config('number', '10')

    def run(self, path):
        """ path and from_module are ignored """
        for i in range(0, int(self.myconfig('number'))):
            yield dict()


class GeneratorReader(base.job.BaseModule):
    """
    Manages `from_module` as a generator, not a module, and yields it contents.

    You can use this module to inject an array into another module down in the chain.

    Example:
        Save a list in a CSV file::

            data = [
                dict(greeting='Hello', language='English'),
                dict(greeting='Hola', language='Spanish')
            ]
            base.output.CSVSink(
                config,
                from_module=GeneratorReader(config, from_module=data),
                local_config=dict(outfile='outfile.csv')
            ).run()

    Attributes:
        from_module: Any generator-like object such a list. Yields its contents.
    """

    def run(self, path=None):
        """ Path is ignored. """
        self.check_params(path, check_from_module=True)
        for data in self.from_module:
            yield data


class AllLinesInFile(base.job.BaseModule):
    """ Yields every line in a file as a string

    Configuration:
        - **encoding** (String): The encoding to use. Defaults to utf-8
        - **reverse** (Boolean): If True, yield every line in reverse order. Defaults to False
        - **progress.disable** (Boolean): If True, disable the progress bar.
        - **progress.cmd** (String): The shell command to run to estimate the number of lines in the file. """

    def read_config(self):
        super().read_config()
        self.set_default_config('encoding', 'utf-8')
        self.set_default_config('reverse', False)
        self.set_default_config('progress.disable', 'False')
        self.set_default_config('progress.cmd', 'cat "{path}" | wc -l')

    def run(self, path):
        """ Read all lines from the path. from_module is ignored """
        self.check_params(path, check_path=True, check_path_exists=True)
        total_iterations = base.commands.estimate_iterations(path, self.myconfig('progress.cmd'))
        encoding = self.myconfig('encoding')

        with open(path, 'r', encoding=encoding) as infile:
            if not self.myflag('reverse'):
                for line in tqdm(infile, total=total_iterations,
                                 desc=f'Reading {os.path.basename(path)}',
                                 disable=self.myflag('progress.disable')):
                    yield line.strip()
            else:
                size = os.path.getsize(path)
                with tqdm(total=total_iterations, initial=0) as pbar:
                    with mmap.mmap(infile.fileno(), size, access=mmap.ACCESS_READ) as mm:
                        end = size
                        # If the file end in \n avoid yielding an empty line
                        if mm.rfind(b'\n', 0, end) == end - 1:
                            end = end - 1

                        while end > 0:
                            line_end = mm.rfind(b'\n', 0, end)
                            yield mm[line_end + 1:end].decode(encoding).strip()
                            pbar.update(1)
                            end = line_end


class AllLinesInCompressedFile(base.job.BaseModule):
    """ Pass to from_module each line in a compressed file as the path.

    Configuration:
        - **encoding** (String): The encoding to use. Defaults to utf-8
        - **reverse** (Boolean): If True, yield every line in reverse order. Defaults to False
        - **progress.disable** (Boolean): If True, disable the progress bar.
        - **chunk.size** (Integer): Size of the chunk when reading in reverse order. Defaults to 65536
    """

    def read_config(self):
        super().read_config()
        self.set_default_config('encoding', 'utf-8')
        self.set_default_config('reverse', False)
        self.set_default_config('progress.disable', 'False')
        self.set_default_config('chunk.size', 65536)

    def run(self, path):
        """ Read all lines from the path and pass them to from_module """
        self.check_params(path, check_path=True, check_path_exists=True)
        self.encoding = self.myconfig('encoding')
        is_gzip = False

        # Check what kind of compressed file it is
        if zipfile.is_zipfile(path):
            self.logger().info(f'Found ZIP file {path}')
            yield from self.read_zip(path)
        else:
            with gzip.open(path, 'r') as fh:
                try:
                    fh.read(1)
                    is_gzip = True
                except gzip.BadGzipFile:
                    pass
        if is_gzip:
            self.logger().info(f'Found GZIP file {path}')
            yield from self.read_gzip(path)
        else:
            self.logger().warning(f'Input file not in a well known compressed format (zip, gzip). Path: {path}')
            return []

    def read_zip(self, path):
        with zipfile.ZipFile(path, 'r') as f:
            # If many files exist inside the ZIP, it will read them one after another
            for file in f.namelist():
                with f.open(file, 'r') as internal:
                    line_count = sum(1 for line in internal)
                    if not self.myflag('reverse'):
                        internal.seek(0)  # Reset the file pointer to the beginning
                        for line in tqdm(internal, total=line_count,
                                         desc=f'Reading {os.path.basename(file)}',
                                         disable=self.myflag('progress.disable')):
                            yield line.strip().decode(self.encoding)
                    else:
                        for line in tqdm(self.reverse_readlines(f, chunk_size=int(self.myconfig('chunk.size')), encoding=self.encoding), total=line_count,
                                         desc=f'Reading {os.path.basename(path)}',
                                         disable=self.myflag('progress.disable')):
                            yield line

    def read_gzip(self, path):
        with gzip.open(path, 'rb') as f:
            # Assuming there is only one file inside GZIP
            line_count = sum(1 for line in f)
            if not self.myflag('reverse'):
                f.seek(0)  # Reset the file pointer to the beginning
                for line in tqdm(f, total=line_count,
                                 desc=f'Reading {os.path.basename(path)}',
                                 disable=self.myflag('progress.disable')):
                    yield line.strip().decode()
            else:
                for line in tqdm(self.reverse_readlines(f, chunk_size=int(self.myconfig('chunk.size')), encoding=self.encoding), total=line_count,
                                 desc=f'Reading {os.path.basename(path)}',
                                 disable=self.myflag('progress.disable')):
                    yield line

    def reverse_readlines(self, file_object, chunk_size=65536, encoding='utf-8'):
        """ Reads a file object in chunks in reverse, yielding each line from the end of the file to the beginning.

        With compressed files it is not possible to use mmap since mmap works with random access files,
        and a gzipped file is compressed, meaning that the file contents need to be decompressed sequentially.
        """

        file_object.seek(0, 2)  # Move the cursor to the end of the file
        buffer = b''
        end = file_object.tell()

        while end > 0:
            size = min(chunk_size, end)  # Determine the size of the chunk to read
            file_object.seek(end - size, 0)
            chunk = file_object.read(size)

            # Split the chunk into lines
            lines = chunk.split(b'\n')
            # Handle the first (incomplete) line of the chunk by prepending the buffer
            if buffer:
                lines[-1] += buffer
            buffer = lines[0]
            # Yield all complete lines in reverse order (skip the first if incomplete)
            for line in lines[-1:0:-1]:
                yield line.decode(encoding)
            end -= size

        # Yield the final line (if present in buffer)
        if buffer:
            yield buffer.decode(encoding)


class ForAllLinesInFile(base.job.BaseModule):
    """ Pass to from_module each line in a file as the path.

    Configuration:
        - **encoding** (String): The encoding to use. Defaults to utf-8
        - **progress.disable** (Boolean): If True, disable the progress bar.
        - **progress.cmd** (String): The shell command to run to estimate the number of lines in the file.
    """

    def read_config(self):
        super().read_config()
        self.set_default_config('encoding', 'utf-8')
        self.set_default_config('progress.disable', 'False')
        self.set_default_config('progress.cmd', 'cat "{path}" | wc -l')

    def run(self, path):
        """ Read all lines from the path and pass them to from_module """
        self.check_params(path, check_path=True, check_path_exists=True, check_from_module=True)
        total_iterations = base.commands.estimate_iterations(path, self.myconfig('progress.cmd'))
        with open(path, 'r', encoding=self.myconfig('encoding')) as infile:
            for line in tqdm(infile, total=total_iterations,
                             desc=f'Reading {os.path.basename(path)}',
                             disable=self.myflag('progress.disable')):
                newpath = line.strip()
                if not newpath:
                    continue
                for data in self.from_module.run(newpath):
                    yield data


class JSONReader(AllLinesInFile):
    """ Load every line in a file as a JSON dictionary and yields it.

    Configuration:
        - **encoding** (String): The encoding to use. Defaults to utf-8
        - **reverse** (Boolean): If True, yield every line in reverse order. Defaults to False
        - **progress.disable** (Boolean): If True, disable the progress bar.
        - **progress.cmd** (String): The shell command to run to estimate the number of lines in the file.
        - **check_path_exists** (Boolean): If True and provided path does not exist, raise an error. If False, just warn and continue
    """

    def read_config(self):
        super().read_config()
        self.set_default_config('encoding', 'utf-8')
        self.set_default_config('reverse', False)
        self.set_default_config('progress.disable', 'False')
        self.set_default_config('progress.cmd', 'cat "{path}" | wc -l')
        self.set_default_config('check_path_exists', True)

    def run(self, path):
        """ Read JSON file in the path. from_module is ignored """
        try:
            self.check_params(path, check_path=True, check_path_exists=True)
        except base.job.RVTErrorNotExistingPath as exc:
            if not self.myflag('check_path_exists'):
                self.logger().info(exc)
                return []
            raise exc
        for line in super().run(path):
            try:
                data = json.loads(line.strip())
                yield data
            except json.decoder.JSONDecodeError:
                if self.myflag('stop_on_error'):
                    raise


class CSVReader(base.job.BaseModule):
    """ Yields every line in a CSV file or generator object.

    Configuration:
        - **is_file** (Boolean): If True, take the 'path' as the input file to read. If False, assume a generator is passed from previous module and read it as a CSV file. Defaults to True.
        - **reverse** (Boolean): If True, yield every line in reverse order. Defaults to False
        - **encoding** (String): The encoding to use. Defaults to "utf-8"
        - **delimiter** (String): The delimiter to use. Use `AUTO` to dinamically find out. Defaults to ;
        - **quotechar** (String): The quotechar. Defaults to \"
        - **restkey** (String): The restkey of the DictReader. Defaults to "extra".
        - **restval** (String): The restval of the DictReader. Defaults to the empty string.
        - **fieldnames** (List or String): A list of header names. If None, use the first line.
          Warning: If provided, the first line will be considered data unless ignore_lines is set to >0
        - **ignore_lines** (Int): Ignore this number of initial lines. If fieldnames is provided, the first line after those is also ignored.
        - **progress.disable** (Boolean): If True, disable the progress bar.
        - **progress.cmd** (String): The shell command to run to estimate the number of lines in the file.
        - **check_path_exists** (Boolean): If True and provided path does not exist, raise an error. If False, just warn and continue
    """

    def read_config(self):
        super().read_config()
        self.set_default_config('is_file', True)
        self.set_default_config('reverse', False)
        self.set_default_config('encoding', 'utf-8')
        self.set_default_config('delimiter', ';')
        self.set_default_config('quotechar', '"')
        self.set_default_config('restkey', 'extra')
        self.set_default_config('restval', '')
        self.set_default_config('fieldnames', '')
        self.set_default_config('ignore_lines', '0')
        self.set_default_config('progress.disable', 'False')
        self.set_default_config('progress.cmd', 'cat "{path}" | wc -l')
        self.set_default_config('field_size_limit', sys.maxsize)  # Default csv max is 131072
        self.set_default_config('check_path_exists', True)

    def run(self, path):
        """ Read CSV file in the path. from_module is ignored """
        csv.field_size_limit(int(self.myconfig('field_size_limit')))
        self.ignore_lines = int(self.myconfig('ignore_lines'))
        self.fieldnames = self.myarray('fieldnames', None)

        # Case where input is a generator object
        if not self.myflag('is_file'):
            yield from self._iter_csv(path)
            return []

        # Case where input is a file
        try:
            self.check_params(path, check_path=True, check_path_exists=True)
        except base.job.RVTErrorNotExistingPath as exc:
            if not self.myflag('check_path_exists'):
                self.logger().info(exc)
                return []
            raise exc

        total_iterations = estimate_iterations(path, self.myconfig('progress.cmd'))
        initial_progress = self.ignore_lines
        if not self.fieldnames:  # if fieldnames is None, the first line is header. Add one to progress
            initial_progress = self.ignore_lines + 1
        encoding = self.myconfig('encoding')

        with open(path, 'r', encoding=encoding) as infile:
            for i in range(0, self.ignore_lines):
                infile.readline()
                ignore_position = infile.tell()
            delimiter = self.myconfig('delimiter')
            if self.myconfig('delimiter') == 'AUTO':
                delimiter = csv.Sniffer().sniff(infile.readline()).delimiter
                infile.seek(ignore_position)

            # Standard case reverse=False
            if not self.myflag('reverse'):
                reader = csv.DictReader(
                    infile,
                    fieldnames=self.fieldnames,
                    restval=self.myconfig('restval'), restkey=self.myconfig('restkey'),
                    delimiter=delimiter, quotechar=self.myconfig('quotechar'))
                # Main loop
                for data in tqdm(reader, total=total_iterations,
                                 initial=initial_progress,
                                 desc=f'Reading {os.path.basename(path)}',
                                 disable=self.myflag('progress.disable')):
                    yield data

            # Reverse reading
            else:
                size = os.path.getsize(path)
                if not self.fieldnames:
                    reader = csv.DictReader(
                        [infile.readline(), 'Dummy'],  # In order to guess fieldnames, csv.DictReader need at least a second line
                        restval=self.myconfig('restval'), restkey=self.myconfig('restkey'),
                        delimiter=delimiter, quotechar=self.myconfig('quotechar'))
                    for i in reader:
                        self.fieldnames = list(i.keys())
                    start_position = infile.tell()
                else:
                    start_position = ignore_position
                # Main loop
                with tqdm(total=total_iterations, initial=initial_progress) as pbar:
                    with mmap.mmap(infile.fileno(), size, access=mmap.ACCESS_READ) as mm:
                        end = size
                        while end > start_position:
                            line_end = mm.rfind(b'\n', 0, end)
                            line = mm[line_end + 1:end].decode(encoding).rstrip()
                            reader = csv.DictReader(
                                [line],
                                fieldnames=self.fieldnames,
                                restval=self.myconfig('restval'), restkey=self.myconfig('restkey'),
                                delimiter=delimiter, quotechar=self.myconfig('quotechar'))
                            yield from reader
                            pbar.update(1)
                            end = line_end

    def _iter_csv(self, path=None):
        input_object = self.from_module.run(path)
        reader = csv.DictReader(
            input_object,
            fieldnames=self.fieldnames,
            restval=self.myconfig('restval'), restkey=self.myconfig('restkey'),
            delimiter=self.myconfig('delimiter'), quotechar=self.myconfig('quotechar'))
        for data in reader:
            yield data


def _dict_factory(cursor, row):
    """ A factory to convert cursor rows in a database to dictionaries.

    See Python docs: https://docs.python.org/3.7/library/sqlite3.html """
    d = {}
    for idx, col in enumerate(cursor.description):
        d[col[0]] = row[idx]
    return d


class SQLiteReader(base.job.BaseModule):
    """ Returns the cursor of a query on a sqlite database.

    Rows in the database are returned as dictionaries.

    Configuration:
        - **query**: The SQL query to run.

    Current job section:
        - **query**: If the query in the module section is empty, read the SQL query from the job section.
        - **read_only**: If True, open the database in read_only mode
    """

    def read_config(self):
        super().read_config()
        self.set_default_config('query', '')
        self.set_default_config('read_only', False)

    def run(self, path):
        """ Read database from the path. from_module is ignored """
        self.check_params(path, check_path=True, check_path_exists=True)

        query = self.myconfig('query')
        if not query:
            try:
                query = self.config.get(self.config.job_name, 'query', None)
            except Exception as exc:
                self.logger().error(f'Cannot decode query for section {self.section}: {str(exc)}')
            if not query:
                self.logger().error('A query must be provided')
                raise base.job.RVTError('A query must be provided')

        connect_args = {'database': path}
        if self.myflag('read_only'):
            path = f"file://{path}?mode=ro&immutable=1"
            connect_args = {'database': path, 'uri': True}

        self.logger().debug(f'Query: {query}')

        with sqlite3.connect(**connect_args) as conn:
            conn.row_factory = _dict_factory
            c = conn.cursor()
            for data in c.execute(query):
                yield data
