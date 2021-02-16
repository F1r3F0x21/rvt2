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
import os.path
import re
import datetime
import logging
from collections import defaultdict
from tqdm import tqdm

import base.utils
from plugins.common.RVT_disk import getSourceImage
import base.job
import base.commands


class Files(base.job.BaseModule):
    """ Generates a list with all the allocated files in a disk, by visiting them. """

    def run(self, path=None):
        """ The path is ignored. """

        if self.myflag('vss'):
            self._generate_allocfiles_vss()
        else:
            self._generate_allocfiles()
        return []

    def _generate_allocfiles(self):
        """ Generates allocfiles

        Todo:
            - If file system is corrupt, alloc_files list may be different from the sleuthkit's output
        """

        mountdir = self.myconfig('mountdir')
        if not base.utils.check_directory(mountdir):
            self.logger().warning('Disk not mounted at {}'.format(mountdir))
            return

        outfile = os.path.join(self.config.get(self.section, 'outdir'), 'alloc_files.txt')
        base.utils.check_file(outfile, delete_exists=True, create_parent=True)
        find = self.myconfig('find', 'find')

        with open(outfile, 'wb') as outf:
            for p in os.listdir(mountdir):
                if p.startswith("p"):
                    relative_p_mountdir = base.utils.relative_path(os.path.join(mountdir, p), self.myconfig('casedir'))
                    base.commands.run_command([find, "-P", relative_p_mountdir + '/'], stdout=outf, logger=self.logger(), from_dir=self.myconfig('casedir'))

    def _generate_allocfiles_vss(self):
        """ Generates allocfiles from mounted vshadows snapshots  """

        disk = getSourceImage(self.myconfig)

        mountdir = self.myconfig('mountdir')
        if not base.utils.check_directory(mountdir):
            self.logger().warning('Disk not mounted')
            return

        outdir = self.config.get(self.section, 'voutdir')
        base.utils.check_directory(outdir, create=True)

        find = self.myconfig('find', 'find')
        for p in disk.partitions:
            for v, dev in p.vss.items():
                if dev != "":
                    with open(os.path.join(outdir, "alloc_{}.txt").format(v), 'wb') as f:
                        relative_v_mountdir = base.utils.relative_path(os.path.join(mountdir, v), self.myconfig('casedir'))
                        base.commands.run_command([find, '-P', relative_v_mountdir + '/'], stdout=f, logger=self.logger(), from_dir=self.myconfig('casedir'))


class GetFiles(object):
    """ This class provides method to interact with the list of all allocated files in the filesystem (alloc_files.txt) """

    # TODO: Files mounted may change over time. Is not enough to ensure allocfiles exists. It may be outdated
    def __init__(self, config, vss=False):
        self.logger = logging.getLogger('GetFiles')
        self.config = config
        self.vss = vss

    def get_alloc_txt_files(self):
        """ Return a list of all alloc_files-txt files present in the output directory for the source """
        alloc_txt_files = []
        files_instance = Files(config=self.config)
        if not self.vss:
            auxdir = self.config.get(files_instance.section, 'outdir')
            alloc_txt_files.append(os.path.join(auxdir, "alloc_files.txt"))
            if not os.path.isfile(alloc_txt_files[0]):
                self.logger.debug("Alloc files not yet created. Proceeding to generate them")
                files_instance._generate_allocfiles()
        else:
            auxdir = self.config.get(files_instance.section, 'voutdir')
            if not os.path.isdir(auxdir):
                self.logger.debug("Alloc files from Volume Snapshots not yet created. Proceeding to generate them.")
                files_instance._generate_allocfiles_vss()
            for file in os.listdir(auxdir):
                if file.startswith("alloc"):
                    alloc_txt_files.append(os.path.join(auxdir, file))

        return alloc_txt_files

    def search(self, regex):
        """ Return a list of allocated files matching 'regex'. """
        rgx = re.compile(regex, re.I)

        alloc_txt_files = self.get_alloc_txt_files()

        matches = []
        for file in alloc_txt_files:
            with open(file, "r") as alloc_f:
                for line in alloc_f:
                    if rgx.search(line):
                        matches.append(line.rstrip())
        return matches

    def files(self):
        """ Yield all of allocated file paths """
        for file in self.get_alloc_txt_files():
            with open(file, "r") as alloc_f:
                for path in alloc_f:
                    yield path


class FilterAllocFiles(base.job.BaseModule):
    """ Reads alloc_files and sends to from_module the filenames that match an expression.

    Configuration:
        - **regex**: the regex expression to match
        - **file_category**: if present, ignore regex and read extensions from this file_category.
        - **vss**: use virtual shadow instead of the current system (only Window images)
    """
    def read_config(self):
        super().read_config()
        self.set_default_config('regex', r'.*')
        self.set_default_config('vss', 'False')
        self.set_default_config('file_category', '')
        file_category = self.myconfig('file_category')
        if file_category:
            # if a file_category is present, use it to filter extensions
            extension_list = base.config.parse_conf_array(self.config.get(file_category, 'extension', ''))
            new_regex = r'\.({})$$'.format('|'.join(extension_list))
            self.local_config['regex'] = new_regex

    def run(self, path=None):
        """ The path is ignored """
        self.check_params(path, check_from_module=True)
        getfiles = GetFiles(self.config, vss=self.myflag("vss"))
        for filename in getfiles.search(self.myconfig('regex')):
            for data in self.from_module.run(filename):
                yield data


class SendAllocFiles(base.job.BaseModule):
    """
    The module sends to *from_module* the path to all files inside alloc_files.
    """
    def run(self, path=None):
        """ The path is ignored """
        self.check_params(path, check_from_module=True)
        paths = GetFiles(self.config, vss=self.myflag("vss")).files()
        for filename in paths:
            filename = os.path.join(self.myconfig('casedir'), filename.rstrip('\n'))
            for data in self.from_module.run(filename):
                yield data


class GetTimeline(base.job.BaseModule):
    """
    Reads timeline BODY file and returns entries that match an expression.
    """

    def __init__(self, *args, timeline_body_file=None, **kwargs):
        """
            Parameters:
                **timeline_body_file** (str): Path to timeline BODY file
                **config** (config object): RVT config

            Raises:
                IOError if timeline BODY file not found or empty
        """
        super().__init__(*args, **kwargs)
        if not timeline_body_file:
            timeline_body_file = os.path.join(self.config.config['plugins.windows']['timelinesdir'], '{}_BODY.csv'.format(self.myconfig('source')))

        if not (os.path.exists(timeline_body_file) and os.path.getsize(timeline_body_file) > 0):
            self.logger().warning('Timeline file not found: {}'.format(timeline_body_file))
            raise IOError

        self.timeline_body_file = timeline_body_file

    def run(self, path=None):
        """ To be implemented if used as a module"""
        return []

    def get_macb(self, file_list, regex=False, progress_disable=False):
        """ Get macb times from timeline BODY file given filenames defined in 'file_list'
        Admits regular expressions for the file search.
        Warning: Slow function. Use only with short or moderate list of files.

        Parameters:
            file_list (list): List of files, relative to sourcedir, to be searched for. Expected file format: sourcename/mnt/p0X/full_path'
            regex (boolean)): If True, consider the file_list as regular expressions
            progress_disable (boolean): If True, disable the progress bar.

        Returns:
            Dictionary 'filename':'dates' for each match. Values are dcitionaries where keys are:
            "m": modification date
            "a": access date
            "b": birth date
            "c": metadata change date
        """

        if not regex:
            search_command = 'grep "{regex}" "{path}"'  # Note that option -P is ommited. We are searching literal matches
        else:
            search_command = 'grep -iP "{regex}" "{path}"'
            # filename_list = ['/'.join(f.split('/')[3:]) for f in file_list]

        module = base.job.load_module(self.config, 'base.commands.RegexFilter', extra_config=dict(cmd=search_command, keyword_list=file_list))
        dates = defaultdict(dict)

        # In case tqdm is not needed: for line in module.run(self.timeline_body_file):
        # usually 2 matches per file. That's why 2 * len(file_list). Later FILE_NAME is skipped
        for line in tqdm(module.run(self.timeline_body_file), total=2 * len(file_list), desc='Getting macb times', disable=progress_disable):
            line = line['match'].split('|')
            filename = line[1]
            if filename.endswith(' ($FILE_NAME)'):  # Skip all FILE_NAME
                continue
            # WARNING: Current documentation for tsk at https://wiki.sleuthkit.org/index.php?title=Body_file is wrong.
            # The actual order for dates is 'amcb'.
            for date_index, date_type in zip([8, 7, 9, 10], ['m', 'a', 'c', 'b']):
                dates[filename][date_type] = datetime.datetime.utcfromtimestamp(int(line[date_index])).strftime("%Y-%m-%dT%H:%M:%SZ")

        return dates

    def get_path_from_inode(self, inode, partition='p01', inode_full=False):
        """ Get File path given an inode searching in timeline BODY file
        Warning: Slow function. Use only with short or moderate list of inodes.

        Parameters:
            inode (str): inode number to be searched for
            inode_full (boolean): if True, search for the 3 numbers. If False, just the base inode

        Returns:
            filename (str): path relative to casedir
        """
        with open(self.timeline_body_file, 'r') as infile:
            for line in infile:
                inode_to_compare = line[2] if inode_full else line[2].split('-')[0]
                if inode_to_compare == inode:
                    part = line[1].split('/')[2]
                    if part == partition:
                        return line[1]

        return ''


class ExtractPathTerms(base.job.BaseModule):
    """ Set new configuration options with user and partition obtained from a file path """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.regex_user = re.compile("(Documents and Settings|Users|home)/(?P<user>[^/]*)/")
        self.regex_partition = re.compile("/mnt/(?P<partition>[^/]*)/")

    def read_config(self):
        super().read_config()
        self.set_default_config('section', 'extract_terms')

    def run(self, path):
        user = self.get_user_from_path(path)
        partition = self.get_partition_from_path(path)
        self.config.set(self.myconfig('section'), 'user', user)
        self.config.set(self.myconfig('section'), 'partition', partition)
        for data in self.from_module.run(path):
            yield data

    def get_user_from_path(self, path):
        res = self.regex_user.search(path)
        if res is None:
            self.logger().error("Couldn't extract user from path: {}".format(path))
            return ''
        return res.group('user')

    def get_partition_from_path(self, path):
        res = self.regex_partition.search(path)
        if res is None:
            self.logger().error("Couldn't obtain partition from path: {}".format(path))
            return ''
        return res.group('partition')
