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
import re
import datetime
import dateutil.parser
from lxml import etree
from collections import OrderedDict
from tqdm import tqdm

from plugins.external import jobparser
import base.job
from base.utils import check_directory, save_csv, save_json, relative_path
from plugins.windows.RVT_os_info import CharacterizeWindows


class ScheduledTasks(base.job.BaseModule):
    """ Parses job files and schedlgu.txt. """

    def run(self, path=""):
        self.check_params(path, check_path=True, check_path_exists=True)
        self.volume_id = self.myconfig('volume_id')
        # Try to guess volume id/partition from path
        if not self.volume_id:
            assumed_location = os.path.join(self.myconfig('casedir'), self.myconfig('source'), 'mnt')
            if path.find(assumed_location) != -1:
                self.volume_id = path[len(assumed_location) + 1:].split('/')[0]

        self.outfolder = self.myconfig('outdir')
        check_directory(self.outfolder, create=True)
        outfile_jobs = os.path.join(self.outfolder, "jobs_files_{}.csv".format(self.volume_id))
        outfile_sched = os.path.join(self.outfolder, 'schedlgu_{}.csv'.format(self.volume_id))
        outfile_tasks_json = os.path.join(self.outfolder, 'tasks_{}.json'.format(self.volume_id))
        outfile_tasks_csv = os.path.join(self.outfolder, 'tasks_{}.csv'.format(self.volume_id))

        self.logger().debug("Parsing artifacts from scheduled tasks files (.job)")
        save_csv(self.parse_Task(path), outfile=outfile_jobs, file_exists='APPEND', quoting=0)

        self.logger().debug("Parsing artifacts from Task Scheduler Service log files (schedlgu.txt)")
        save_csv(self.parse_schedlgu(path), config=self.config,
                 outfile=outfile_sched, file_exists='APPEND', quoting=0)

        self.logger().debug("Parsing XML files from Tasks directory")
        xml_tasks = list(self.parse_tasks_xml(path))
        save_json(xml_tasks, config=self.config,
                  outfile=outfile_tasks_json, file_exists='APPEND')
        save_csv(self.summarize_xml_tasks(xml_tasks), config=self.config,
                 outfile=outfile_tasks_csv, file_exists='APPEND')

        return []

    def parse_Task(self, directory):
        """ Parse .job files """
        jobs_files = [os.path.join(directory, file) for file in os.listdir(directory) if file.endswith('.job')]

        for file in jobs_files:
            with open(file, "rb") as f:
                data = f.read()
            # Every .job file is a task
            job = jobparser.Job(data)
            yield OrderedDict([("Product Info", jobparser.products.get(job.ProductInfo)),
                               ("File Version", job.FileVersion),
                               ("UUID", job.UUID),
                               ("Maximum Run Time", job.MaxRunTime),
                               ("Exit Code", job.ExitCode),
                               ("Status", jobparser.task_status.get(job.Status, "Unknown Status")),
                               ("Flasgs", job.Flags_verbose),
                               ("Date Run", job.RunDate),
                               ("Running Instances", job.RunningInstanceCount),
                               ("Application", "{} {}".format(job.Name, job.Parameter)),
                               ("Working Directory", job.WorkingDirectory),
                               ("User", job.User),
                               ("Comment", job.Comment),
                               ("Scheduled Date", job.ScheduledDate)])

        self.logger().debug("Finished extraction from scheduled tasks .job")

    def parse_schedlgu(self, directory):
        """ Parse SCHEDLGU.TXT files """
        sched_files = [os.path.join(directory, file) for file in os.listdir(directory) if file.lower().endswith('schedlgu.txt')]

        for file in sched_files:
            with open(file, 'r', encoding='utf16') as sched:
                dates = {'start': datetime.datetime.min, 'end': datetime.datetime.min}
                parsed_entry = False
                for line in sched:
                    if line == '\n':
                        continue
                    elif line.startswith('"'):
                        service = line.rstrip('\n').strip('"')
                        if parsed_entry:
                            yield OrderedDict([('Service', service), ('Started', dates['start']), ('Finished', dates['end'])])
                        parsed_entry = False
                        dates = {'start': datetime.datetime.min, 'end': datetime.datetime.min}
                        continue
                    for state, words in {'start': ['Started', 'Iniciado'], 'end': ['Finished', 'Finalizado']}.items():
                        for word in words:
                            if line.startswith('\t{}'.format(word)):
                                try:
                                    dates[state] = dateutil.parser.parse(line[re.search(r'\d', line).span()[0]:].rstrip('\n')).strftime("%Y-%m-%d %H:%M:%S")
                                    parsed_entry = True
                                except Exception:
                                    pass
                                break

        self.logger().debug("Finished extraction from schedlgu.txt")

    def parse_tasks_xml(self, directory):
        """ Parse UTF-16 encoded XML files inside Tasks folders """
        # ScheduledTasks XML format: https://docs.microsoft.com/en-us/windows/win32/taskschd/task-scheduler-schema
        task_xml_files = []
        for root_folder, subf, files in os.walk(directory):
            for file in files:
                if not file.endswith('.job') and not file.lower().endswith('schedlgu.txt'):
                    task_xml_files.append(os.path.join(root_folder, file))

        for file in tqdm(task_xml_files, total=len(task_xml_files), desc=self.section):
            try:  # Not all files may be in XML format
                st = etree.parse(file)
            except Exception as exc:
                self.logger().debug('File {} may not be a valid XML: {}'.format(file, exc))
                continue

            # Get the namespace. All tags are preceded by this namespace
            ns = st.getroot().nsmap[None]

            xml_dict = self._xml_element_to_dict(st.getroot(), ns=ns)
            xml_dict['FileName'] = relative_path(file, self.myconfig('sourcedir'))
            yield xml_dict

    def summarize_xml_tasks(self, xml_tasks):
        """ Get most relevant fields from task definitions"""
        os_info = CharacterizeWindows(config=self.config)

        for t in xml_tasks:
            has_start = False
            res = {'StartBoundary': '',
                   'TaskName': t.get('RegistrationInfo', {}).get('URI', '').lstrip('\\'),
                   'User': os_info.get_user_name_from_sid(t.get('Principals', {}).get('Principal', {}).get('UserId',''), partition=self.volume_id, sid_default=True),
                   'Command': '',
                   'Arguments': '',
                   'Enabled': t.get('Settings', {}).get('Enabled', ''),
                   'RunLevel': t.get('Principals', {}).get('Principal', {}).get('RunLevel', ''),
                   'Hidden': t.get('Settings', {}).get('Hidden', ''),
                   'Description': t.get('RegistrationInfo', {}).get('Description', '')
                  }

            if 'Exec' in t.get('Actions', {}):
                if isinstance(t['Actions']['Exec'], list):
                    res['Command'] = [exec.get('Command', '') for exec in t['Actions']['Exec']]
                    res['Arguments'] = [exec.get('Arguments', '') for exec in t['Actions']['Exec']]
                else:
                    res['Command'] = t['Actions']['Exec'].get('Command', '')
                    res['Arguments'] = t['Actions']['Exec'].get('Arguments', '')

            # Create a new instance of the task for every StartBoundary
            for trig in t.get('Triggers', {}).values():
                if 'StartBoundary' in trig:
                    res['StartBoundary'] = trig['StartBoundary']
                    has_start = True
                    yield res

            # Yield also tasks without StartBoundary
            if not has_start:
                yield res

    def _xml_element_to_dict(self, element, ns=''):
        """ Convert XML Element to a compated dictionary, ignoring attributes"""
        # If the element has no children, return its text directly
        ns_length = len(ns)
        if len(element) == 0:
            return element.text.strip() if element.text else None

        # Otherwise, create a dictionary to hold children
        child_dict = {}
        for child in element:
            child_value = self._xml_element_to_dict(child, ns=ns)

            # Handle repeated tags by grouping them in a list
            # Tags are in the format "{ns}tag_name". Keep only the tag_name
            tag = child.tag if not ns else child.tag[ns_length+2:]
            if tag in child_dict:
                if not isinstance(child_dict[tag], list):
                    child_dict[tag] = [child_dict[tag]]
                child_dict[tag].append(child_value)
            else:
                child_dict[tag] = child_value

        return child_dict
