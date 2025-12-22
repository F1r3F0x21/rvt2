# Copyright (C) DEFION.
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
import shutil
import re
from base.utils import check_directory
from base.commands import run_command
from plugins.common.RVT_timelines import BaseTimeline
import base.job


class UAC(base.job.BaseModule):
    """
    Extracts uac output and parses some info. It is supposed to be artifacts from unix based systems

    Configuration:
        - **fls**: Path to the fls app (TSK)
        - **apfs_fls**: Path to a fls app with APFS support (TSK>?)
        - **mactime**: Path to the mactime app (TSK)
    """

    def run(self, path=None):
        """ The path is the absolute path to the imagefile or device. If not provided, search in imagedir for known extensions """

        if path is None:
            path = self.myconfig('source')

        regex = re.search('uac-([^-]+)-([^-]+)-', path)
        self.source_name = regex.group(1)
        self.os_type = regex.group(2)
        imagefile = os.path.join(self.myconfig('imagedir'), f'{path}.tar.gz')
        if not os.path.exists(imagefile):
            self.logger().error(f'{imagefile} not exists')
            exit(1)

        self.casedir = self.myconfig('casedir')
        self.sourcedir = os.path.join(self.casedir, self.source_name)
        self.outputdir = os.path.join(self.sourcedir, 'output')
        self.tldir = os.path.join(self.outputdir, 'timelines')
        self.mountdir = os.path.join(self.sourcedir, 'mnt')

        check_directory(self.tldir, create=True)
        check_directory(self.mountdir, create=True)
        # Extract uac file
        run_command(['tar', 'xzvf', imagefile, '-C', self.sourcedir])

        # move [root] to p01 dir
        run_command(['mv', os.path.join(self.sourcedir, '[root]'), os.path.join(self.mountdir, 'p01')])

        self.generate_tl()
        summary = self.summary()
        check_directory(os.path.join(self.sourcedir, 'analysis'), create=True)
        outfile = os.path.join(self.sourcedir, 'analysis', self.myconfig('outfilename'))
        with open(outfile, 'w') as fout:
            fout.write("""[[[inlinetable(Información del sistema operativo,m{4.5cm}m{7cm})]]]
Concepto|Valor
--|--
""")
            for k, v in summary.items():
                fout.write(f'**{k}**| {v}\n')

        temp_dir = os.path.join(self.casedir, path)

        if os.path.exists(os.path.join(temp_dir, 'log')):
            shutil.move(os.path.join(temp_dir, 'log'), self.sourcedir)
            os.rmdir(temp_dir)

    def generate_tl(self):
        """ generate timeline from bodyfile """

        bodyfilename = os.path.join(self.tldir, f'{self.source_name}_BODY.csv')
        body_dir = os.path.join(self.sourcedir, 'bodyfile')
        run_command(['mv', os.path.join(body_dir, 'bodyfile.txt'), bodyfilename])
        if 'bodyfile.txt.stderr' in os.listdir(body_dir):
            shutil.move(os.path.join(body_dir, 'bodyfile.txt.stderr'), self.tldir)
            os.rmdir(body_dir)
        # shutil.move(os.path.join(self.sourcedir, 'bodyfile', 'bodyfile.txt'), bodyfilename)

        btl = BaseTimeline(config=self.config, section=self.section)

        btl.timeline_from_body(self.tldir, bodyfilename, False)
        shutil.move(os.path.join(self.tldir, f'{self.myconfig('source')}_TL.csv'), os.path.join(self.tldir, f'{self.source_name}_TL.csv'))

    def summary(self):
        """ Creates a os summary file with live response files """

        results = {}

        live_response_dir = os.path.join(self.sourcedir, 'live_response')
        with open(os.path.join(live_response_dir, 'network', 'hostname.txt'), 'r') as f_in:
            results['hostname'] = f_in.read().strip()
        ip_list = []
        regex = re.compile(r"inet ([\d.]+)/")
        with open(os.path.join(live_response_dir, 'network', 'ip_addr_show.txt'), 'r') as f_in:
            for line in f_in:
                aux = regex.search(line)
                if aux:
                    ip_list.append(aux.group(1))
        results['IP'] = ip_list
        regex2 = re.compile(r"(Virtualization|Operating System|Kernel|Architecture): (.*)")
        with open(os.path.join(live_response_dir, 'network', 'hostnamectl.txt'), 'r') as f_in:
            for line in f_in:
                aux = regex2.search(line)
                if aux:
                    results[aux.group(1)] = aux.group(2)
        return results
