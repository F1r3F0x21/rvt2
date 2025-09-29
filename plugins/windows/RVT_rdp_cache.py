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

from PIL import Image
import os
import re

import base.job
# from plugins.common.RVT_files import GetFiles
from base.utils import check_directory
from base.commands import run_command


class RdpCache(base.job.BaseModule):

    def run(self, path=""):
        """ Parses rdp cache files """

        # Check if there's another rdp_cache job running
        base.job.wait_for_job(self.config, self, job_name='windows.rdp_cache')

        self.logger().info("Starting extraction of rdp cache image files")

        # self.Files = GetFiles(self.config)
        self.mountdir = self.myconfig('mountdir')

        base_path = self.myconfig('outdir')
        check_directory(base_path, create=True)

        # dir_list = [os.path.join(self.myconfig('casedir'), f) for f in self.Files.search(r'/Users/[^/]*/AppData/Local/Microsoft/Terminal Server Client/Cache$')]

        srch = re.compile(r'/([^/]*)/(Documents and Settings|Users)/([^/]*)')
        bmcc = os.path.join(self.myconfig('rvthome'), "plugins/external/bmc-tools/bmc-tools.py")
        python3 = os.path.join(self.myconfig('rvthome'), ".venv/bin/python3")

        srch_aux = srch.search(path)
        partition = srch_aux.group(1)
        user = srch_aux.group(3)
        self.logger().info(f'Extracting RDP cache images from user {user} at {partition}')
        outdir = os.path.join(base_path, f'imgs_{partition}_{user}')
        check_directory(outdir, create=True)
        run_command([python3, bmcc, '-s', path, '-d', outdir])
        self.logger().info('Joining images')
        self.join_images(outdir, os.path.join(base_path, f'{partition}_{user}'))

        self.logger().info("RDP cache extraction done")
        return []

    def join_images(self, inputdir, base_filename):
        """
        Method to join cache images in a one image
        Based on https://note.nkmk.me/en/python-pillow-concat-images/
        """

        n_horizontal_images = 16
        img_default_width = 64

        def get_concat_h_blank(imgs, color=(0, 0, 0)):
            """ Joins n_horizontal_images """

            dst = Image.new('RGB', (n_horizontal_images * img_default_width, img_default_width), color)
            for e, i in enumerate(imgs):
                dst.paste(i, (e * img_default_width, 0))
            return dst

        def get_concat_v_blank(imgs, color=(0, 0, 0)):
            """ Joins vertical images of n_horizontal_images * img_default_width """

            dst = Image.new('RGB', (n_horizontal_images * img_default_width, img_default_width * len(imgs)), color)
            for e, i in enumerate(imgs):
                dst.paste(i, (0, e * img_default_width))
            return dst

        img_list = sorted(os.listdir(inputdir))
        l = set()
        for i in img_list:
            l.add(i.split('_')[0])
        imgs_dict = {}
        for f in l:
            imgs_dict[f.split('_')[0]] = []

        for f in img_list:
            imgs_dict[f.split('_')[0]].append(f)

        for fkey, img_l in imgs_dict.items():
            imgs = []
            vimgs = []
            for e, i in enumerate(img_l):
                if e % n_horizontal_images == 0:
                    vimgs.append(get_concat_h_blank(imgs))
                    imgs = [Image.open(os.path.join(inputdir, i))]
                else:
                    imgs.append(Image.open(os.path.join(inputdir, i)))

            get_concat_v_blank(vimgs).save(os.path.join(f'{base_filename}_{fkey}.bmp'))
