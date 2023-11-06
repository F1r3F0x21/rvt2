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

# TODO finish script and dump to file
# Linux partitions must be mounted

import base.job
from datetime import datetime, timedelta

class Passwd(base.job.BaseModule):
    
    """ Extract the essential information about user accounts in passwd file.

    Module description:
        - **from_module**: Data dict.
        - **yields**: The updated dict data.
    """

    def read_config(self):
        super().read_config()

    def run(self, path=None):
        for line in self.from_module.run(path):
            data = line.split(":")
            user_account_entry_dict = {
                "username": data[0],
                "password": data[1],
                "user_ID ": data[2],
                "group_ID": data[3],
                "user_information" : data[4],
                "home_directory" : data[5],
                "login_shell": data[6]
            }
            yield user_account_entry_dict

class Shadow(base.job.BaseModule):
    
    """ Extract the essential information secure user account information in shadow file.

    Module description:
        - **from_module**: Data dict.
        - **yields**: The updated dict data.
    """

    def read_config(self):
        super().read_config()

    def run(self, path=None):
        for line in self.from_module.run(path):
            data = line.split(":")

            # last password change conversion
            start_date = datetime(1970, 1, 1)
            date_change = str(data[2])
            if date_change == "":
                formatted_date = "disabled"
            else:
                if date_change == "0":
                    formatted_date = "to be changed"
                else:
                    corresponding_date = start_date + timedelta(days=int(data[2]))
                    formatted_date = corresponding_date.strftime('%Y-%m-%d')
            
            # minimum password age conversion
            if str(data[3]) == "0":
                minimum_pwd_age = "disabled"
            else:
                if data[3] != "":
                    minimum_pwd_age = f"{data[3]} days"
                else:
                    minimum_pwd_age = data[3]
            
            # maximum password age conversion
            if data[4] != "":
                maximum_pwd_age = f"{data[4]} days"
            else:
                maximum_pwd_age = ""
            
            # password warning period
            if data[5] != "":
                warning_period = f"{data[5]} days"
            else:
                warning_period = ""
            
            # password inactivity period
            if data[6] != "":
                inactivity_period = f"{data[6]} days"
            else:
                inactivity_period = ""            

            # account expiration date conversion
            date_exp = str(data[7])
            if date_exp == "":
                account_expiration_date = "Never expire"
            else:
                corresponding_date = start_date + timedelta(days=int(data[2]))
                account_expiration_date = corresponding_date.strftime('%Y-%m-%d')

            user_password_entry_dict = {
                "account_name": data[0],
                "encrypted_password": data[1],
                "last_password_change": formatted_date,
                "minimum_password_age": minimum_pwd_age,
                "maximum_password_age": maximum_pwd_age,
                "password_warning_period": warning_period,
                "password_inactivity_period": inactivity_period,
                "account_expiration_date": account_expiration_date
            }
            yield user_password_entry_dict
