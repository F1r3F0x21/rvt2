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

import re
import os
import base.job
import subprocess, shlex
from tqdm import tqdm
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
                "user.name": data[0],
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
                "user.name": data[0],
                "encrypted_password": data[1],
                "last_password_change": formatted_date,
                "minimum_password_age": minimum_pwd_age,
                "maximum_password_age": maximum_pwd_age,
                "password_warning_period": warning_period,
                "password_inactivity_period": inactivity_period,
                "account_expiration_date": account_expiration_date
            }
            yield user_password_entry_dict

class Access(base.job.BaseModule):
    
    """ Extract the essential information about user accounts in access.conf file.

    Module description:
        - **from_module**: Data dict.
        - **yields**: The updated dict data.
    """

    def read_config(self):
        super().read_config()

    def run(self, path=None):
        for line in self.from_module.run(path):
            if not line.startswith('#') and line != '':
                data = line.split(":",2)
                user_account_entry_dict = {
                    "permission": data[0],
                    "users": data[1],
                    "origins ": data[2]
                }
                yield user_account_entry_dict

class Utmpdump(base.job.BaseModule):
    
    """ Extract the essential information of logins and additional information about system reboots in btmp and wtmp file.

    Module description:
        - **from_module**: Data dict.
        - **yields**: The updated dict data.
    """
    ut_type = {
        "EMPTY": "0",
        "RUN_LVL": "1",
        "BOOT_TIME": "2",
        "NEW_TIME": "3",
        "OLD_TIME": "4",
        "INIT_PROCESS": "5",
        "LOGIN_PROCESS": "6",
        "USER_PROCESS": "7",
        "DEAD_PROCESS": "8",
        "ACCOUNTING": "9"
    }

    def read_config(self):
        super().read_config()
        self.set_default_config('progress.disable', 'False')

    def run(self, path=None):
        pattern_authorized_keys = r'\[(.*)\]\s+\[(.*)\]\s+\[(.*)\]\s+\[(.*)\]\s+\[(.*)\]\s+\[(.*)\]\s+\[(.*)\]\s+\[(.*)\]'
        prog = re.compile(pattern_authorized_keys)
        command = "utmpdump " + path
        args = shlex.split(command)
        process = subprocess.Popen(args,  stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        aux_dict = {}

        output_string = process.stdout.read()
        total_iterations = output_string.count('\n') + 1

        for line in tqdm(output_string.split('\n'), total=total_iterations,
                            desc='Reading {}'.format(os.path.basename(path)),
                            disable=self.myflag('progress.disable')):
            match = prog.match(line)
            if match:
                match_group = match.groups()
                wtmp_entry_dict = {
                    "ut_type": match_group[0].strip(),
                    "ut_pid": match_group[1].strip(),
                    "ut_id": match_group[2].strip(),
                    "ut_user": match_group[3].strip(),
                    "ut_line": match_group[4].strip(),
                    "ut_host": match_group[5].strip(),
                    "ut_addr_v6": match_group[6].strip(),
                    "ut_time": match_group[7].strip()
                }
                aux_dict, data_to_yield = self.UtmpdumpConnectionsStartedAndEnded(wtmp_entry_dict, aux_dict)
                if data_to_yield:
                    yield data_to_yield
            else:
                self.logger().warning("Regex pattern failed with some utmp line: " + line)
        
        connections_to_yield = self.UtmpdumpOtherConnections(aux_dict)
        for conection in connections_to_yield:
            yield conection

        process.wait()
    
    def UtmpdumpConnectionsStartedAndEnded(self, input_dict, aux_dict):
        connection_dict = False

        dict_pid = aux_dict.get(input_dict["ut_pid"],"Empty")
        if dict_pid == "Empty":
            aux_dict[input_dict["ut_pid"]] = {input_dict["ut_type"]: input_dict}
        else:
            aux_dict[input_dict["ut_pid"]].update({input_dict["ut_type"]: input_dict})

        if input_dict["ut_type"] == self.ut_type["USER_PROCESS"] or input_dict["ut_type"] == self.ut_type["DEAD_PROCESS"]: 
            if self.ut_type["USER_PROCESS"] in aux_dict[input_dict["ut_pid"]].keys() and self.ut_type["DEAD_PROCESS"] in aux_dict[input_dict["ut_pid"]].keys():
                register_dict = aux_dict.get(input_dict["ut_pid"])
                aux_dict.pop(input_dict["ut_pid"])

                # time conversion
                time_format = "%Y-%m-%dT%H:%M:%S,%f%z"
                time_from = register_dict[self.ut_type["USER_PROCESS"]]["ut_time"]
                time_to = register_dict[self.ut_type["DEAD_PROCESS"]]["ut_time"]

                datetime_from = datetime.strptime(time_from, time_format)
                datetime_to = datetime.strptime(time_to, time_format)

                time_difference = datetime_to - datetime_from
                hours, remainder = divmod(time_difference.seconds, 3600)
                minutes, _ = divmod(remainder, 60)

                connection_dict = {
                    "@timestamp": time_from,
                    "ut_type": "USER_PROCESS",
                    "ut_pid": register_dict[self.ut_type["USER_PROCESS"]]["ut_pid"],
                    "user.name": register_dict[self.ut_type["USER_PROCESS"]]["ut_user"],
                    "ut_line": register_dict[self.ut_type["USER_PROCESS"]]["ut_line"],
                    "ut_host": register_dict[self.ut_type["USER_PROCESS"]]["ut_host"],
                    "ut_time_to": time_to,
                    "ut_time_total": f"{hours}:{minutes:02}"
                }

        return aux_dict, connection_dict
    
    def UtmpdumpOtherConnections(self, aux_dict):
        list_data = []
        ut_type_T = {
            0: "EMPTY",
            1: "RUN_LVL",
            2: "BOOT_TIME",
            3: "NEW_TIME",
            4: "OLD_TIME",
            5: "INIT_PROCESS",
            6: "LOGIN_PROCESS",
            7: "USER_PROCESS",
            8: "DEAD_PROCESS",
            9: "ACCOUNTING"
        }
        for tuple_pid_dict in aux_dict.items():
            for ut_type_key, dict_value in tuple_pid_dict[1].items():
                
                ut_type_2 = ut_type_T[int(ut_type_key)]
                if ut_type_key == self.ut_type["USER_PROCESS"]:
                    ut_time_to = "-"
                    ut_time_total = "gone - no logout"
                    time_from = dict_value["ut_time"]

                else:
                    ut_time_to = ""
                    ut_time_total = ""
                    time_from = dict_value["ut_time"]

                connection_dict = {
                    "@timestamp": time_from,
                    "ut_type": ut_type_2,
                    "ut_pid": dict_value["ut_pid"],
                    "user.name": dict_value["ut_user"],
                    "ut_line": dict_value["ut_line"],
                    "ut_host": dict_value["ut_host"],
                    "ut_time_to": ut_time_to ,
                    "ut_time_total": ut_time_total
                }
                list_data.append(connection_dict)
        return list_data

