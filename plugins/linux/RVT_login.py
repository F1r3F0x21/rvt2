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

import ast
import re
import os
import struct
import base.job
import subprocess, shlex
import pandas as pd
from tqdm import tqdm
from datetime import datetime, timedelta
from base.utils import date_to_iso, save_dummy, save_md_table
from plugins.linux import get_timezone
from functools import partial


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

class Group(base.job.BaseModule):
    """ Extract the essential information about group file.

    Module description:
        - **from_module**: Data dict.
        - **yields**: The updated dict data.
    """

    def read_config(self):
        super().read_config()

    def run(self, path=None):
        for line in self.from_module.run(path):
            data = line.split(":")
            group_entry_dict = {
                "group_name": data[0],
                "password": data[1],
                "group_ID": data[2],
                "user_list" : data[3]
            }
            yield group_entry_dict

class Gshadow(base.job.BaseModule):
    """ Extract the essential information about gshadow file.

    Module description:
        - **from_module**: Data dict.
        - **yields**: The updated dict data.
    """

    def read_config(self):
        super().read_config()

    def run(self, path=None):
        for line in self.from_module.run(path):
            data = line.split(":")
            group_entry_dict = {
                "group_name": data[0],
                "password": data[1],
                "administrators": data[2],
                "members" : data[3]
            }
            yield group_entry_dict

class LastLog(base.job.BaseModule):
    """ Extract the essential information about lastLog file.

    Module description:
        - **from_module**: Data dict.
        - **yields**: The updated dict data.
    """

    def read_config(self):
        super().read_config()

    def run(self, path=None):
        structure_block=struct.Struct("I32s256s")
        with open(path, "rb") as lastlog_file:
            for uid, block_bytes in enumerate(iter(partial(lastlog_file.read, structure_block.size), b"")):
                if any(block_bytes):
                    timestamp, line, host = structure_block.unpack(block_bytes)
                    dict_output = {
                        "user_ID" : uid,
                        "ut_line" : line.rstrip(b"\x00").decode("utf8"),
                        "ut_host" : host.rstrip(b"\x00").decode("utf8"),
                        "datetime" : datetime.fromtimestamp(timestamp)
                    }
                    # Localtime to UTC
                    local_tz = get_timezone(self.myconfig('mountdir'))
                    dict_output["datetime"] = date_to_iso(dict_output["datetime"], input_timezone=local_tz)

                    yield dict_output

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
                datetime_from_iso = date_to_iso(datetime_from)
                datetime_to_iso = date_to_iso(datetime_to)

                time_difference = datetime_to - datetime_from
                hours, remainder = divmod(time_difference.seconds, 3600)
                minutes, _ = divmod(remainder, 60)

                connection_dict = {
                    "@timestamp": str(datetime_from_iso),
                    "ut_type": "USER_PROCESS",
                    "ut_pid": register_dict[self.ut_type["USER_PROCESS"]]["ut_pid"],
                    "user.name": register_dict[self.ut_type["USER_PROCESS"]]["ut_user"],
                    "ut_line": register_dict[self.ut_type["USER_PROCESS"]]["ut_line"],
                    "ut_host": register_dict[self.ut_type["USER_PROCESS"]]["ut_host"],
                    "ut_time_to": str(datetime_to_iso),
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

class Analysis(base.job.BaseModule):
    """ Extract the essential information of the users and groups in a tables
    """

    def read_config(self):
        super().read_config()

    def run(self, path=None):
        self.login_dir = self.myconfig('logindir')

        df_result = pd.DataFrame()

        # User information
        url_passwd = os.path.join(self.login_dir, "passwd.csv")
        if os.path.isfile(url_passwd):
            df_passwd = pd.read_csv(url_passwd, sep=';', quotechar='"')
            data_passwd = []
            for index, row in df_passwd.iterrows():
                if str(row["home_directory"]).startswith("/home") or row["login_shell"] == "/bin/bash":
                    data_passwd.append(row)
            df_result = pd.DataFrame(data_passwd)
            df_result.columns = df_result.columns.str.strip()
            
            # Lastlog information
            df_result = self.lastlog(df_result)

            # Shadow information
            df_result = self.shadow(df_result)

            # Group information
            df_result = self.group(df_result)

            df_result_filtered = df_result[['user.name', 'user_ID', 'user_information', 'lastlog_ut_host', 'lastlog_datetime', 'last_password_change', 'group']]
            
            # Saving table
            txt_out = os.path.join(self.myconfig('analysisdir'), 'users_summary.md')
            data = df_result_filtered.to_markdown()
            with open(txt_out, 'w') as file:
                file.write(data)
            df_result_filtered.to_csv(os.path.join(self.myconfig('analysisdir'), 'users_summary.csv'))
        else:
            self.logger().error("To make the users table etc/passwd needed, and not found.")
        
        # Login information
        url_wtmp = os.path.join(self.login_dir, "wtmp.csv")
        if os.path.isfile(url_wtmp):
            df_wtmp = pd.read_csv(url_wtmp, sep=';', quotechar='"')
            df_filtered_wtmp = df_wtmp[df_wtmp['ut_type'] == 'USER_PROCESS']
            df_result_wtmp = df_filtered_wtmp[['user.name', 'ut_host', '@timestamp', 'ut_time_to', 'ut_time_total']]

            # Saving table
            txt_out = os.path.join(self.myconfig('analysisdir'), 'logins_summary.md')
            data = df_result_wtmp.to_markdown()
            with open(txt_out, 'w') as file:
                file.write(data)
            df_result_wtmp.to_csv(os.path.join(self.myconfig('analysisdir'), 'logins_summary.csv'))

    def lastlog(self, df_result):
        url_lastlog = os.path.join(self.login_dir, "lastlog.csv")
        if os.path.isfile(url_lastlog):
            df_lastlog = pd.read_csv(url_lastlog, sep=';', quotechar='"')
            df_result = pd.merge(df_result, df_lastlog, on='user_ID', how='outer')
            df_result.rename(columns={'ut_line': 'lastlog_ut_line', 'ut_host': 'lastlog_ut_host', 'datetime': 'lastlog_datetime' }, inplace=True)
            return df_result
        else:
            return df_result
        
    def shadow(self, df_result):
        url_shadow = os.path.join(self.login_dir, "shadow.csv")
        if os.path.isfile(url_shadow):
            df_shadow = pd.read_csv(url_shadow, sep=';', quotechar='"')
            df_result = pd.merge(df_result, df_shadow[['user.name', 'last_password_change']], on='user.name', how='left')
            return df_result
        else:
            return df_result
        
    def group(self, df_result):
        url_group_secure = os.path.join(self.login_dir, "group_secure.csv")
        if os.path.isfile(url_group_secure):
            df_group_secure = pd.read_csv(url_group_secure, sep=';', quotechar='"')
            df_result['group'] = None
            for index, row in df_group_secure.iterrows():
                if (pd.notna(row['members'])):
                    for user in str(row["members"]).split(","):
                        list_group = df_result.loc[df_result['user.name'] == user]
                        if not list_group.empty:
                            if list_group['group'].values != None:
                                list_group = list_group['group'].values[0]
                                list_group = ast.literal_eval(str(list_group))
                                list_group.append(row["group_name"])
                            else:
                                list_group = [row["group_name"]]
                            df_result.loc[df_result['user.name'] == user, 'group'] = str(list_group)
                        
        else:
            url_group = os.path.join(self.login_dir, "group.csv")
            if os.path.isfile(url_group):
                df_group = pd.read_csv(url_group, sep=';', quotechar='"')
                df_result['group'] = None
                print(df_group_secure)
                for index, row in df_group_secure.iterrows():
                    if (pd.notna(row['user_list'])):
                        for user in str(row["user_list"]).split(","):
                            list_group = df_result.loc[df_result['user.name'] == user]
                            if not list_group.empty:
                                if list_group['group'].values != None:
                                    list_group = list_group['group'].values[0]
                                    list_group = ast.literal_eval(str(list_group))
                                    list_group.append(row["group_name"])
                                else:
                                    list_group = [row["group_name"]]
                                df_result.loc[df_result['user.name'] == user, 'group'] = str(list_group)

        return df_result





