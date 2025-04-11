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
import pyesedb
import uuid
import binascii
import struct
import datetime
import base.job
from base.utils import save_csv


GUID_Dict = {
    '{10A9226F-50EE-49D8-A393-9A501D47CE04}': 'File Server',
    '{1479A8C1-9808-411E-9739-2D3C5923E86A}': 'Windows Server 2016 DatacenterRemote Desktop Gateway',
    '{2414BC1B-1572-4CD9-9CA5-65166D8DEF3D}': 'SQL Server Analysis Services',
    '{4116A14D-3840-4F42-A67F-F2F9FF46EB4C}': 'Windows Deployment Services',
    '{48EED6B2-9CDC-4358-B5A5-8DEA3B2F3F6A}': 'DHCP Server',
    '{4AD13311-EC3B-447E-9056-14EDE9FA7052}': 'Active Directory Lightweight Directory Services',
    '{7CC4B071-292C-4732-97A1-CF9A7301195D}': 'FAX Server',
    '{7FB09BD3-7FE6-435E-8348-7D8AEFB6CEA3}': 'Print and Document Services',
    '{8CC0AC85-40F7-4886-9DAB-021519800418}': 'Reporting Services',
    '{90E64AFA-70DB-4FEF-878B-7EB8C868F091}': 'Windows ServerRemote Desktop Services',
    '{910CBAF9-B612-4782-A21F-F7C75105434A}': 'BranchCache',
    '{952285D9-EDB7-4B6B-9D85-0C09E3DA0BBD}': 'Remote Access',
    '{AD495FC3-0EAA-413D-BA7D-8B13FA7EC598}': 'Active Directory Domain Services',
    '{B4CDD739-089C-417E-878D-855F90081BE7}': 'Active Directory Rights Management Service',
    '{BBD85B29-9DCC-4FD9-865D-3846DCBA75C7}': 'Network Policy and Access Services',
    '{BD7F7C0D-7C36-4721-AFA8-0BA700E26D9E}': 'SQL Server Database Engine',
    '{C23F1C6A-30A8-41B6-BBF7-F266563DFCD6}': 'FTP Server',
    '{C50FCC83-BC8D-4DF5-8A3D-89D7F80F074B}': 'Active Directory Certificate Services',
    '{D6256CF7-98FB-4EB4-AA18-303F1DA1F770}': 'Web Server',
    '{D8DC1C8E-EA13-49CE-9A68-C9DCA8DB8B33}': 'Windows Server Update Services',
    '{DDE30B98-449E-4B93-84A6-EA86AF0B19FE}': 'MSMQ'
}


class UAL(base.job.BaseModule):
    """ Parses User Access Logs (UAL) """

    # Code adapted from https://github.com/brimorlabs/KStrike
    # UAL forensic information: https://svch0st.medium.com/windows-user-access-logs-ual-9580f1100635

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.INSERT_YEAR = "1601"
        self.INSERT_HOUR = "00"
        self.INSERT_DAY = "01"
        self.INSERT_DATE = "1601-01-01"
        self.LAST_YEAR = "1601"
        self.LAST_DATE = "1601-01-01"
        self.BAD_YEAR_DETECTOR = False
        self.CORRELATED_ACCESS_MISMATCH = False
        self.DNS_IP_ADDRESS = 'False'
        self.TOTAL_ACCESSES_COUNT = 0
        self.DNS_Dict = {}
        self.columns_names = {
            "DNS": ["LastSeen", "Address", "HostName"],
            "CLIENTS": ["RoleGuid", "TenantId", "TotalAccesses", "InsertDate", "LastAccess", "Address", "AuthenticatedUserName", "ClientName", "DatesAndAccesses"],
            "ROLE_ACCESS": ["RoleGuid", "FirstSeen", "LastSeen"],
            "SYSTEM_IDENTITY": ["CreationTime", "PhysicalProcessorCount", "CoresPerPhysicalProcessor", "LogicalProcessorsPerPhysicalProcessor", "MaximumMemory", "OSMajor", "OSMinor", "OSBuildNumber", "OSPlatformId", "ServicePackMajor", "ServicePackMinor", "OSSuiteMask", "OSProductType", "OSCurrentTimeZone", "OSDaylightInEffect", "SystemManufacturer", "SystemProductName", "SystemSMBIOSUUID", "SystemSerialNumber", "SystemDNSHostName", "SystemDomainName", "OSSerialNumber", "OSCountryCode", "OSLastBootUpTime"],
            "CHAINED_DATABASES": ["Year", "FileName"],
            "ROLE_IDS": ["RoleGuid", "ProductName", "RoleName"]
        }

    def run(self, path):
        self.check_params(path, check_path=True, check_path_exists=True)
        outdir = self.myconfig('outdir')
        for file in os.listdir(path):
            if not file.lower().endswith('.mdb'):
                continue

            self.logger().debug(f'Parsing {file}')
            # Each mdb file other than SystemIdentity.mdb contains information of a single year. Relation described on CHAINED_DATABASES table
            with open(os.path.join(os.path.abspath(path), file), "rb") as fin:
                self.esedb_file = pyesedb.file()
                self.esedb_file.open_file_object(fin)
                Num_Of_tables = self.esedb_file.get_number_of_tables()
                self.tables_dict = {self.esedb_file.get_table(i).get_name(): i for i in range(0, Num_Of_tables)}

                # Process SystemIdentity.mdb database separately
                if file.lower() == 'systemidentity.mdb':
                    save_csv(self._parse_table('SYSTEM_IDENTITY'), config=None, outfile=os.path.join(outdir, 'SystemIdentity.csv'),
                             file_exists='OVERWRITE', fieldnames=str(self.columns_names['SYSTEM_IDENTITY']))
                    save_csv(self._parse_table('CHAINED_DATABASES'), config=None, outfile=os.path.join(outdir, 'Databases.csv'),
                             file_exists='OVERWRITE', fieldnames=str(self.columns_names['CHAINED_DATABASES']))
                    # save_csv(self._parse_table('ROLE_IDS'), config=None, outfile=os.path.join(outdir, 'RoleIds.csv'),
                    #          file_exists='OVERWRITE', fieldnames=str(self.columns_names['ROLE_IDS']))

                else:
                    # Process DNS table the first, since it will fill Clients table information
                    save_csv(self._parse_table('DNS'), config=None, outfile=os.path.join(outdir, 'DNS.csv'),
                             file_exists='APPEND', fieldnames=str(self.columns_names['DNS']))

                    # Process CLIENTS table once DNS relation is already stablished
                    records = []
                    for record in self._parse_table('CLIENTS'):
                        records.append(record)
                        yield record  # Yield to the cummulative CSV for all years
                    save_csv(records, config=None, outfile=os.path.join(outdir, f'{file.split(".")[0]}.csv'),
                             file_exists='OVERWRITE', fieldnames=str(self.columns_names['CLIENTS']))

                    # Finally, to know which roles have been used each year, parse ROLE_ACCESS table
                    save_csv(self._parse_table('ROLE_ACCESS'), config=None, outfile=os.path.join(outdir, 'RoleAccess.csv'),
                             file_exists='APPEND', fieldnames=str(self.columns_names['ROLE_ACCESS']))

    def _parse_table(self, table_name):
        try:
            if table_name not in self.tables_dict:
                return []
            Table = self.esedb_file.get_table(self.tables_dict[table_name])
            Table_Num_Records = Table.get_number_of_records()
            for t in range(0, Table_Num_Records):
                data = {}
                days = ""
                Table_Num_Columns = Table.get_number_of_columns()
                for x in range(0, Table_Num_Columns):
                    Table_Record = Table.get_record(t)
                    Column_Name = Table_Record.get_column_name(x)
                    Column_Type = Table_Record.get_column_type(x)
                    if Column_Name.startswith('Day'):  # Day Columns are handled separately
                        days += self.process_data(Table_Record, Column_Type, x, Column_Name, table_name)
                    else:
                        data[self.columns_names[table_name][x]] = self.process_data(Table_Record, Column_Type, x, Column_Name, table_name)
                if days:
                    data["DatesAndAccesses"] = days[:-2]
                yield(data)
                self.BAD_YEAR_DETECTOR = False
                self.CORRELATED_ACCESS_MISMATCH = False
        except Exception as exc:
            self.logger().error(f'Error while parsing table {table_name}. {exc}')

    def win_date_bin_to_datetime(self, win_date_bin, Column_Name):
        """ Converts the datetime field of the CLIENTS table specificaly. It is Windows FILETIME """
        decimaldate = int(struct.unpack("<Q", win_date_bin)[0])
        try:
            windowsdt = datetime.datetime(1601, 1, 1, 0, 0, 0) + datetime.timedelta(microseconds=decimaldate / 10)
        except Exception:
            windowsdt = datetime.datetime(1601, 1, 1, 0, 0, 0)
        fourofyear = str(windowsdt)[0:4]  # Year number
        fullyyyymmdd = str(windowsdt)[0:10]  # Full yyyy-mm-dd
        twoofhour = str(windowsdt)[11:13]  # Hour
        twoofdate = str(windowsdt)[8:10]  # Day
        if ((len(fourofyear) == 4) and Column_Name == "InsertDate"):
            self.INSERT_YEAR = fourofyear
            self.INSERT_DATE = fullyyyymmdd
            self.INSERT_DAY = twoofdate
            self.INSERT_HOUR = twoofhour
        elif ((len(fourofyear) == 4) and Column_Name == "LastAccess"):
            self.LAST_YEAR = fourofyear
            self.LAST_DATE = fullyyyymmdd
        return str(windowsdt)

    def process_data(self, Table_Record, Column_Type, Column_Number, Column_Name, Table_name):
        if (Column_Type == 0):  # Null
            return "NULL"
        elif (Column_Type == 1):  # Boolean
            if (Table_Record.get_value_data(Column_Number) is None):
                return "NULL"
            else:
                return str(Table_Record.get_value_data(Column_Number).decode('utf-16', 'ignore'))
        elif (Column_Type == 2):  # INTEGER_8BIT_UNSIGNED
            return Table_Record.get_value_data_as_integer(Column_Number)
        elif (Column_Type == 3):  # INTEGER_16BIT_SIGNED
            return Table_Record.get_value_data_as_integer(Column_Number)
        elif (Column_Type == 4):  # INTEGER_32BIT_SIGNED
            return Table_Record.get_value_data_as_integer(Column_Number)
        elif (Column_Type == 5):  # CURRENCY
            return Table_Record.get_value_data_as_integer(Column_Number)
        elif (Column_Type == 6):  # INTEGER_8BIT_UNSIGNED
            return Table_Record.get_value_data_as_floating_point(Column_Number)
        elif (Column_Type == 7):  # DOUBLE_64BIT
            return Table_Record.get_value_data_as_floating_point(Column_Number)
        elif (Column_Type == 8):  # DATETIME
            if (Table_Record.get_value_data(Column_Number) is None):
                return ''
            else:
                return self.win_date_bin_to_datetime(Table_Record.get_value_data(Column_Number), Column_Name)
        elif (Column_Type == 9):  # BINARY_DATA_TO_HEX
            if (Table_Record.get_value_data(Column_Number) is None):
                return "NO BINARY_DATA_TO_HEX"
            else:
                hexdb = binascii.hexlify(Table_Record.get_value_data(Column_Number))  # Turning the binary data to hex
                macaddress = hexdb.decode('utf-8', 'ignore')
                if ((len(hexdb) <= 8) and Column_Name == "Address"):
                    if (len(hexdb) < 8):
                        hexdb = ''.join(('0', hexdb))  # Adding zeros to make sure everything is correct
                    ipaddr = "%i.%i.%i.%i" % (int(hexdb[0:2], 16), int(hexdb[2:4], 16), int(hexdb[4:6], 16), int(hexdb[6:8], 16))
                    raw_ipaddr_correlations = self.DNS_Dict.get(ipaddr, "")
                    ipaddr_correlations = str(raw_ipaddr_correlations).strip("[]")  # Removing brackets
                    return str(ipaddr) + (" (" + str(ipaddr_correlations) + ")" if ipaddr_correlations else "")
                elif (((macaddress[:4] == "fe80") or (macaddress[:4] == "2001")) and (Column_Name == "Address") and (len(hexdb) == 32)):  # A couple of checks for the IPV6 address formatting. So far have only seen fe80 and 2001, there may be more
                    colonaddedtohexdb = ':'.join(macaddress[i:i + 4] for i in range(0, len(macaddress), 4))  # Adding colons to the IPV6 address
                    ipv6Parts = colonaddedtohexdb.split(":")
                    macParts = []
                    for ipv6Part in ipv6Parts[-4:]:
                        while len(ipv6Part) < 4:
                            ipv6Part = "0" + ipv6Part
                        macParts.append(ipv6Part[:2])
                        macParts.append(ipv6Part[-2:])
                    macParts[0] = "%02x" % (int(macParts[0], 16) ^ 2)
                    del macParts[4]
                    del macParts[3]
                    rawmacparts = ":".join(macParts)
                    finalmac = str(rawmacparts).upper()
                    return str(finalmac)
                elif ((str(macaddress) == "00000000000000000000000000000001") and (Column_Name == "Address") and (len(hexdb) == 32)):  # A couple of checks for the IPV6 local host address formatting
                    return "::1"
                else:
                    return ""
        elif (Column_Type == 10):  # TEXT
            if (Table_Record.get_value_data(Column_Number) is None):
                return ''
            else:
                return Table_Record.get_value_data(Column_Number).decode('utf-16', 'ignore').replace('\x00', '')
        elif (Column_Type == 11):  # LARGE_BINARY_DATA
            if (Table_Record.get_value_data(Column_Number) is None):
                return ''
            else:
                return Table_Record.get_value_data(Column_Number)
        elif (Column_Type == 12):  # LARGE_TEXT
            if ((Table_Record.get_value_data(Column_Number) is None) and (Column_Name == "ClientName")):
                return ''
            elif ((Table_Record.get_value_data(Column_Number) is None) and (Column_Name == "AuthenticatedUserName")):
                return "<BLANK>"
            elif ((Table_Record.get_value_data(Column_Number) == "\x00\x00") and (Column_Name == "AuthenticatedUserName")):
                return "<BLANK>"
            elif ((Table_Record.get_value_data(Column_Number) == "") and (Column_Name == "AuthenticatedUserName")):
                return "<BLANK>"
            elif ((Column_Name == "Address") and (Table_name == "DNS")):  # Pulling out IP address from DNS table
                self.DNS_IP_ADDRESS = Table_Record.get_value_data(Column_Number).decode('utf-16', 'ignore').replace('\x00', '')
                return self.DNS_IP_ADDRESS
            elif ((Column_Name == "HostName") and (Table_name == "DNS")):  # Pulling out Hostname from DNS table
                hostname_from_dns = Table_Record.get_value_data(Column_Number).decode('utf-16', 'ignore').replace('\x00', '')
                if self.DNS_IP_ADDRESS in self.DNS_Dict:
                    self.DNS_Dict[str(self.DNS_IP_ADDRESS)].append(str(hostname_from_dns))
                else:
                    self.DNS_Dict[str(self.DNS_IP_ADDRESS)] = [str(hostname_from_dns)]
                return str(hostname_from_dns)
            else:
                large_text = Table_Record.get_value_data(Column_Number).decode('utf-16', 'ignore')
                if len(large_text) > 1:
                    return large_text.replace('\x00', '')
                else:
                    return "<BLANK>"
        elif (Column_Type == 13):  # SUPER_LARGE_VALUE
            return Table_Record.get_value_data_as_integer(Column_Number)
        elif (Column_Type == 14):  # INTEGER_32BIT_UNSIGNED
            int32bitunsigned = str(Table_Record.get_value_data_as_integer(Column_Number))
            if (Column_Name == "TotalAccesses"):
                self.TOTAL_ACCESSES_COUNT = int32bitunsigned  # Setting variable for a check later on
            return int32bitunsigned
        elif (Column_Type == 15):  # INTEGER_64BIT_SIGNED
            return Table_Record.get_value_data_as_integer(Column_Number)
        elif (Column_Type == 16):  # GUID
            if (Table_Record.get_value_data(Column_Number) is None):
                return "NO GUID DATA"
            else:
                uuid_Bytes = Table_Record.get_value_data(Column_Number)
                orgguid = uuid.UUID(bytes_le=uuid_Bytes)  # Turning the data into a GUID
                urnguid = orgguid.urn
                rawguid = urnguid[9:]
                ucrawguid = str(rawguid).upper()
                fullguid = '{' + ucrawguid + '}'  # Building the GUID for the table lookup
                if (Column_Name == "RoleGuid"):
                    GUID_conversion = GUID_Dict.get(fullguid, "")
                    return fullguid + (" (" + GUID_conversion + ")" if GUID_conversion else "")
                else:
                    return fullguid
        elif (Column_Type == 17):  # INTEGER_16BIT_UNSIGNED
            value = Table_Record.get_value_data_as_integer(Column_Number)
            if ((value is not None) and ("Day" in str(Column_Name))):  # Checking to see if Day is in the field
                juliandate = str(Column_Name)[3:]  # Pulling out Julian Date
                if ((int(self.INSERT_YEAR)) != (int(self.LAST_YEAR)) and (Column_Name != "Day1") and (self.TOTAL_ACCESSES_COUNT == "2")):
                    if (not self.CORRELATED_ACCESS_MISMATCH):
                        str(self.INSERT_DATE) + ":1, " + str(self.LAST_DATE) + ":1"
                        self.CORRELATED_ACCESS_MISMATCH = True
                else:
                    if ((int(self.INSERT_YEAR)) != (int(self.LAST_YEAR)) and (Column_Name != "Day1") and (self.TOTAL_ACCESSES_COUNT > "2") and (not self.BAD_YEAR_DETECTOR)):
                        self.BAD_YEAR_DETECTOR = True
                        return "**** WARNING: Multiple years detected, correlated \"DatesAndAccesses\" may not be accurate **** "
                    # Checking to see if the hour is 23 and day is 31. The day should be 1, however, time skew can happen, and we are accounting for that here
                    if ((Column_Name == "Day1") and (int(self.INSERT_HOUR) == 23) and (int(self.INSERT_DAY) == 31)):
                        properINSERT_YEAR = (int(self.INSERT_YEAR) + 1)  # Adding one to the year to make it right, and avoiding adding a variable to itself
                        self.INSERT_YEAR = properINSERT_YEAR
                    testingd = datetime.datetime.strptime(f'{juliandate} {self.INSERT_YEAR}', '%j %Y')
                    fullconvjd = testingd.strftime("%Y-%m-%d")
                    return f'{str(fullconvjd)}: {str(value)}, '
            elif (value is not None):
                return f'{str(Column_Name)} {str(value)}, '
            else:
                return ""
