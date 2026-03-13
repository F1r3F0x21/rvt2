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


import base.job
import os
import re
import csv
import datetime
import xmltodict
import ujson as json
import shutil
import pyodbc
import time
from base.docker import Docker
from base.utils import check_directory


def copy_by_extension(init_path, dest_path, extension):
    n = 0
    for fname in os.listdir(init_path):
        if fname.endswith(f'.{extension}'):
            shutil.copy2(os.path.join(init_path, fname), dest_path)
            n += 1
    return n


def clear_data_folder(path):
    for fname in os.listdir(path):
        os.remove(os.path.join(path, fname))


class MSSQL(base.job.BaseModule):
    """ Parse trc and xel log files """

    def run(self, path=""):
        if not os.path.isdir(path):
            raise base.job.RVTError(f'Provided path {path} is not a directory')

        self.outdir = self.myconfig('outdir')
        self.analysisdir = self.myconfig('analysisdb')
        check_directory(self.outdir, create=True)
        check_directory(self.analysisdir, create=True)

        self.docker_compose_path = os.path.join(self.myconfig("docker_containers_dir"), self.myconfig('container'), 'docker-compose.yml')
        self.docker_project_name = self.config.config['MSServer_docker']['PROJECT']
        self.data_folder = os.path.join(os.path.dirname(self.docker_compose_path), 'traces')

        try:
            self.docker = Docker(compose_file=self.docker_compose_path, project_name=self.docker_project_name)
        except Exception:
            self.logger().error(f'{self.docker_compose_path} not exists')
            return []

        srch = re.compile(r'mnt/([^/]+)/Program Files/Microsoft SQL Server/([^/]+)/')
        aux = srch.search(path)
        self.partition = aux.group(1)
        self.version = aux.group(2)

        # copy files to parse
        ntrc = copy_by_extension(path, self.data_folder, 'trc')
        nxel = copy_by_extension(path, self.data_folder, 'xel')

        if ntrc + nxel == 0:
            self.logger().debug("There are not trc or xel files to parse")
            return []

        if not self.docker.is_running():
            self.docker.up()
            self.logger().warning('mssqlserver docker is starting. It will take some minutes')
            time.sleep(50)

        self.connect_db()
        try:
            self.parse_xel(os.path.join(self.outdir, f"xel.json"))
        except Exception:
            self.logger().error(f"Problems parsing xel files from {self.version}")
        try:
            self.parse_trc(self._get_base_trc())
        except Exception:
            self.logger().error(f"Problems parsing trc files from {self.version}")
        self.disconnect_db()
        clear_data_folder(self.data_folder)
        return []

    def connect_db(self):
        """
        Connects with MSSQL Server database
        """

        CONN_STR = ("DRIVER={ODBC Driver 18 for SQL Server};"
                    f"SERVER={self.config.config['MSServer_docker']['MSSERVER']};"
                    f"DATABASE={self.config.config['MSServer_docker']['MSDATABASE']};"
                    f"UID={self.config.config['MSServer_docker']['MSUSERNAME']};"
                    f"PWD={self.config.config['MSServer_docker']['MSPASSWORD']};"
                    "Encrypt=yes;"
                    "TrustServerCertificate=yes;"
                    "Connection Timeout=20;")
        self.conn = pyodbc.connect(CONN_STR)

    def disconnect_db(self):
        """
        Disconnects from MSSQL Server database
        """
        self.conn.close()

    def parse_xel(self, outfile):

        self.cursor = self.conn.cursor()
        container_path = '/traces'
        file_pattern = container_path + "/*.xel"

        self.logger().info(f"Processing {file_pattern}")

        query = """ SELECT object_name, event_data,file_name,file_offset,timestamp_utc FROM sys.fn_xe_file_target_read_file(?, NULL, NULL, NULL);"""
        self.cursor.execute(query, file_pattern)

        with open(outfile, "w") as f:
            for row in self.cursor:
                data = {'timestamp': row[4].strftime("%Y-%m-%dT%H:%M:%S.%f"), 'object_name': row[0], 'file_offset': row[3]}
                text = xmltodict.parse(row[1])
                data['package'] = text['event']['@package']
                for d in text['event']['data']:
                    data[d['@name']] = d['value']
                data['file_name'] = row[2]
                data['version'] = self.version
                data['partition'] = self.partition
                f.write(f'{json.dumps(data)}\n')

        self.logger().info(f"Export finished")
        self.cursor.close()

    def _get_base_trc(self):
        regex = re.compile(r'([^_]+).*\.trc')
        for fname in os.listdir(self.data_folder):
            aux = regex.search(fname)
            if aux:
                return f"/traces/{aux.group(1)}.trc"

    def parse_trc(self, outfile, container_path='/traces/log.trc'):
        self.cursor = self.conn.cursor()

        self.logger().info(f"Processing {container_path}")

        # Dump de todo
        query1 = """
                SELECT
                    t.StartTime, t.EndTime, t.EventClass, t.EventSubclass, e.name AS EventName, sc.subclass_name AS EventSubclassName,
                    t.TextData, t.Duration, t.CPU, t.Reads, t.Writes, t.RowCounts, t.LoginName, t.SessionLoginName, t.NTUserName, t.NTDomainName,
                    t.HostName, t.ApplicationName, t.SPID, t.DatabaseName, t.DatabaseID, t.ObjectName, t.ObjectID, t.ObjectType, t.TransactionID,
                    t.Error, t.Severity, t.State, t.FileName, t.ClientProcessID, t.ServerName, t.DBUserName, t.TargetUserName, t.LoginSid,
                    t.TargetLoginName, t.TargetLoginSid, t.BinaryData
                FROM fn_trace_gettable(?, DEFAULT) AS t
                LEFT JOIN sys.trace_events AS e
                    ON t.EventClass = e.trace_event_id
                LEFT JOIN sys.trace_subclass_values AS sc
                    ON t.EventClass = sc.trace_event_id
                    AND t.EventSubclass = sc.subclass_value;"""

        # Detectar ejecución de comandos peligrosos, manipulación de datos o modificaciones de usuario
        query2 = """
                SELECT
                    StartTime, SPID, SessionLoginName, LoginName, HostName, ApplicationName, DatabaseName, ObjectName, TextData
                FROM fn_trace_gettable(?, DEFAULT)
                WHERE TextData LIKE '%xp_cmdshell%'
                   OR TextData LIKE '%sp_oacreate%'
                   OR TextData LIKE '%xp_regread%'
                   OR TextData LIKE '%xp_regwrite%'
                   OR TextData LIKE '%xp_dirtree%'
                   OR TextData LIKE '%OPENROWSET%'
                   OR TextData LIKE '%OPENDATASOURCE%'
                   OR TextData LIKE '%CREATE LOGIN%'
                   OR TextData LIKE '%ALTER LOGIN%'
                   OR TextData LIKE '%CREATE USER%'
                   OR TextData LIKE '%ALTER USER%'
                   OR TextData LIKE '%sp_addlogin%'
                   OR TextData LIKE '%DROP TABLE%'
                   OR TextData LIKE '%DROP DATABASE%'
                   OR TextData LIKE '%TRUNCATE TABLE%'
                   OR TextData LIKE '%ALTER TABLE%'
                ORDER BY StartTime;"""

        # Busca consultas que leen muchos datos para posible exfiltación de datos
        query3 = """
                SELECT
                    StartTime, SPID, SessionLoginName, DatabaseName, Reads, Writes, RowCounts, Duration, TextData
                FROM fn_trace_gettable(?, DEFAULT)
                WHERE Reads > 100000
                   OR RowCounts > 100000
                ORDER BY Reads DESC;"""

        # Detecta intentos de login fallidos
        query4 = """
                SELECT
                    StartTime, NTUserName, LoginName, HostName, ApplicationName, TextData
                FROM fn_trace_gettable(?, DEFAULT)
                WHERE EventClass = 20
                ORDER BY StartTime;"""
        query5 = """
                SELECT
                    StartTime,
                    LoginName,
                    NTUserName,
                    HostName,
                    ApplicationName,
                    ClientProcessID,
                    TextData
                FROM fn_trace_gettable(?, DEFAULT)
                WHERE EventClass IN (14, 15)  -- 14=Audit Login, 15=Audit Logout
                ORDER BY StartTime DESC;"""

        query_dict = {
            os.path.join(self.outdir, "trc.csv"): query1,
            os.path.join(self.analysisdir, "trc_suspicious.csv"): query2,
            os.path.join(self.analysisdir, "trc_exfil.csv"): query3,
            os.path.join(self.analysisdir, "trc_logon_failed.csv"): query4,
            os.path.join(self.analysisdir, "trc_logon_success.csv"): query5
        }

        for fname, q in query_dict.items():
            self.cursor.execute(q, container_path)
            columns = [col[0] for col in self.cursor.description]
            columns += ["partition", "version"]
            headers = False
            if not os.path.exists(fname):
                headers = True

            with open(fname, "a", newline="") as f:
                writer = csv.writer(f, delimiter=';')
                if headers:
                    writer.writerow(columns)

                for row in self.cursor:
                    writer.writerow((*row, self.partition, self.version))

        self.logger().info(f"Export finished")
        self.cursor.close()
