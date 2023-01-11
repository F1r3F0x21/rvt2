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

import json
import base.job

class Parse_Audit_Logs(base.job.BaseModule):
    """ 
        Office 365 Audit Logs original CSV output contains a json format field.
        This job parses that field and yield the results
    """

    def run(self, path=None):
        self.check_params(path, check_path=True, check_path_exists=True)

        for row in self.from_module.run(path):
            data = {}
            audit_data = row['AuditData']
            audit_data = json.loads(audit_data)
            data["CreationTime"] = audit_data["CreationTime"]
            data["Operation"] = audit_data["Operation"]
            data["User"] = audit_data["UserId"]
            data["ClientIP"] = audit_data["ClientIP"] if "ClientIP" in audit_data else ""
            data["LogonError"] = audit_data["LogonError"] if "LogonError" in audit_data else ""
            data["ModifiedProperties"] = str(audit_data.get("ModifiedProperties",""))
            data["ObjectId"] = audit_data.get("ObjectId","")
            
            data["SessionId"] = ""
            if "DeviceProperties" in audit_data:
                for property in audit_data["DeviceProperties"]:
                    if property["Name"] == "SessionId":
                        data["SessionId"] = property["Value"]
                        break
            
            data["UserAgent"] = ""
            data["RequestType"] = ""
            if "ExtendedProperties" in audit_data:
                for property in audit_data["ExtendedProperties"]:
                    if property["Name"] == "UserAgent":
                        data["UserAgent"] = property["Value"]
                    if property["Name"] == "RequestType":
                        data["RequestType"] = property["Value"]
 
            data["Subject"] = ""
            data["InternetMessageId"] = ""
            data["ParentPath"] = ""
            for a_field in ["Item", "AffectedItems"]:
                if a_field in audit_data:
                    if isinstance(audit_data[a_field],list):
                        audit_data[a_field] = audit_data[a_field][0]
                    for field in ["Subject", "InternetMessageId"]:
                        data[field] = audit_data[a_field].get(field, "")
                    if "ParentFolder" in audit_data[a_field]:
                        data["ParentPath"] = audit_data[a_field]["ParentFolder"].get("Path","")

            yield data




