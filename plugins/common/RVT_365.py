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
        Office 365 Audit Logs original CSV output contains a json format field `AuditData`.
        Parse regular fields and `AuditData` field and yield the results
    """

    def run(self, path=None):
        self.check_params(path, check_path=True, check_path_exists=True)

        for row in self.from_module.run(path):
            data = {}

            # Commmon fields
            common_fields = ['RecordType', 'Identity', 'IsValid', 'ObjectState']
            for field in common_fields:
                data[field] = row[field]

            # Audit Data regular fields
            audit_data = json.loads(row['AuditData'])
            ad_fields = ['CreationTime', 'UserId', 'Operation', 'ClientIP', 'LogonError', 'ObjectId', 'ResultStatus', 'UserKey']
            for field in ad_fields:
                data[field] = audit_data.get(field,"")
            data['ClientIP'] = data['ClientIP'].lstrip('::ffff:')
            data["ModifiedProperties"] = ""

            # Fields on RecordType=AzureActiveDirectoryStsLogon
            device_properties = ['SessionId', 'OS', 'BrowserType']
            for selected_prop in device_properties:
                data[selected_prop] = ""
                if "DeviceProperties" in audit_data:
                    for dev_property in audit_data["DeviceProperties"]:
                        if dev_property["Name"] == selected_prop:
                            data[selected_prop] = dev_property["Value"]

            ext_properties = ['UserAgent', 'RequestType']
            for selected_prop in ext_properties:
                data[selected_prop] = ""
                if "ExtendedProperties" in audit_data:
                    for ext_property in audit_data["ExtendedProperties"]:
                        if ext_property["Name"] == selected_prop:
                            data[selected_prop] = ext_property["Value"]
 
            # Fields on RecordType=ExchangeItem and RecordType=ExchangeItemGroup
            data["Subject"] = ""
            data["InternetMessageId"] = ""
            data["ParentPath"] = ""
            data["SizeInBytes"] = 0
            data['MailboxOwnerUPN'] = audit_data.get('MailboxOwnerUPN', "")
            data['ClientInfoString'] = audit_data.get('ClientInfoString', "")
            if data['RecordType'] == 'ExchangeItem':
                data["ModifiedProperties"] = str(audit_data.get("ModifiedProperties",""))
            for a_field in ["Item", "AffectedItems"]:
                if a_field in audit_data:
                    if isinstance(audit_data[a_field],list):
                        audit_data[a_field] = audit_data[a_field][0]
                    for field in ["Subject", "InternetMessageId", "SizeInBytes"]:
                        data[field] = audit_data[a_field].get(field, "")
                    if "ParentFolder" in audit_data[a_field]:
                        data["ParentPath"] = audit_data[a_field]["ParentFolder"].get("Path","")

            # data['Client'] = ""
            # if 'ClientInfoString' in audit_data:
            #     components = audit_data['ClientInfoString'].split(';')
            #     data['Client'] = components[0].split('=')[1]
            #     if components[1:] and not (components[1].startswith('Client') or components[1].startswith('Service')):
            #         data['UserAgent'] = ';'.join(components[1:])

            # fields on RecordType=AzureActiveDirectory
            if data['RecordType'] == 'AzureActiveDirectory':
                data["ModifiedProperties"] = str(audit_data.get("ModifiedProperties",""))

            # fields on RecordType=MicrosoftTeams
            teams_fields = ['CommunicationType', 'ChatName', 'ItemName']
            for field in teams_fields:
                data[field] = audit_data.get(field,"")

            # fields on RecordType=SharePoint
            sharepoint_fields = ['ApplicationId', 'ApplicationDisplayName', 'CorrelationId', 'ItemType']
            for share_field in sharepoint_fields:
                data[share_field] = audit_data.get(share_field, "")

            # fields on RecordType=ExchangeAdmin
            data["Parameters"] = str(audit_data.get("Parameters",""))

            yield data




