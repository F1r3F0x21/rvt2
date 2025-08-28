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

import ujson as json
import dateutil.parser
import base.job
from base.utils import sanitize_ip, detect_encoding

class Parse_Audit_Logs(base.job.BaseModule):
    """ 
        Office 365 Audit Logs original CSV output contains a json format field `AuditData`.
        Parse regular fields and `AuditData` field and yield the results
    """

    def run(self, path=None):
        self.check_params(path, check_path=True, check_path_exists=True)

        exchange_admin_fields = {
            "Identity": "Identity",
            "Trustee": "User",
            "User": "User",
            "AccessRights": "AccessRights",
            "InheritanceType": "InheritanceType",
            "DisplayName": "DisplayName",
            "Name": "Name",
            "PrimarySmtpAddress": "PrimarySmtpAddress",
            "Enabled": "Enabled",
            "FromAddressContainsWords": "From",
            "From": "From",
            "SubjectOrBodyContainsWords": "SubjectOrBodyContainsWords",
            "SubjectContainsWords": "SubjectOrBodyContainsWords",
            "BodyContainsWords": "SubjectOrBodyContainsWords",
            "HeaderContainsWords": "SubjectOrBodyContainsWords",
            "RecipientAddressContainsWords": "SentTo",
            "SentTo": "SentTo",
            "MoveToFolder": "MoveToFolder",
            "MarkAsRead": "MarkAsRead",
            "TrustedSendersAndDomain": "TrustedSenders",
            "BlockedSendersAndDomains": "BlockedSenders",
            "TrustedRecipientsAndDomains": "TrustedRecipients",
            "BlockedRecipientsAndDomains": "BlockedRecipients",
            "ForwardTo": "ForwardTo",
            "RedirectTo": "ForwardTo",
            "ForwardAsAttachmentTo": "ForwardTo",
            "DeleteMessage": "DeleteMessage"
        }

        sharepoint_fields = ['ApplicationDisplayName', 'ClientAppName', 'ItemType', 'ListName', 'TargetUserOrGroupName',
                    'AuthenticationType', 'DeviceDisplayName', 'SourceFileExtension', 'UserAgent']

        # RecordType list: https://learn.microsoft.com/en-us/office/office-365-management-api/office-365-management-activity-api-schema
        yield_event = True
        for row in self.from_module.run(path):
            data = {
                # General Fields
                "CreationTime": "",
                "RecordType": "",
                "Operation": "",
                "UserId": "",
                "Identity": "",
                "IsValid": "",
                "ObjectState": "",
                # Common Audit Data
                "Workload": "",
                "SessionId": "",
                "ClientIP": "",
                "UserAgent": "",
                "ObjectId": "",
                "ResultStatus": "",
                "UserKey": "",
                "UserType": "",
                "AppId": "",  # TODO: lookup table based on https://learn.microsoft.com/en-us/troubleshoot/entra/entra-id/governance/verify-first-party-apps-sign-in
                "APIId": "",
                "ClientAppId": "",
                "MailboxOwnerUPN": "",
                "MailboxGuid": "",
                "MailboxOwnerSid": "",
                "ExternalAccess": "",
                "LogonType": "",
                "OrganizationId": "",
                "OrganizationName": "",
                # RecordType = AzureActiveDirectoryStsLogon (15)
                "OS": "",
                "Browser": "",
                "RequestType": "",
                "LogonError": "",
                "ErrorNumber": "",
                # RecordType = ExchangeItem (2) and ExchangeItemGroup (3) and ExchangeItemAggregated (50)
                "Subject": "",
                "InternetMessageId": "",
                "ParentPath": "",
                "SizeInBytes": "",
                "Attachments": "",
                "CrossMailboxOperation": "",
                "MailAccessType": "",
                "OperationCount": "",
                # RecordType = ExchangeAdmin (1)
                "AccessRights": "",
                "InheritanceType": "",
                "User": "", # TargetUser
                "DisplayName": "",
                "Name": "",
                "PrimarySmtpAddress": "",
                "Enabled": "",
                "From": "",
                "SentTo": "",
                "SubjectOrBodyContainsWords": "",
                "MoveToFolder": "",
                "MarkAsRead": "",
                "ForwardTo": "",
                "DeleteMessage": "",
                "TrustedSenders": "",
                "BlockedSenders": "",
                "TrustedRecipients": "",
                "BlockedRecipients": "",
                "RequestId": "",
                # RecordType = SharePoint (4) and SharePointFileOperation (6) and OneDrive (7) and SharePointSharingOperation (14)
                "ApplicationDisplayName": "",
                "ClientAppName": "",
                "AuthenticationType": "",
                "ItemType": "",
                "DeviceDisplayName": "",
                "SourceFileExtension": "",
                "CorrelationId": "",
                "ListName": "",
                "TargetUserOrGroupName": "",
                # RecordType = MicrosoftTeams (25)
                "CommunicationType": "",
                "ChatName": "",
                "ItemName": "",
                # RecordType = MailSubmission (29)
                "SenderIP": "",
                # RecordType = AzureActiveDirectory (8)
                "ModifiedProperties": "",
                # RecordType = FileSyncDataTransfer / Defender (63)
                "RemovableMedia": "",
                "Sha256": "",
                "PreviousFileName": "",
                "TargetFilePath": "",
            }

            # General fields
            common_fields = ["CreationTime", "RecordType", "Operation", "UserId", "Identity", "IsValid", "ObjectState"]
            for field in common_fields:
                data[field] = row.get(field, '')

            # Audit Data
            try:
                if 'AuditData' in row:
                    audit_data = json.loads(row['AuditData'])
                elif 'auditData' in row:
                    audit_data = json.loads(row['auditData'])
                    #audit_data = row['auditData']
            except:
                data['CreationTime'] = dateutil.parser.parse(row['CreationDate']).isoformat()
                data['Operation'] = row['Operations']
                data['UserId'] = row['UserIds']
                self.logger().warning(f'AuditData in wrong format for RecordType {data["RecordType"]} at {data["CreationTime"]}')
                yield data
                continue

            # Audit Data common fields
            # Check if not in general fields
            for field in ['CreationTime', 'UserId', 'Operation', 'RecordType']:
                if not data[field]:
                    data[field] = str(audit_data.get(field,""))
            # ad_fields = ['CreationTime', 'UserId', 'Operation', 'ClientIP', 'LogonError', 'ObjectId', 'ResultStatus', 'UserKey', 'SessionID']
            ad_fields = ["Workload", "SessionId", "ObjectId", "ResultStatus", "UserKey", "UserType", "LogonType",
                         "MailboxOwnerUPN", "MailboxGuid", "MailboxOwnerSid", "ExternalAccess", "OrganizationId", "OrganizationName"]
            for field in ad_fields:
                data[field] = audit_data.get(field, "")
            app_context_fields = ["AppId", "ClientAppId", "CorrelationId"]
            for field in app_context_fields:
                data[field] = audit_data.get("AppAccessContext", {}).get(field, "")
            if not data['SessionId']:
                data['SessionId'] = audit_data.get("AppAccessContext", {}).get("AADSessionId", "")

            # IP and user agent
            ip = audit_data.get('ClientIP', audit_data.get('ClientIPAddress', ''))
            sanitized_ip, _ = sanitize_ip(ip.lstrip('::ffff:'))
            data['ClientIP'] = sanitized_ip or ip
            data['UserAgent'] = audit_data.get('ClientInfoString', audit_data.get('UserAgent'))

            # Fields on RecordType=AzureActiveDirectoryStsLogon
            if data['RecordType'] in ('15', 'AzureActiveDirectoryStsLogon'):
                data['LogonError'] = audit_data.get('LogonError')
                data['ErrorNumber'] = audit_data.get('ErrorNumber')
                data['AppId'] = audit_data.get('ApplicationId')
                ext_properties = ['UserAgent', 'RequestType']
                for selected_prop in ext_properties:
                    for ext_property in audit_data.get("ExtendedProperties", []):
                        if ext_property["Name"] == selected_prop:
                            data[selected_prop] = ext_property["Value"]
                device_properties = zip(['SessionId', 'OS', 'BrowserType'],['SessionId', 'OS', 'Browser'])
                for selected_prop, translated_prop in device_properties:
                    for dev_property in audit_data.get("DeviceProperties", []):
                        if dev_property["Name"] == selected_prop:
                            data[translated_prop] = dev_property["Value"]

            # Fields on RecordType=ExchangeItem and RecordType=ExchangeItemGroup
            if data['RecordType'] in ('2', 'ExchangeItem', '3', 'ExchangeItemGroup', '50', 'ExchangeItemAggregated'):
                data["ModifiedProperties"] = str(audit_data.get("ModifiedProperties",""))
                data['OrganizationId'] = audit_data.get('OrganizationId')
                data['OperationCount'] = audit_data.get('OperationCount')
                data['CrossMailboxOperation'] = audit_data.get('CrossMailboxOperation')
                # data['Path'] = audit_data.get('Folder', {}).get('Path')   # Always the same as ParentFolder
                for op_property in audit_data.get('OperationProperties', []):
                    if op_property.get("Name") == "MailAccessType":
                        data['MailAccessType'] = op_property.get("Value")

                if "Item" in audit_data:
                    for field in ["Subject", "InternetMessageId", "SizeInBytes", "Attachments"]:
                        data[field] = audit_data["Item"].get(field, "")
                        data["ParentPath"] = audit_data["Item"].get("ParentFolder", {}).get("Path", "")

                # Yield a new event for each item
                # WARNING: Make sure no more transformations are expected after this point
                if "AffectedItems" in audit_data:
                    for affected_item in audit_data["AffectedItems"]:
                        for field in ["Subject", "InternetMessageId", "SizeInBytes", "Attachments"]:
                            data[field] = affected_item.get(field, "")
                            data["ParentPath"] = affected_item.get("ParentFolder", {}).get("Path", "")
                        yield data
                        yield_event = False  # Don't yield again the last item

                # Yield a new event for each item
                if data['Operation'] == 'MailItemsAccessed':
                    for folder in audit_data.get("Folders", []):
                        data["ParentPath"] = folder.get("Path", "")
                        for folder_item in folder.get('FolderItems', []):
                            for field in ["InternetMessageId", "SizeInBytes"]:
                                data[field] = folder_item.get(field, "")
                            yield data
                            yield_event = False

            # fields on RecordType=MicrosoftTeams
            if data['RecordType'] in ('25', 'MicrosoftTeams'):
                teams_fields = ['CommunicationType', 'ChatName', 'ItemName']
                for field in teams_fields:
                    data[field] = audit_data.get(field,"")
                for ext_property in audit_data.get("ExtendedProperties", []):
                    if ext_property.get("Name") == "OsName":
                        data['OS'] = ext_property.get("Value")

            # fields on RecordType=SharePoint
            if data['RecordType'] in ('4', 'SharePoint', '6', 'SharePointFileOperation', '7', 'OneDrive', '14', 'SharePointSharingOperation', '36', 'SharePointListOperation'):
                for share_field in sharepoint_fields:
                    data[share_field] = audit_data.get(share_field, "")
                data['AppId'] = audit_data.get('ApplicationId')
                data['OS'] = audit_data.get('Platform')
                data['Browser'] = audit_data.get('BrowserName')
                data['SizeInBytes'] = audit_data.get('FileSizeBytes')

            # fields on RecordType=ExchangeAdmin
            if data['RecordType'] in ('1', 'ExchangeItem'):
                # Join similar fields to simplify output
                for input_param, output_param in exchange_admin_fields.items():
                    for parameters in audit_data.get("Parameters", []):
                        if parameters.get("Name") == input_param:
                            if not data[output_param]:
                                data[output_param] = parameters.get("Value")
                            else:
                                data[output_param] += ', ' + parameters.get("Value")
                data['RequestId'] = audit_data.get('RequestId')

            # fields on RecordType=AzureActiveDirectory
            if data['RecordType'] in ['8', 'AzureActiveDirectory']:
                # Get only the fields modified, not the details, since they are in json format
                for mdf_property in audit_data.get("ModifiedProperties", [{}]):
                    if not data["ModifiedProperties"]:
                        data["ModifiedProperties"] = mdf_property.get('Name')
                    else:
                        data["ModifiedProperties"] += ', ' + mdf_property.get('Name')
                for target in audit_data.get('Target', [{}]):
                    if str(target.get('Type')) == "1":  # Application
                        data['ApplicationDisplayName'] = target.get('ID')

            # fields on RecordType=MailSubmission
            if data['RecordType'] in ['29', 'MailSubmission']:
                data['InternetMessageId'] = audit_data.get('InternetMessageId')
                data['Subject'] = audit_data.get('Subject')
                data['From'] = audit_data.get('P1Sender')
                data['SenderIP'] = audit_data.get('SenderIP')

            # fields on RecordType=ThreatIntelligenceUrl
            if data['RecordType'] in ['41', 'ThreatIntelligenceUrl']:
                data['ObjectId'] = audit_data.get('EventDeepLink')
                data['Attachments'] = audit_data.get('Url')

            # fields on RecordType=FileSyncDataTransfer
            if data['RecordType'] in ['63', 'FileSyncDataTransfer']:
                data['DeviceDisplayName'] = audit_data.get('DeviceName')
                data['ApplicationDisplayName'] = audit_data.get('Application')
                data['RemovableMedia'] = audit_data.get('RemovableMediaDeviceAttributes')
                data['SourceFileExtension'] = audit_data.get('FileExtension')
                data['SizeInBytes'] = audit_data.get('FileSize')
                data['Sha256'] = audit_data.get('Sha256')
                data['PreviousFileName'] = audit_data.get('PreviousFileName')
                data['TargetFilePath'] = audit_data.get('TargetFilePath')
                if not data['TargetFilePath']:
                    data['TargetFilePath'] = audit_data.get('TargetUrl')
                if not data['TargetFilePath']:
                    data['TargetFilePath'] = audit_data.get('TargetPrinterName')

            if yield_event:
                yield data
            else:
                yield_event = True


class Parse_SignInLogs(base.job.BaseModule):
    """
        Parse Microsoft Entra SignInLogs.
    """

    def read_config(self):
        super().read_config()
        self.set_default_config('signin_type', '')

    def run(self, path=None):
        self.check_params(path, check_path=True, check_path_exists=True)

        self.coalesce_fields = [
            {'fields': ["createdDateTime","Date (UTC)","CreatedDateTime","Fecha (UTC)"], 'new_field': 'Date'},
            {'fields': ["userId","User ID","UserID","Id. de usuario"], 'new_field': 'UserID'},
            {'fields': ["userDisplayName","User","UserDisplayName","Usuario"], 'new_field': 'User'},
            {'fields': ["userPrincipalName","Username","UserPrincipalName","Nombre de usuario"], 'new_field': 'Username'},
            {'fields': ["userType","User type","UserType","Tipo de usuario"], 'new_field': 'UserType'},
            {'fields': ["ipAddress","IP address","IpAddress","Dirección IP"], 'new_field': 'ClientIp'},
            {'fields': ["location","Location","Ubicación"], 'new_field': 'Location'},
            {'fields': ["autonomousSystemNumber","Autonomous system  number","Autonomous system number","AutonomousSystemNumber","Número de sistema autónomo"], 'new_field': 'ASN'},
            {'fields': ["operatingSystem","Operating System","OperatingSystem","Sistema operativo"], 'new_field': 'OS'},
            {'fields': ["browser","Browser","Explorador"], 'new_field': 'Browser'},
            {'fields': ["userAgent","User agent","UserAgent"], 'new_field': 'UserAgent'},
            {'fields': ["clientAppUsed","Client App","ClientAppUsed","Aplicación cliente"], 'new_field': 'ClientApp'},
            {'fields': ["deviceID","Device ID","DeviceID"], 'new_field': 'DeviceID'},
            {'fields': ["sessionId","Session ID","SessionID","Correlation ID","CorrelationId","Id. de correlación"], 'new_field': 'SessionID'},
            {'fields': ["status","Status","Estado"], 'new_field': 'Status'},
            {'fields': ["clientCredentialType","Client credential type","ClientCredentialType","Tipo de credencial de cliente"], 'new_field': 'ClientCredentialType'},
            {'fields': ["authenticationProtocol","Authentication Protocol","AuthenticationProtocol","Protocolo de autenticación"], 'new_field': 'AuthProtocol'},
            {'fields': ["authenticationRequirement","Authentication requirement","AuthenticationRequirement","Requisito de autenticación"], 'new_field': 'AuthRequirement'},
            {'fields': ["multifactorAuthenticationResult","Multifactor authentication result","MultifactorAuthenticationResult"], 'new_field': 'MFAResult'},
            #{'fields': ["Multifactor authentication auth method","MultifactorAuthenticationAuthMethod"], 'new_field': 'MFAMethod'},
            {'fields': ["failureReason","Failure reason","FailureReason","Motivo del error"], 'new_field': 'FailureReason'},
            {'fields': ["appDisplayName","Application","AppDisplayName","Aplicación"], 'new_field': 'Application'},
            {'fields': ["resourceDisplayName","Resource","ResourceDisplayName","Recurso"], 'new_field': 'Resource'},
            {'fields': ["signInSessionStatusCode","Token Protection - Sign In Session StatusCode","TokenProtection-SignInSessionStatusCode"], 'new_field': 'TokenStatusCode'},
            {'fields': ["conditionalAccessStatus","Conditional Access","ConditionalAccessStatus"], 'new_field': 'ConditionalAccessStatus'}
        ]

        self.flatten_fields = [
            {'fields': ["status", "errorCode"], 'new_field': 'statusErrorCode'},
            {'fields': ["status", "failureReason"], 'new_field': 'failureReason'},
            {'fields': ["status", "additionalDetails"], 'new_field': 'multifactorAuthenticationResult'},
            {'fields': ["location", "city"], 'new_field': 'city'},
            {'fields': ["location", "state"], 'new_field': 'state'},
            {'fields': ["location", "countryOrRegion"], 'new_field': 'countryOrRegion'},
            {'fields': ["deviceDetail", "deviceId"], 'new_field': 'deviceID'},
            {'fields': ["deviceDetail", "displayName"], 'new_field': 'deviceDisplayName'},
            {'fields': ["deviceDetail", "operatingSystem"], 'new_field': 'operatingSystem'},
            {'fields': ["deviceDetail", "browser"], 'new_field': 'browser'},
            {'fields': ["tokenProtectionStatusDetails", "signInSessionStatusCode"], 'new_field': 'signInSessionStatusCode'},
        ]

        is_json = False
        if path.lower().endswith('json'):
            is_json = True

        signin_type = self.myconfig('signin_type')
        if not is_json:
            for line in base.job.run_job(self.config, 'base.input.CSVReader', path=path, extra_config={'delimiter': ',', 'encoding': 'utf-8-sig'}):
                result = self.coalesce(line)
                if signin_type == 'interactive':
                    result['IsInteractive'] = 'true'
                elif signin_type == 'noninteractive':
                    result['IsInteractive'] = 'false'
                else:
                    result['IsInteractive'] = 'unknown'
                yield result
        else:
            for line in base.job.run_job(self.config, 'base.input.JSONReader', path=path):
                result = self.flatten(line)
                result['location'] = result['city'] + ', ' + result['state'] + ', ' + result['countryOrRegion']
                result['status'] = 'Success' if not result.get('statusErrorCode', "") else 'Failure'
                result['IsInteractive'] = result.get('isInteractive', 'unknown')
                result = self.coalesce(result)
                yield result

    def coalesce(self, data):
        default = ""
        for substitutions in self.coalesce_fields:
            fields_to_remove = set(substitutions['fields']) - set([substitutions['new_field']])
            non_empty_values = [data.get(k, default) for k in substitutions['fields'] if data.get(k, None)]
            data[substitutions['new_field']] = default if not non_empty_values else non_empty_values[0]
            [data.pop(i, None) for i in fields_to_remove]
        return data

    def flatten(self, data):
        default = ""
        for sub in self.flatten_fields:
            main_key = sub['fields'][0]
            sub_key = sub['fields'][1]
            if main_key in data and isinstance(data[main_key], dict):
                data[sub['new_field']] = data[main_key].get(sub_key, default)
            else:
                data[sub['new_field']] = default
        return data


class Parse_AzureAD_AuditLogs(base.job.BaseModule):
    """
        Parse AzureAD Audit Logs.
    """

    def run(self, path=None):
        self.check_params(path, check_path=True, check_path_exists=True)

        self.coalesce_fields = [
            {'fields': ["activityDateTime","ActivityDateTime","Date (UTC)","Fecha (UTC)"], 'new_field': 'Date'},
            {'fields': ["CorrelationId","correlationId"], 'new_field': 'CorrelationId'},
            {'fields': ["category","Category","Categoría"], 'new_field': 'Category'},
            {'fields': ["result","Result","Resultado"], 'new_field': 'Result'},
            {'fields': ["resultReason","ResultReason"], 'new_field': 'ResultReason'},
            {'fields': ["loggedByService","LoggedByService","Service","Servicio"], 'new_field': 'LoggedByService'},
            {'fields': ["activityDisplayName","ActivityDisplayName","Activity","Actividad"], 'new_field': 'Activity'},
            {'fields': ["ActorName","ActorUserPrincipalName"], 'new_field': 'ActorName'},
            {'fields': ["IpAddress","IPAddress"], 'new_field': 'IpAddress'},
            {'fields': ["TargetType","Target1Type"], 'new_field': 'TargetType'},
            {'fields': ["TargetName","Target1DisplayName"], 'new_field': 'TargetName'},
            {'fields': ["TargetUPN","Target1UserPrincipalName","Objetivo1NombrePrincipalDeUsuario"], 'new_field': 'TargetUPN'},
            {'fields': ["TargetModifiedPropertyName","Target1ModifiedProperty1Name"], 'new_field': 'TargetModifiedProperty'},
            {'fields': ["UserAgent","User Agent","Agente de usuario"], 'new_field': 'UserAgent'}
        ]

        is_json = False
        if path.lower().endswith('json'):
            is_json = True

        if not is_json:
            for line in base.job.run_job(self.config, 'base.input.CSVReader', path=path, extra_config={'delimiter': ',', 'encoding': 'utf-8-sig'}):
                result = {}
                if "Target1ModifiedProperty1Name" in line:
                    result = {'ModifiedProperties': self.join_modifiedProperties(line)}
                result.update(self.coalesce(line))
                if not result.get('TargetModifiedProperty'):
                    result['TargetModifiedProperty'] = self.parse_modifiedProperties(line.get('ModifiedProperties'))
                if line.get('ActorType').startswith('Ap'):
                    result['ActorName'] = line.get('ActorDisplayName')
                result['TargetName'] = result.get('TargetName', result.get('TargetUPN'))
                yield result
        else:
            for line in base.job.run_job(self.config, 'base.input.JSONReader', path=path):
                line['UserAgent'] = self.get_user_agent(line)
                result = self.parse_initiatedBy(line)
                result = self.parse_targetResources(result)
                result = self.coalesce(result)
                yield result

    def coalesce(self, data):
        default = ""
        for substitutions in self.coalesce_fields:
            fields_to_remove = set(substitutions['fields']) - set([substitutions['new_field']])
            non_empty_values = [data.get(k, default) for k in substitutions['fields'] if data.get(k, None)]
            data[substitutions['new_field']] = default if not non_empty_values else non_empty_values[0]
            [data.pop(i, None) for i in fields_to_remove]
        return data

    def parse_initiatedBy(self, data):
        new_data = {
            'ActorType': '',
            'ActorUserPrincipalName': '',
            'IpAddress': ''
        }
        initiatedBy = data.get('initiatedBy')
        if not isinstance(initiatedBy, dict):
            data.update(new_data)
            return data
        if 'user' in initiatedBy and isinstance(initiatedBy['user'], dict):
            new_data['ActorType'] = 'User'
            new_data['ActorUserPrincipalName'] = initiatedBy['user'].get('userPrincipalName')
            new_data['IpAddress'] = initiatedBy['user'].get('ipAddress')
        if 'app' in initiatedBy and isinstance(initiatedBy['app'], dict):
            new_data['ActorType'] = 'Application'
            new_data['ActorUserPrincipalName'] = initiatedBy['app'].get('displayName')
        data.update(new_data)
        return data

    def parse_targetResources(self, data):
        new_data = {
            'TargetType': '',
            'TargetName': '',
            'TargetUPN': '',
            'ModifiedProperties': [],
            'TargetModifiedPropertyName': ''
        }
        targetResources = data.get('targetResources')
        if not isinstance(targetResources, list):
            data.update(new_data)
            return data
        for target in targetResources:
            new_data['TargetType'] = target.get('type')
            new_data['TargetName'] = target.get('displayName')
            new_data['TargetUPN'] = target.get('userPrincipalName')
            modifiedProperties = target.get('modifiedProperties')
            new_data['ModifiedProperties'] = str(modifiedProperties)
            new_data['TargetModifiedPropertyName'] = self.parse_modifiedProperties(modifiedProperties)
            if any([new_data['TargetType'], new_data['TargetName'], new_data['TargetUPN']]):
                break
        data.update(new_data)
        return data

    def parse_modifiedProperties(self, modifiedProperties):
        if not modifiedProperties:
            return ''
        if isinstance(modifiedProperties, list):
            return modifiedProperties[0].get('displayName')
        if isinstance(modifiedProperties, str):
            try:
                modifiedProperties = json.loads(modifiedProperties)
                return modifiedProperties[0].get('DisplayName')
            except Exception:
                return ''
        return ''

    def join_modifiedProperties(self, data):
        modifiedProperties = []
        for target_idx in range(1,3):
            for property_idx in range(1,5):
                prop_name = data.get(f'Target{target_idx}ModifiedProperty{property_idx}Name')
                if prop_name:
                    old_value = data.get(f'Target{target_idx}ModifiedProperty{property_idx}OldValue')
                    new_value = data.get(f'Target{target_idx}ModifiedProperty{property_idx}NewValue')
                    modifiedProperties.append({'displayName': prop_name, 'oldValue': old_value, 'newValue': new_value})
        return str(modifiedProperties)

    def get_user_agent(self, data):
        details = data.get('additionalDetails')
        for detail in details:
            if detail.get('key') == 'User-Agent':
                return detail.get('value')
        return ''


class Parse_MessageTrace(base.job.BaseModule):
    """
        Parse Message Trace Logs.
    """

    def run(self, path=None):
        self.check_params(path, check_path=True, check_path_exists=True)
        # MessageTrace from 365 portal is provided in 'utf-16-le' encoding
        # When extracted with PowerShell, the results are encoded in 'utf8'
        input_encoding = base.utils.detect_encoding(path)
        self.logger().info(f'Input encoding: {input_encoding}. File: {path}')

        self.coalesce_fields = [
            {'fields': ["date_time_utc", "origin_timestamp_utc", "Received"], 'new_field': 'Date'},
            {'fields': ["sender_address", "SenderAddress"], 'new_field': 'Sender'},
            {'fields': ["recipient_address", "RecipientAddress"], 'new_field': 'Recipient'},
            {'fields': ["recipient_status", "Status"], 'new_field': 'Status'},
            {'fields': ["message_subject", "Subject"], 'new_field': 'Subject'},
            {'fields': ["total_bytes", "Size"], 'new_field': 'TotalBytes'},
            {'fields': ["original_client_ip", "FromIP"], 'new_field': 'ClientIp'},
            {'fields': ["original_destination_ip", "ToIP"], 'new_field': 'DestinationIp'},
            {'fields': ["message_id", "MessageId"], 'new_field': 'MessageID'},
        ]

        for line in base.job.run_job(self.config, 'base.input.CSVReader', path=path, extra_config={'delimiter': ',', 'encoding': input_encoding}):
            result = self.coalesce(line)
            if input_encoding == 'utf_16_le':
                for recipient_status in self.parse_recipient_status(result):
                    result['Recipient'] = recipient_status[0]
                    result['Status'] = recipient_status[1]
                    yield result
            else:
                yield result

    def coalesce(self, data):
        default = ""
        for substitutions in self.coalesce_fields:
            fields_to_remove = set(substitutions['fields']) - set([substitutions['new_field']])
            non_empty_values = [data.get(k, default) for k in substitutions['fields'] if data.get(k, None)]
            data[substitutions['new_field']] = default if not non_empty_values else non_empty_values[0]
            [data.pop(i, None) for i in fields_to_remove]
        return data

    def parse_recipient_status(self, data):
        # Separates recipient email address from delivery status
        # Creates a new event for each recipient
        # Example input:
        # "email_name@email.com##Receive, Expand, Fail;email_name2@mail.com##Receive, Pending, Deliver"
        # Info on status on https://learn.microsoft.com/en-us/exchange/monitoring/trace-an-email-message/message-trace-modern-eac#detailed-search-options
        return [rs.split('##') for rs in data.get('Status').split(';')]
