#!/usr/bin/python3

import requests
import gzip
import os
import time
import json
import datetime
import dateutil
from OTXv2 import OTXv2
import IndicatorTypes
import re

import base.job


def check_file_date(fdate, days):
    """ checks if date is older than X days"""

    if fdate is None or fdate == '-':
        return False

    if type(fdate) == datetime.datetime:
        fdate = fdate.replace(tzinfo=None)
    else:
        fdate = dateutil.parser.parse(fdate).replace(tzinfo=None)

    if (datetime.datetime.now() - fdate).days < days:
        return True
    return False


def check_db_date(filepath, hours=24):
    """ checks if file is older than X hours"""

    if os.path.isfile(filepath) and (time.time() - os.path.getmtime(filepath)) / 3600. < hours:
        return True
    return False


def check_private_ip(ip):
    """ Checks if an IP is internal """

    if ip.startswith('L') or ip.startswith('192.168') or ip.startswith("192.0.0") or ip.startswith('10.') or ip.startswith("169.254.") or ip.startswith('127.') or ip.find(':') > 0 or re.search(r'172\.(1[6-9]|2.|3[01])\.', ip):
        return True
    return False


def getValue(results, keys):
    # Get a nested key from a dict, without having to do loads of ifs
    # Get from https://github.com/AlienVault-OTX/OTX-Python-SDK/tree/master/examples/is_malicious
    if type(keys) is list and len(keys) > 0:

        if type(results) is dict:
            key = keys.pop(0)
            if key in results:
                return getValue(results[key], keys)
            else:
                return None
        else:
            if type(results) is list and len(results) > 0:
                return getValue(results[0], keys)
            else:
                return results
    else:
        return results


class phishtank(object):
    def __init__(self, db_file='phishtank_db.csv.gz'):
        self.url = 'http://data.phishtank.com/data/online-valid.csv.gz'
        self.db_file = db_file
        self.update_db()

    def update_db(self):
        if check_db_date(self.db_file):
            return
        print('Updating database file')
        try:
            r = requests.get(self.url)
            with open(self.db_file, 'wb') as db:
                db.write(r.content)
        except Exception:
            print('Problems updating database')

    def check_url(self, url):
        with gzip.open(self.db_file, 'r') as db:
            for line in db:
                line = line.decode()
                line = line.split(',')
                if url in line[1]:
                    return {'url': line[1],
                            'submit_time': line[2],
                            'target': line[7],
                            'is_malicious': True}
        return {'url': url,
                'is_malicious': False}


class tor_node(object):
    def __init__(self, db_file='tor_list.gz'):
        self.url = 'https://check.torproject.org/torbulkexitlist'
        self.db_file = db_file
        self.update_db()

    def update_db(self):
        if check_db_date(self.db_file):
            return
        print('Updating tor list file')
        try:
            r = requests.get(self.url)
            with gzip.open(self.db_file, 'wb') as db:
                db.write(r.content)
        except Exception:
            print('Problems updating database')

    def check_tor_ip(self, ip):
        with gzip.open(self.db_file, 'r') as db:
            for line in db:
                if ip == line.decode().rstrip():
                    return {'ip': ip,
                            'tor_exit_node': True}
        return {'ip': ip,
                'tor_exit_node': False}


class abuseipdb(object):
    def __init__(self, max_days=60):
        try:
            from . import api_keys
            self.key = api_keys.ABUSEIPDB
        except Exception:
            self.apikey = None
        self.url = 'https://api.abuseipdb.com/api/v2/check'
        self.max_days = max_days

    def get_ip_data(self, ip):

        querystring = {
            'ipAddress': ip,
            'maxAgeInDays': self.max_days
        }

        headers = {
            'Accept': 'application/json',
            'Key': self.key
        }

        response = requests.request(method='GET', url=self.url, headers=headers, params=querystring)

        # Formatted output
        ab = json.loads(response.text)
        data = {'CC': ab['data']['countryCode'],
                'abuseConfidenceScore': ab['data']['abuseConfidenceScore'],
                'isWhitelisted': ab['data']['isWhitelisted'],
                'usageType': ab['data']['usageType'],
                'isp': ab['data']['isp']}
        return data

    def check_ip(self, ip):
        data = self.get_ip_data(ip)
        return data['abuseConfidenceScore'] != '0'


class alienvault(object):
    # Class based on https://github.com/AlienVault-OTX/OTX-Python-SDK/tree/master/examples/is_malicious
    def __init__(self, otx_server='https://otx.alienvault.com/'):
        try:
            from . import api_keys
            self.apikey = api_keys.ALIENVAULT
        except Exception:
            self.apikey = None
        self.otx_server = otx_server
        self.otx = OTXv2(self.apikey, server=otx_server)

    def hostname(self, hostname):
        alerts = []
        result = self.otx.get_indicator_details_by_section(IndicatorTypes.HOSTNAME, hostname, 'general')

        # Return nothing if it's in the whitelist
        validation = getValue(result, ['validation'])
        if not validation:
            pulses = getValue(result, ['pulse_info', 'pulses'])
            if pulses:
                for pulse in pulses:
                    if 'name' in pulse:
                        alerts.append('In pulse: ' + pulse['name'])

        result = self.otx.get_indicator_details_by_section(IndicatorTypes.DOMAIN, hostname, 'general')
        # Return nothing if it's in the whitelist
        validation = getValue(result, ['validation'])
        if not validation:
            pulses = getValue(result, ['pulse_info', 'pulses'])
            if pulses:
                for pulse in pulses:
                    if 'name' in pulse:
                        alerts.append('In pulse: ' + pulse['name'])

        return alerts

    def ip(self, ip):
        res = {'alerts': []}
        result = self.otx.get_indicator_details_by_section(IndicatorTypes.IPv4, ip, 'general')
        res['city'] = result.get('city', '')
        res['country_name'] = result.get('country_name', '')
        res['asn'] = result.get('asn', '')

        # Return nothing if it's in the whitelist
        validation = getValue(result, ['validation'])
        if not validation:
            pulses = getValue(result, ['pulse_info', 'pulses'])
            if pulses:
                for pulse in pulses:
                    if 'name' in pulse:
                        res['alerts'].append('In pulse: ' + pulse['name'])

        return res

    def url(self, url):
        alerts = []
        result = self.otx.get_indicator_details_full(IndicatorTypes.URL, url)

        google = getValue(result, ['url_list', 'url_list', 'result', 'safebrowsing'])
        if google and 'response_code' in str(google):
            alerts.append({'google_safebrowsing': 'malicious'})

        clamav = getValue(result, ['url_list', 'url_list', 'result', 'multiav', 'matches', 'clamav'])
        if clamav:
            alerts.append({'clamav': clamav})

        avast = getValue(result, ['url_list', 'url_list', 'result', 'multiav', 'matches', 'avast'])
        if avast:
            alerts.append({'avast': avast})

        # Get the file analysis too, if it exists
        has_analysis = getValue(result, ['url_list', 'url_list', 'result', 'urlworker', 'has_file_analysis'])
        if has_analysis:
            hash = getValue(result, ['url_list', 'url_list', 'result', 'urlworker', 'sha256'])
            file_alerts = file(self.otx, hash)
            if file_alerts:
                for alert in file_alerts:
                    alerts.append(alert)

        # Todo: Check file page

        return alerts

    def file(self, hash):

        alerts = []

        hash_type = IndicatorTypes.FILE_HASH_MD5
        if len(hash) == 64:
            hash_type = IndicatorTypes.FILE_HASH_SHA256
        if len(hash) == 40:
            hash_type = IndicatorTypes.FILE_HASH_SHA1

        result = self.otx.get_indicator_details_full(hash_type, hash)

        n_av = 0
        pos_av = 0

        if 'virustotal' in result['analysis']['analysis']['plugins']['cuckoo']['result'].keys():
            for av in result['analysis']['analysis']['plugins']['cuckoo']['result']['virustotal']['scans'].keys():
                n_av += 1
                if getValue(result, ['analysis', 'analysis', 'plugins', 'cuckoo', 'result', 'virustotal', 'scans', av, 'result']):
                    pos_av += 1
            alerts.append({'vt': 'Detected in %s of %s engines' % (pos_av, n_av)})

        avg = getValue(result, ['analysis', 'analysis', 'plugins', 'avg', 'results', 'detection'])
        if avg:
            alerts.append({'avg': avg})

        clamav = getValue(result, ['analysis', 'analysis', 'plugins', 'clamav', 'results', 'detection'])
        if clamav:
            alerts.append({'clamav': clamav})

        avast = getValue(result, ['analysis', 'analysis', 'plugins', 'avast', 'results', 'detection'])
        if avast:
            alerts.append({'avast': avast})

        microsoft = getValue(result, ['analysis', 'analysis', 'plugins', 'cuckoo', 'result', 'virustotal', 'scans', 'Microsoft', 'result'])
        if microsoft:
            alerts.append({'microsoft': microsoft})

        symantec = getValue(result, ['analysis', 'analysis', 'plugins', 'cuckoo', 'result', 'virustotal', 'scans', 'Symantec', 'result'])
        if symantec:
            alerts.append({'symantec': symantec})

        kaspersky = getValue(result, ['analysis', 'analysis', 'plugins', 'cuckoo', 'result', 'virustotal', 'scans', 'Kaspersky', 'result'])
        if kaspersky:
            alerts.append({'kaspersky': kaspersky})

        suricata = getValue(result, ['analysis', 'analysis', 'plugins', 'cuckoo', 'result', 'suricata', 'rules', 'name'])
        if suricata and 'trojan' in str(suricata).lower():
            alerts.append({'suricata': suricata})

        return alerts


class IP_info(base.job.BaseModule):
    """ A module that gets the results from other modules and yields info about IP.

    Configuration::
        - **max_days** (String): Maximum number of previous days to get data (api_keys have a limit number of queries per hour, day or month).

    """

    def read_config(self):
        super().read_config()
        self.set_default_config('section', 'DEFAULT')
        self.set_default_config('tor_db_file', os.path.join('external_tools', 'tor_list.gz'))

    def run(self, path=None):
        self.check_params(path, check_from_module=True)
        try:
            max_days = int(self.myarray('max_days')[0])
        except Exception:
            max_days = int(self.myconfig('max_days', 90))

        tn = tor_node(self.myconfig('tor_db_file'))
        ab = abuseipdb()
        av = alienvault()
        ip_list = set()
        ip_field = self.myarray('ip_field')[0]
        date_field = self.myarray('date_field')[0]

        for fileinfo in self.from_module.run(path):
            if fileinfo[ip_field] in ip_list or check_private_ip(fileinfo[ip_field]) or check_file_date(fileinfo[date_field], max_days):
                continue
            ip_list.add(fileinfo[ip_field])
            res = tn.check_tor_ip(fileinfo[ip_field])
            res.update(ab.get_ip_data(fileinfo[ip_field]))
            res.update(av.ip(fileinfo[ip_field]))
            for k, v in res.items():
                if type(v) == list:
                    res[k] = ';'.join(v)
                else:
                    res[k] = str(v)
            yield res
