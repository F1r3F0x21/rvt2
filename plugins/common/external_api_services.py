#!/usr/bin/python3

import requests
import gzip
import os
import time
import ujson as json
import datetime
import dateutil.parser
from OTXv2 import OTXv2
import IndicatorTypes
import re
import logging
from functools import lru_cache

import base.job
import base.utils


def check_file_date(fdate, days):
    """ checks if date is older than X days"""
    if not fdate or fdate == '-':
        return False

    if isinstance(fdate, datetime.datetime):
        fdate = fdate.replace(tzinfo=None)
    else:
        fdate = dateutil.parser.parse(fdate).replace(tzinfo=None)

    if (datetime.datetime.now() - fdate).days > int(days):
        return True
    return False


def check_db_date(filepath, hours=24):
    """ checks if file is older than X hours"""

    if os.path.isfile(filepath) and (time.time() - os.path.getmtime(filepath)) / 3600. < hours:
        return True
    return False


def getValue(results, keys):
    # Get a nested key from a dict
    # Get from https://github.com/AlienVault-OTX/OTX-Python-SDK/tree/master/examples/is_malicious
    if isinstance(keys, list) and len(keys) > 0:

        if isinstance(results, dict):
            key = keys.pop(0)
            if key in results:
                return getValue(results[key], keys)
            else:
                return None
        else:
            if isinstance(results, list) and len(results) > 0:
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
        logging.getLogger(__name__).debug('Updating PhishTank database file')
        try:
            r = requests.get(self.url)
            with open(self.db_file, 'wb') as db:
                db.write(r.content)
        except Exception:
            logging.getLogger(__name__).error('Problems updating PhishTank database')

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
        logging.getLogger(__name__).debug('Updating TOR list file')
        try:
            r = requests.get(self.url)
            with gzip.open(self.db_file, 'wb') as db:
                db.write(r.content)
        except Exception:
            logging.getLogger(__name__).error('Problems updating TOR database')

    def check_tor_ip(self, ip):
        with gzip.open(self.db_file, 'r') as db:
            for line in db:
                if ip == line.decode().rstrip():
                    return {'torExitNode': True}
        return {'torExitNode': False}


class abuseipdb(object):
    def __init__(self, max_days=90, api_key=None, config=None):
        self.apikey = api_key
        if not self.apikey:
            if config:
                self.apikey = config.get('IP_API_keys', 'abuseipdb_key', None)
            if not self.apikey:
                logging.getLogger(__name__).error(f'No API key provided for abuseipdb')

        self.url = 'https://api.abuseipdb.com/api/v2/check'
        self.max_days = max_days

    @lru_cache(maxsize=1000)
    def get_ip_data(self, ip):
        data = {
            'isp': '',
            'domain': '',
            'hostnames': '',
            'usageType': '',
            'countryCode': '',
            'isWhitelisted': False,
            'isTor': False,
            'abuseConfidenceScore': 0,
            'totalReports': 0,
            'lastReportedAt': ''
        }

        # Keep only globally routable public IPs
        if not base.utils.is_candidate_for_abuse_check(ip):
            return data

        querystring = {
            'ipAddress': ip,
            'maxAgeInDays': self.max_days
        }

        headers = {
            'Accept': 'application/json',
            'Key': self.apikey
        }

        logging.getLogger(__name__).debug(f'Getting AbuseIP data for {ip}')
        response = requests.request(method='GET', url=self.url, headers=headers, params=querystring)

        # Formatted output
        ab = json.loads(response.text)
        if 'errors' in ab:
            return data
        for field in data.keys():
            value = ab['data'].get(field)
            if value:
                data[field] = value
        return data

    def check_ip(self, ip):
        data = self.get_ip_data(ip)
        return data['abuseConfidenceScore'] != '0'


class alienvault(object):
    # Class based on https://github.com/AlienVault-OTX/OTX-Python-SDK/tree/master/examples/is_malicious
    def __init__(self, otx_server='https://otx.alienvault.com/', api_key=None, config=None):
        self.apikey = api_key
        if not self.apikey:
            if config:
                self.apikey = config.get('IP_API_keys', 'alienvault_key', None)
            if not self.apikey:
                logging.getLogger(__name__).error(f'No API key provided for alienvault')

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

    @lru_cache(maxsize=1000)
    def ip(self, ip):
        res = {
            'alerts': [],
            'asn': '',
            'city': '',
            'countryName': '',
            'malicious': False
        }
        # Keep only globally routable public IPs
        if not base.utils.is_candidate_for_abuse_check(ip):
            return res

        logging.getLogger(__name__).debug(f'Getting AlienVault data for IP {ip}')
        try:
            result = self.otx.get_indicator_details_by_section(IndicatorTypes.IPv4, ip, 'general')
        except Exception:
            return res
        res['asn'] = result.get('asn', '')
        res['city'] = result.get('city', '')
        res['countryName'] = result.get('country_name', '')

        validation = getValue(result, ['validation'])
        if validation:  # ip is whitelisted
            return res
        pulses = getValue(result, ['pulse_info', 'pulses'])
        if pulses:
            for pulse in pulses:
                if 'name' in pulse:
                    res['alerts'].append(pulse['name'].replace('|','/'))
        res['malicious'] = len(res['alerts']) > 0
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
            file_alerts = self.file(hash)['alerts']
            if file_alerts:
                for alert in file_alerts:
                    alerts.append(alert)

        # Todo: Check file page

        return alerts

    def file(self, hash):
        logging.getLogger(__name__).debug(f'Getting AlienVault data for hash {hash}')

        hash_type = IndicatorTypes.FILE_HASH_MD5
        if len(hash) == 64:
            hash_type = IndicatorTypes.FILE_HASH_SHA256
        if len(hash) == 40:
            hash_type = IndicatorTypes.FILE_HASH_SHA1

        result = self.otx.get_indicator_details_full(hash_type, hash)

        malicious_indicators = self._is_malicious_file(result)
        a = {
            'indicator': getValue(result, ['general', 'indicator']),
            'type': getValue(result, ['general', 'type']),
            'file_class': getValue(result, ['analysis', 'analysis', 'info', 'results', 'file_class']),
            'filesize': getValue(result, ['analysis', 'analysis', 'info', 'results', 'filesize']),
            'filename': getValue(result, ['analysis', 'analysis', 'plugins', 'exiftool', 'results', 'Original_Filename']) or getValue(result, ['analysis', 'analysis', 'plugins', 'exiftool', 'results', 'EXE:OriginalFileName']),
            'alerts': malicious_indicators,
            'malicious': len(malicious_indicators) > 0,
            'full_result': result
        }
        return a

    def _is_malicious_file(self, result):
        ''' Check if a file hash has known malicious indicators. Expected input: result of self.file(hash) '''
        alerts = []
        n_av = 0
        pos_av = 0

        virustotal = getValue(result, ['analysis', 'analysis', 'plugins', 'cuckoo', 'results', 'virustotal', 'scans'])
        if virustotal:
            for av in virustotal.keys():
                n_av += 1
                if getValue(result, ['analysis', 'analysis', 'plugins', 'cuckoo', 'result', 'virustotal', 'scans', av, 'result']):
                    pos_av += 1
            alerts.append({'vt': f'Detected in {pos_av} of {n_av} engines'})

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


class IPInfo(base.job.BaseModule):
    """ Get input from other modules and provide additional information about IP.
        When 'ip_field' and 'date_field' are defined, input data is assumed to be a dictionary.
        Otherwise, input data is treated as a string containg an IP address.
        The search services generate the following new fields:
            - AbuseIPDB: 'isp', 'domain', 'hostnames', 'usageType', 'countryCode', 'abuseConfidenceScore', 'totalReports', 'isWhitelisted', 'isTor', 'lastReportedAt'
            - AlienVault: 'alerts', 'city', 'countryName', 'asn', 'malicious'
            - TorProject: 'torExitNode'

    Configuration:
        - **max_days** (String): Maximum number of past days to include in queries. Useful to limit data retrieval and respect API query rate limits (hourly, daily, or monthly, depending on the provider)
        - **ip_field** (String): Name of the field in the input data that contains the IP address
        - **date_field** (String): Name of the field in the input data that contains the date associated with the IP
        - **alienvault_key** (String): API key for authenticating requests to the AlienVault service
        - **abuseipdb_key** (String): API key for authenticating requests to the AbuseIPDB service
        - **services** (list): List of external services to query. Valid options are: [AbuseIPDB, AlienVault, TorProject]
    """

    def read_config(self):
        super().read_config()
        self.set_default_config('section', 'DEFAULT')
        self.set_default_config('tor_db_file', os.path.join(self.myconfig('rvthome'), 'external_tools', 'tor_list.gz'))
        self.set_default_config('max_days', 90)
        self.set_default_config('alienvault_key', None)
        self.set_default_config('abuseipdb_key', None)
        self.set_default_config('services', '["AbuseIPDB", "AlienVault", "TorProject"]')

    def run(self, path=None):
        self.check_params(path, check_from_module=True)
        max_days = int(self.myconfig('max_days'))

        # Initialize services
        available_services = ["abuseipdb", "alienvault", "torproject"]
        services = self.myarray('services')
        services = [i.lower() for i in services]
        tools_to_remove = []
        for i, tool in enumerate(services):
            if tool not in available_services:
                self.logger().error(f'Search tool {tool} not among available services: {available_services}')
                tools_to_remove.append(i)
                continue
            elif tool == "abuseipdb":
                ab_key = self.myconfig('abuseipdb_key')
                ab = abuseipdb(api_key=ab_key, config=self.config)
            elif tool == "alienvault":
                av_key = self.myconfig('alienvault_key')
                av = alienvault(api_key=av_key, config=self.config)
            elif tool == "torproject":
                tn = tor_node(self.myconfig('tor_db_file'))
        for tool_to_remove in tools_to_remove:
            services.pop(tool_to_remove)

        # Get ip_field and date_field
        parsed_ips = set()
        flag_dict = True
        ip_field = self.myconfig('ip_field')
        if not ip_field:
            flag_dict = False
        date_field = self.myconfig('date_field')
        if not date_field:
            now = datetime.datetime.now()

        for iteminfo in self.from_module.run(path):
            res= {name: "" for name in "isp asn domain hostnames usageType countryCode countryName city abuseConfidenceScore totalReports isWhitelisted isTor torExitNode lastReportedAt alerts malicious".split()}
            if not flag_dict:  # Input data is treated as a string containg an IP address.
                ip_item = iteminfo.rstrip()
                fdate = now
            else:  # Input data is assumed to be a dictionary
                ip_item = iteminfo.get(ip_field)
                fdate = iteminfo.get(date_field) if date_field else now

            # When a list of IP is passed as input, return only unique IPs
            if not flag_dict and ip_item in parsed_ips:
                continue
            # Skip if the date is older than 'max_days' before today
            if flag_dict and check_file_date(fdate, max_days):
                # Update the original dictionary but don't overwrite fields
                for key, value in res.items():
                    if key not in iteminfo:
                        iteminfo[key] = value
                yield iteminfo
                continue

            parsed_ips.add(ip_item)
            if not flag_dict:
                res['ip'] = ip_item
            if "abuseipdb" in services:
                res.update(ab.get_ip_data(ip_item))
            if "alienvault" in services:
                res.update(av.ip(ip_item))
            if "torproject" in services:
                res.update(tn.check_tor_ip(ip_item))
            for k, v in res.items():
                if isinstance(v, list):
                    res[k] = ';'.join(v)
                else:
                    res[k] = str(v)

            if flag_dict:
                iteminfo.update(res)
                yield iteminfo
            else:
                yield res
