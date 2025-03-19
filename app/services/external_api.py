import requests
from typing import Dict
import time

class ExternalAPIService:
    def __init__(self, virustotal_key: str, gsb_key: str):
        self.virustotal_key = virustotal_key
        self.gsb_key = gsb_key
        self.timeout = 10
        self.max_retries = 3

    def check_virustotal(self, url: str) -> Dict:
        for attempt in range(self.max_retries):
            try:
                response = requests.get(
                    f'https://www.virustotal.com/vtapi/v2/url/report',
                    params={'apikey': self.virustotal_key, 'resource': url},
                    headers={'x-apikey': self.virustotal_key},
                    timeout=self.timeout
                )
                if response.status_code == 429:
                    time.sleep(60)
                    continue
                if response.status_code == 200:
                    return response.json()
                return {'error': 'API request failed'}
            except Exception as e:
                return {'error': str(e)}

    def check_google_safe_browsing(self, url: str) -> Dict:
        try:
            payload = {
                'client': {
                    'clientId': 'your-client-id',
                    'clientVersion': '1.0'
                },
                'threatInfo': {
                    'threatTypes': ['MALWARE', 'SOCIAL_ENGINEERING'],
                    'platformTypes': ['ANY_PLATFORM'],
                    'threatEntryTypes': ['URL'],
                    'threatEntries': [{'url': url}]
                }
            }
            response = requests.post(
                f'https://safebrowsing.googleapis.com/v4/threatMatches:find?key={self.gsb_key}',
                json=payload
            )
            if response.status_code == 200:
                return response.json()
            return {'error': 'API request failed'}
        except Exception as e:
            return {'error': str(e)}
