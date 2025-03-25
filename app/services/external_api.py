import logging
import requests
from typing import Dict
import time
from config import Configuration

class ExternalAPIService:
    def __init__(self, virustotal_api_key, google_safe_browsing_key):
        self.virustotal_api_key = virustotal_api_key
        self.google_safe_browsing_key = google_safe_browsing_key
        self.timeout = 10
        self.max_retries = 3

    def query_external_apis(self, url):
        results = {}
        results['virustotal'] = self._query_virustotal(url)
        results['google_safe_browsing'] = self._query_google_safe_browsing(url)
        logging.debug(f"External API results: {results}")
        return results

    def _query_virustotal(self, url):
        # Example implementation for VirusTotal API query
        response = requests.get(
            f"https://www.virustotal.com/vtapi/v2/url/report?apikey={self.virustotal_api_key}&resource={url}"
        )
        return response.json()

    def _query_google_safe_browsing(self, url):
        # Example implementation for Google Safe Browsing API query
        payload = {
            "client": {
                "clientId": "yourcompany",
                "clientVersion": "1.5.2"
            },
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
                "platformTypes": ["WINDOWS"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [
                    {"url": url}
                ]
            }
        }
        response = requests.post(
            f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={self.google_safe_browsing_key}",
            json=payload
        )
        return response.json()