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
        try:
            response = requests.get(
                f"https://www.virustotal.com/vtapi/v2/url/report?apikey={self.virustotal_api_key}&resource={url}"
            )
            response.raise_for_status()
            logging.debug(f"VirusTotal response: {response.text}")
            return response.json()
        except requests.exceptions.RequestException as e:
            logging.error(f"Error querying VirusTotal: {e}")
            return {}

    def _query_google_safe_browsing(self, url):
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
        try:
            response = requests.post(
                f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={self.google_safe_browsing_key}",
                json=payload
            )
            response.raise_for_status()
            logging.debug(f"Google Safe Browsing response: {response.text}")
            return response.json()
        except requests.exceptions.RequestException as e:
            logging.error(f"Error querying Google Safe Browsing: {e}")
            return {}