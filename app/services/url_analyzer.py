import json
from datetime import datetime
from app.database.db import URLThreat
from app.services.external_api import ExternalAPIService
from app.models.ml_model import URLThreatModel

class URLAnalyzer:
    def __init__(self, db_session, external_api_service, ml_model):
        self.db_session = db_session
        self.external_api_service = external_api_service
        self.ml_model = ml_model

    def analyze_url(self, url):
        # Normalize the URL
        url = self._normalize_url(url)

        # Always perform external API analysis and ML model analysis
        external_api_results = self._query_external_apis(url)
        ml_results = self._analyze_url_using_ml(url)

        # Combine results from external APIs and ML model
        combined_results = self._combine_results(external_api_results, ml_results)

        # Update the Threat Database with combined results
        self._update_threat_database(url, combined_results)
        return self._display_analysis_report(self._check_threat_database(url))

    def _check_threat_database(self, identifier):
        # Check if the identifier is a URL or an analysis ID
        if self._is_url(identifier):
            # Query the database for the URL
            threat = self.db_session.query(URLThreat).filter_by(url=identifier).first()
        else:
            # Query the database for the analysis ID
            threat = self.db_session.query(URLThreat).filter_by(analysis_id=identifier).first()
        return threat

    def _is_url(self, identifier):
        # Simple check to determine if the identifier is a URL
        return identifier.startswith('http://') or identifier.startswith('https://')

    def _normalize_url(self, url):
        # Add http:// prefix if missing
        if not url.startswith('http://') and not url.startswith('https://'):
            url = 'http://' + url
        return url

    def _query_external_apis(self, url):
        return self.external_api_service.query_external_apis(url)

    def _analyze_url_using_ml(self, url):
        return self.ml_model.analyze_url(url)

    def _combine_results(self, external_api_results, ml_results):
        # Combine the results from external APIs and ML model
        combined_results = {
            'analysis_id': ml_results['analysis_id'],
            'threat_status': ml_results['threat_status'],
            'threat_score': ml_results['threat_score'],
            'source': ml_results['source'],
            'external_api_results': external_api_results
        }

        # If external APIs indicate a threat, update the threat status and score
        if any(api_result.get('threat_status') == 'malicious' for api_result in external_api_results.values()):
            combined_results['threat_status'] = 'malicious'
            combined_results['threat_score'] = max(api_result.get('threat_score', 0) for api_result in external_api_results.values())

        return combined_results

    def _update_threat_database(self, url, results):
        try:
            threat = self.db_session.query(URLThreat).filter_by(url=url).first()
            if threat:
                # Update existing entry
                threat.analysis_id = results['analysis_id']
                threat.threat_status = results.get('threat_status', 'unknown')
                threat.threat_score = results.get('threat_score')
                threat.source = results.get('source')
                threat.external_api_results = json.dumps(results.get('external_api_results'))
                threat.last_checked = datetime.utcnow()
            else:
                # Insert new entry
                threat = URLThreat(
                    url=url,
                    analysis_id=results['analysis_id'],
                    threat_status=results.get('threat_status', 'unknown'),  # Default to 'unknown' if not provided
                    threat_score=results.get('threat_score'),
                    source=results.get('source'),
                    external_api_results=json.dumps(results.get('external_api_results'))  # Serialize to JSON
                )
                self.db_session.add(threat)
            self.db_session.commit()
        except Exception as e:
            self.db_session.rollback()
            raise e

    def _display_analysis_report(self, threat):
        # Generate a report based on the threat data
        report = {
            'url': threat.url,
            'status': threat.threat_status,
            'details': {
                'analysis_id': threat.analysis_id,
                'threat_score': threat.threat_score,
                'source': threat.source,
                'external_api_results': json.loads(threat.external_api_results)  # Deserialize from JSON
            }
        }
        return report

