import json
from datetime import datetime
from app.database.db import URLThreat
from app.services.external_api import ExternalAPIService
from app.models.ml_model import URLThreatModel
import uuid
import logging

class URLAnalyzer:
    def __init__(self, db_session, external_api_service, ml_model):
        self.db_session = db_session
        self.external_api_service = external_api_service
        self.ml_model = ml_model

    def analyze_url(self, url):
        # Normalize the URL
        url = self._normalize_url(url)

        # Query external APIs
        try:
            external_api_results = self.external_api_service.query_external_apis(url)
            logging.debug(f"External API results: {external_api_results}")
        except Exception as e:
            logging.error(f"Error querying external APIs: {e}")
            raise

        # Analyze URL using ML model
        try:
            ml_results = self.ml_model.analyze_url(url)
            logging.debug(f"ML model results: {ml_results}")
        except Exception as e:
            logging.error(f"Error analyzing URL with ML model: {e}")
            raise

        # Ensure ml_results contains 'details' key
        if 'details' not in ml_results:
            ml_results['details'] = {
                'analysis_id': ml_results.get('analysis_id', str(uuid.uuid4())),
                'threat_score': ml_results.get('threat_score', 0.0),
                'source': ml_results.get('source', 'ML Model')
            }

        # Combine results
        combined_results = self._combine_results(external_api_results, ml_results)
        logging.debug(f"Combined results: {combined_results}")

        # Save results to database
        self._update_threat_database(url, combined_results)

        return combined_results

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
            'analysis_id': ml_results['details']['analysis_id'],
            'threat_status': ml_results['threat_status'],
            'threat_score': ml_results['threat_score'],
            'source': ml_results['source'],
            'external_api_results': external_api_results
        }

        # Check if 'scans' key is present in external_api_results
        if 'virustotal' in external_api_results and 'scans' in external_api_results['virustotal']:
            # If any external API indicates a threat, update the threat status and score
            if any(api_result.get('detected') for api_result in external_api_results['virustotal']['scans'].values()):
                combined_results['threat_status'] = 'malicious'
                combined_results['threat_score'] = max(api_result.get('threat_score', 1.0) for api_result in external_api_results['virustotal']['scans'].values())
            else:
                # If all external APIs indicate the URL is safe, override the ML model's prediction
                if all(not api_result.get('detected') for api_result in external_api_results['virustotal']['scans'].values()):
                    combined_results['threat_status'] = 'safe'
                    combined_results['threat_score'] = 0.0

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

