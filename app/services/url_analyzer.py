import json
from datetime import datetime
from app.database.db import URLThreat
from app.services.external_api import ExternalAPIService
from app.models.ml_model import URLThreatModel
import uuid
import logging
import joblib
import re
from scipy.sparse import csr_matrix, hstack
import numpy as np
import random  # Import random for randomized ranges

class URLAnalyzer:
    def __init__(self, db_session, external_api_service, ml_model):
        self.db_session = db_session
        self.external_api_service = external_api_service
        self.ml_model = ml_model

        # Load the vectorizer and scaler
        self.vectorizer = joblib.load('models/url_vectorizer.joblib')
        self.scaler = joblib.load('models/url_scaler.joblib')

    def analyze_url(self, url):
        # Normalize the URL and ensure it's a string
        url = str(self._normalize_url(url))

        # Check if the URL has already been analyzed
        existing_threat = self._check_threat_database(url)
        if existing_threat:
            logging.debug(f"URL already analyzed. Returning stored results for {url}")
            return self._display_analysis_report(existing_threat)

        # Query external APIs
        try:
            external_api_results = self.external_api_service.query_external_apis(url)
            logging.debug(f"External API results: {external_api_results}")
        except Exception as e:
            logging.error(f"Error querying external APIs: {e}")
            raise

        # Initialize variables for threat score calculation
        scores = []
        total_sources = 0
        malicious_detected = False  # Track if any malicious activity is detected
        total_issues_detected = 0  # Track the total number of issues detected

        # Add VirusTotal score if available
        if 'virustotal' in external_api_results:
            vt_results = external_api_results['virustotal']
            positives = vt_results.get('positives', 0)
            total = vt_results.get('total', 1)  # Avoid division by zero
            vt_score = positives / total  # Calculate threat score as a ratio
            scores.append(vt_score)
            total_sources += 1

            # Check if any malicious activity is detected
            if positives > 0:
                malicious_detected = True
                total_issues_detected += positives

        # Add Google Safe Browsing score if available
        if 'google_safe_browsing' in external_api_results:
            # Assume Google Safe Browsing returns a binary result (safe or unsafe)
            gsb_score = 1.0 if external_api_results['google_safe_browsing'] else 0.0
            scores.append(gsb_score)
            total_sources += 1

            # Check if Google Safe Browsing flagged the URL
            if gsb_score > 0.0:
                malicious_detected = True
                total_issues_detected += 1

        # Analyze URL using ML model
        ml_score = None
        try:
            # Ensure URL is in a list for processing
            url_list = [str(url)]  # Explicitly convert to string list
            
            # Transform the URL into numerical features
            lexical_features = self._extract_lightweight_features(url_list)
            tfidf_features = self.vectorizer.transform(url_list)
            
            # Ensure both matrices are in compatible sparse formats
            lexical_features_sparse = csr_matrix(lexical_features.astype(np.float32))
            combined_features = hstack([lexical_features_sparse, tfidf_features])
            
            scaled_features = self.scaler.transform(combined_features)
            ml_score = self.ml_model.predict(scaled_features)[0]  # Assuming the model returns a score between 0 and 1
            scores.append(ml_score)
            total_sources += 1
            logging.debug(f"ML model score: {ml_score}")

            # Check if ML model flagged the URL
            if ml_score > 0.0:
                malicious_detected = True
                total_issues_detected += 1
        except Exception as e:
            logging.error(f"Error analyzing URL with ML model: {e}")
            # Proceed without ML model score

        # Calculate the average threat score
        average_score = sum(scores) / total_sources if total_sources > 0 else 0.0

        # Enforce a minimum threshold if malicious activity is detected
        if malicious_detected:
            if total_issues_detected == 1:
                average_score = max(average_score, random.uniform(0.61, 0.70))  # Randomize between 61% and 70%
            elif total_issues_detected == 2:
                average_score = max(average_score, random.uniform(0.71, 0.80))  # Randomize between 71% and 80%
            elif total_issues_detected == 3:
                average_score = max(average_score, random.uniform(0.81, 0.90))  # Randomize between 81% and 90%
            else:  # More than 3 issues
                average_score = max(average_score, random.uniform(0.91, 1.00))  # Randomize between 91% and 100%

        threat_score = average_score  # Already normalized to 0.0 - 1.0 scale

        # Combine results
        combined_results = self._combine_results(external_api_results, ml_score)
        combined_results['threat_score'] = threat_score
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
            url = 'https://' + url
        return url

    def _query_external_apis(self, url):
        return self.external_api_service.query_external_apis(url)

    def _analyze_url_using_ml(self, url):
        return self.ml_model.analyze_url(url)

    def _combine_results(self, external_api_results, ml_results):
        # Combine the results from external APIs and ML model
        combined_results = {
            'external_api_results': external_api_results
        }

        if ml_results:
            combined_results.update({
                'analysis_id': ml_results['details']['analysis_id'],
                'threat_status': ml_results['threat_status'],
                'threat_score': ml_results['threat_score'],
                'source': ml_results['source']
            })
        else:
            # If ML model fails, fallback to external API results
            combined_results.update({
                'analysis_id': str(uuid.uuid4()),
                'threat_status': 'unknown',
                'threat_score': 0.0,
                'source': 'External APIs Only'
            })

        # Check if 'scans' key is present in external_api_results
        if 'virustotal' in external_api_results and 'scans' in external_api_results['virustotal']:
            # If any external API indicates a threat, update the threat status and score
            if any(api_result.get('detected') for api_result in external_api_results['virustotal']['scans'].values()):
                combined_results['threat_status'] = 'malicious'
                combined_results['threat_score'] = max(api_result.get('threat_score', 1.0) for api_result in external_api_results['virustotal']['scans'].values())
            else:
                # If all external APIs indicate the URL is safe
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
        report = {
            'url': threat.url,
            'threat_status': threat.threat_status,
            'threat_score': threat.threat_score,
            'source': threat.source,
            'external_api_results': json.loads(threat.external_api_results) if threat.external_api_results else {},
            'analysis_id': threat.analysis_id
        }
        return report

    def _extract_lightweight_features(self, urls):
        """
        Returns features as float32 numpy array with robust type handling
        """
        features = np.zeros((len(urls), 5), dtype=np.float32)
        for i, url in enumerate(urls):
            url = str(url).lower()  # Ensure string type and lowercase
            
            # Length feature
            features[i, 0] = float(len(url))
            
            # Special characters feature
            features[i, 1] = float(sum(c in '-_@?%/' for c in url))
            
            # IP address check (using simplified regex)
            features[i, 2] = float(bool(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', url)))
            
            # HTTPS check
            features[i, 3] = float(url.startswith('https://'))
            
            # Domain length
            domain_match = re.findall(r'://([^/]+)/?', url)
            features[i, 4] = float(len(domain_match[0]) if domain_match else 0)
        
        return features

