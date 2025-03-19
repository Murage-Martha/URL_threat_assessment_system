from typing import Dict
from datetime import datetime
from ..models.ml_model import URLThreatModel
from ..database.db import URLThreat
from .external_api import ExternalAPIService

class URLAnalyzer:
    def __init__(self, db_session, external_api_service: ExternalAPIService, ml_model: URLThreatModel):
        self.db_session = db_session
        self.external_api_service = external_api_service
        self.ml_model = ml_model
    
    def analyze_url(self, url: str) -> Dict:
        """Complete URL analysis pipeline"""
        # Check database first
        existing_threat = self._check_database(url)
        if existing_threat:
            return self._create_report(existing_threat)
        
        # Initialize report
        report = {
            'url': url,
            'timestamp': datetime.utcnow().isoformat(),
            'analysis': {}
        }
        
        # Check external APIs
        api_results = self._check_external_apis(url)
        report['analysis']['external_apis'] = api_results
        
        # ML model analysis
        ml_status, ml_score = self.ml_model.predict(url)
        report['analysis']['ml_model'] = {
            'status': ml_status,
            'threat_score': ml_score
        }
        
        # Determine final threat status
        final_status = self._determine_final_status(api_results, ml_status)
        report['final_status'] = final_status
        
        # Save to database
        self._save_to_database(url, final_status, ml_score, report)
        
        return report
    
    def _check_database(self, url: str) -> URLThreat:
        """Check if URL exists in database"""
        return self.db_session.query(URLThreat).filter_by(url=url).first()
    
    def _check_external_apis(self, url: str) -> Dict:
        """Query external APIs"""
        vt_results = self.external_api_service.check_virustotal(url)
        gsb_results = self.external_api_service.check_google_safe_browsing(url)
        
        return {
            'virustotal': vt_results,
            'google_safe_browsing': gsb_results
        }
    
    def _determine_final_status(self, api_results: Dict, ml_status: str) -> str:
        """Determine final threat status based on all analyses"""
        # If any source marks as malicious, consider it malicious
        if (api_results['virustotal'].get('positives', 0) > 0 or
            api_results['google_safe_browsing'].get('matches') or
            ml_status == 'malicious'):
            return 'malicious'
        
        # If ML model marks as suspicious, maintain that status
        if ml_status == 'suspicious':
            return 'suspicious'
        
        return 'safe'
    
    def _save_to_database(self, url: str, status: str, score: float, report: Dict):
        """Save analysis results to database"""
        threat = URLThreat(
            url=url,
            threat_status=status,
            threat_score=score,
            source='combined',
            external_api_results=str(report['analysis'])
        )
        self.db_session.add(threat)
        self.db_session.commit()
    
    def _create_report(self, threat: URLThreat) -> Dict:
        """Create report from database entry"""
        return {
            'url': threat.url,
            'timestamp': threat.created_at.isoformat(),
            'final_status': threat.threat_status,
            'threat_score': threat.threat_score,
            'analysis': eval(threat.external_api_results) if threat.external_api_results else {}
        }