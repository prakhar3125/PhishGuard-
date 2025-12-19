import requests
import json
import base64
from typing import Dict, Optional, List
from datetime import datetime, timedelta
from pathlib import Path
from app.config import settings
from sqlalchemy.orm import Session
from sqlalchemy.exc import SQLAlchemyError
from app.models import ThreatIntelCache

class ThreatIntelligence:
    def __init__(self, db: Session):
        self.db = db
        self.vt_api_key = settings.VIRUSTOTAL_API_KEY
        self.abuseipdb_api_key = settings.ABUSEIPDB_API_KEY
        self.cache_ttl_hours = 24
        
        # Optimization: Reuse TCP connections for all API calls
        self.http_session = requests.Session()
        
        # Load blacklist once at startup to avoid repeated disk reads
        self.bad_domains = self._load_local_blacklist()

    def _load_local_blacklist(self) -> List[str]:
        """Load local blacklist safely with absolute paths"""
        try:
            # Adjust path calculation to be more robust
            base_path = Path(__file__).resolve().parents[2] 
            file_path = base_path / 'data' / 'intel_db.json'
            
            if file_path.exists():
                with open(file_path, 'r') as f:
                    data = json.load(f)
                    return data.get('bad_domains', [])
        except (json.JSONDecodeError, IOError) as e:
            print(f"⚠️ Error loading local blacklist: {e}")
        return []

    def check_ip(self, ip: str) -> Dict:
        """Check IP reputation across multiple sources"""
        cached = self._get_from_cache(ip, 'ip')
        if cached: return cached
        
        results = {
            'ioc_value': ip, 'ioc_type': 'ip', 'is_malicious': False,
            'reputation_score': 0, 'threat_categories': [], 'sources': {}
        }
        
        # AbuseIPDB check
        if self.abuseipdb_api_key:
            abuse_data = self._check_abuseipdb(ip)
            if abuse_data:
                results['sources']['abuseipdb'] = abuse_data
                results['reputation_score'] += abuse_data.get('abuse_confidence_score', 0)
                if abuse_data.get('is_malicious'):
                    results['is_malicious'] = True
                    results['threat_categories'].extend(abuse_data.get('categories', []))
        
        # VirusTotal check
        if self.vt_api_key:
            vt_data = self._check_virustotal_ip(ip)
            if vt_data:
                results['sources']['virustotal'] = vt_data
                malicious = vt_data.get('malicious_count', 0)
                if malicious > 2:
                    results['is_malicious'] = True
                    results['reputation_score'] += min(malicious * 10, 50)
        
        results['reputation_score'] = min(results['reputation_score'], 100)
        self._save_to_cache(ip, 'ip', results)
        return results

    def check_url(self, url: str) -> Dict:
        """Check URL reputation with existing report fallback"""
        cached = self._get_from_cache(url, 'url')
        if cached: return cached
        
        results = {
            'ioc_value': url, 'ioc_type': 'url', 'is_malicious': False,
            'reputation_score': 0, 'threat_categories': [], 'sources': {}
        }
        
        if self.vt_api_key:
            vt_data = self._check_virustotal_url(url)
            if vt_data:
                results['sources']['virustotal'] = vt_data
                malicious = vt_data.get('malicious_count', 0)
                if malicious >= 2:
                    results['is_malicious'] = True
                    results['reputation_score'] = min(malicious * 15, 100)
        
        # Check in-memory blacklist (Instant)
        if any(domain in url for domain in self.bad_domains):
            results['is_malicious'] = True
            results['reputation_score'] = 100
            results['threat_categories'].append('Known Phishing Domain')
        
        self._save_to_cache(url, 'url', results)
        return results

    # ===== Private API Implementation Methods =====
    
    def _check_abuseipdb(self, ip: str) -> Optional[Dict]:
        """Query AbuseIPDB API with connection pooling"""
        try:
            url = 'https://api.abuseipdb.com/api/v2/check'
            headers = {'Key': self.abuseipdb_api_key, 'Accept': 'application/json'}
            params = {'ipAddress': ip, 'maxAgeInDays': '90'}
            response = self.http_session.get(url, headers=headers, params=params, timeout=5)
            
            if response.status_code == 200:
                data = response.json().get('data', {})
                return {
                    'abuse_confidence_score': data.get('abuseConfidenceScore', 0),
                    'is_malicious': data.get('abuseConfidenceScore', 0) > 50,
                    'categories': [str(data.get('usageType', ''))],
                    'total_reports': data.get('totalReports', 0)
                }
            elif response.status_code == 429:
                print("⚠️ AbuseIPDB rate limit exceeded.")
        except requests.RequestException:
            pass
        return None

    def _check_virustotal_url(self, url: str) -> Optional[Dict]:
        """Check VirusTotal for an existing URL report (instant)"""
        try:
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
            endpoint = f'https://www.virustotal.com/api/v3/urls/{url_id}'
            headers = {'x-apikey': self.vt_api_key}
            
            response = self.http_session.get(endpoint, headers=headers, timeout=5)
            if response.status_code == 200:
                stats = response.json().get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                return {
                    'malicious_count': stats.get('malicious', 0),
                    'suspicious_count': stats.get('suspicious', 0),
                    'harmless_count': stats.get('harmless', 0)
                }
        except requests.RequestException:
            pass
        return None

    # ===== Cache Management Methods =====

    def _get_from_cache(self, ioc_value: str, ioc_type: str) -> Optional[Dict]:
        """Atomic cache retrieval"""
        try:
            cached = self.db.query(ThreatIntelCache).filter_by(
                ioc_value=ioc_value, ioc_type=ioc_type
            ).first()
            
            if cached and cached.expires_at > datetime.utcnow():
                return {
                    'ioc_value': cached.ioc_value,
                    'ioc_type': cached.ioc_type,
                    'is_malicious': cached.is_malicious,
                    'reputation_score': cached.reputation_score,
                    'sources': cached.raw_response or {},
                    'threat_categories': []
                }
        except SQLAlchemyError:
            pass 
        return None

    def _save_to_cache(self, ioc_value: str, ioc_type: str, results: Dict):
        """Safe cache persistence with error rollback"""
        try:
            expires_at = datetime.utcnow() + timedelta(hours=self.cache_ttl_hours)
            cached = ThreatIntelCache(
                ioc_value=ioc_value,
                ioc_type=ioc_type,
                reputation_score=results['reputation_score'],
                is_malicious=results['is_malicious'],
                source_api='multiple',
                raw_response=results.get('sources', {}),
                expires_at=expires_at
            )
            self.db.add(cached)
            self.db.commit()
        except SQLAlchemyError as e:
            self.db.rollback()
            print(f"❌ Database error saving cache: {e}")