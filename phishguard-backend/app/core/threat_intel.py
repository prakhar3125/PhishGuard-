import requests
import json
import time
from typing import Dict, Optional, List
from datetime import datetime, timedelta
from app.config import settings
from sqlalchemy.orm import Session
from app.models import ThreatIntelCache

class ThreatIntelligence:
    def __init__(self, db: Session):
        self.db = db
        self.vt_api_key = settings.VIRUSTOTAL_API_KEY
        self.abuseipdb_api_key = settings.ABUSEIPDB_API_KEY
        self.cache_ttl_hours = 24

    def check_ip(self, ip: str) -> Dict:
        """Check IP reputation across multiple sources"""
        # Check cache first
        cached = self._get_from_cache(ip, 'ip')
        if cached:
            return cached
        
        results = {
            'ioc_value': ip,
            'ioc_type': 'ip',
            'is_malicious': False,
            'reputation_score': 0,
            'threat_categories': [],
            'sources': {}
        }
        
        # AbuseIPDB check
        if self.abuseipdb_api_key:
            abuseipdb_result = self._check_abuseipdb(ip)
            if abuseipdb_result:
                results['sources']['abuseipdb'] = abuseipdb_result
                results['reputation_score'] += abuseipdb_result.get('abuse_confidence_score', 0)
                if abuseipdb_result.get('is_malicious'):
                    results['is_malicious'] = True
                    results['threat_categories'].extend(abuseipdb_result.get('categories', []))
        
        # VirusTotal check
        if self.vt_api_key:
            vt_result = self._check_virustotal_ip(ip)
            if vt_result:
                results['sources']['virustotal'] = vt_result
                malicious_count = vt_result.get('malicious_count', 0)
                if malicious_count > 3:
                    results['is_malicious'] = True
                    results['reputation_score'] += min(malicious_count * 10, 50)
        
        # Normalize score to 0-100
        results['reputation_score'] = min(results['reputation_score'], 100)
        
        # Cache the result
        self._save_to_cache(ip, 'ip', results)
        
        return results

    def check_url(self, url: str) -> Dict:
        """Check URL reputation"""
        cached = self._get_from_cache(url, 'url')
        if cached:
            return cached
        
        results = {
            'ioc_value': url,
            'ioc_type': 'url',
            'is_malicious': False,
            'reputation_score': 0,
            'threat_categories': [],
            'sources': {}
        }
        
        # VirusTotal URL scan
        if self.vt_api_key:
            vt_result = self._check_virustotal_url(url)
            if vt_result:
                results['sources']['virustotal'] = vt_result
                malicious_count = vt_result.get('malicious_count', 0)
                if malicious_count > 3:
                    results['is_malicious'] = True
                    results['reputation_score'] = min(malicious_count * 10, 100)
        
        # Check against local blacklist
        blacklist_result = self._check_local_blacklist(url)
        if blacklist_result:
            results['is_malicious'] = True
            results['reputation_score'] = 100
            results['threat_categories'].append('Known Phishing')
        
        self._save_to_cache(url, 'url', results)
        return results

    def check_domain(self, domain: str) -> Dict:
        """Check domain reputation"""
        cached = self._get_from_cache(domain, 'domain')
        if cached:
            return cached
        
        results = {
            'ioc_value': domain,
            'ioc_type': 'domain',
            'is_malicious': False,
            'reputation_score': 0,
            'threat_categories': [],
            'sources': {}
        }
        
        # VirusTotal domain check
        if self.vt_api_key:
            vt_result = self._check_virustotal_domain(domain)
            if vt_result:
                results['sources']['virustotal'] = vt_result
                malicious_count = vt_result.get('malicious_count', 0)
                if malicious_count > 2:
                    results['is_malicious'] = True
                    results['reputation_score'] = min(malicious_count * 15, 100)
        
        # Check domain age and registrar (heuristic)
        domain_analysis = self._analyze_domain(domain)
        if domain_analysis['is_suspicious']:
            results['reputation_score'] += 30
            results['threat_categories'].extend(domain_analysis['reasons'])
        
        self._save_to_cache(domain, 'domain', results)
        return results

    def check_file_hash(self, file_hash: str) -> Dict:
        """Check file hash reputation"""
        cached = self._get_from_cache(file_hash, 'hash')
        if cached:
            return cached
        
        results = {
            'ioc_value': file_hash,
            'ioc_type': 'hash',
            'is_malicious': False,
            'reputation_score': 0,
            'threat_categories': [],
            'sources': {}
        }
        
        if self.vt_api_key:
            vt_result = self._check_virustotal_hash(file_hash)
            if vt_result:
                results['sources']['virustotal'] = vt_result
                malicious_count = vt_result.get('malicious_count', 0)
                if malicious_count > 5:
                    results['is_malicious'] = True
                    results['reputation_score'] = 100
        
        self._save_to_cache(file_hash, 'hash', results)
        return results

    # ===== API Implementations =====
    
    def _check_abuseipdb(self, ip: str) -> Optional[Dict]:
        """Query AbuseIPDB API"""
        if not self.abuseipdb_api_key:
            return None
        
        try:
            url = 'https://api.abuseipdb.com/api/v2/check'
            headers = {
                'Key': self.abuseipdb_api_key,
                'Accept': 'application/json'
            }
            params = {
                'ipAddress': ip,
                'maxAgeInDays': '90',
                'verbose': ''
            }
            
            response = requests.get(url, headers=headers, params=params, timeout=10)
            
            if response.status_code == 200:
                data = response.json().get('data', {})
                return {
                    'abuse_confidence_score': data.get('abuseConfidenceScore', 0),
                    'is_malicious': data.get('abuseConfidenceScore', 0) > 50,
                    'categories': data.get('usageType', ''),
                    'total_reports': data.get('totalReports', 0)
                }
        except Exception as e:
            print(f"AbuseIPDB API error: {e}")
        
        return None

    def _check_virustotal_ip(self, ip: str) -> Optional[Dict]:
        """Query VirusTotal IP API"""
        if not self.vt_api_key:
            return None
        
        try:
            url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip}'
            headers = {'x-apikey': self.vt_api_key}
            
            response = requests.get(url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json().get('data', {}).get('attributes', {})
                last_analysis = data.get('last_analysis_stats', {})
                
                return {
                    'malicious_count': last_analysis.get('malicious', 0),
                    'suspicious_count': last_analysis.get('suspicious', 0),
                    'harmless_count': last_analysis.get('harmless', 0),
                    'reputation': data.get('reputation', 0)
                }
        except Exception as e:
            print(f"VirusTotal IP API error: {e}")
        
        return None

    def _check_virustotal_url(self, url: str) -> Optional[Dict]:
        """Query VirusTotal URL API"""
        if not self.vt_api_key:
            return None
        
        try:
            # Submit URL for analysis
            submit_url = 'https://www.virustotal.com/api/v3/urls'
            headers = {'x-apikey': self.vt_api_key}
            data = {'url': url}
            
            response = requests.post(submit_url, headers=headers, data=data, timeout=10)
            
            if response.status_code == 200:
                analysis_id = response.json().get('data', {}).get('id')
                
                # Wait briefly then check results
                time.sleep(2)
                
                result_url = f'https://www.virustotal.com/api/v3/analyses/{analysis_id}'
                result_response = requests.get(result_url, headers=headers, timeout=10)
                
                if result_response.status_code == 200:
                    stats = result_response.json().get('data', {}).get('attributes', {}).get('stats', {})
                    return {
                        'malicious_count': stats.get('malicious', 0),
                        'suspicious_count': stats.get('suspicious', 0),
                        'harmless_count': stats.get('harmless', 0)
                    }
        except Exception as e:
            print(f"VirusTotal URL API error: {e}")
        
        return None

    def _check_virustotal_domain(self, domain: str) -> Optional[Dict]:
        """Query VirusTotal Domain API"""
        if not self.vt_api_key:
            return None
        
        try:
            url = f'https://www.virustotal.com/api/v3/domains/{domain}'
            headers = {'x-apikey': self.vt_api_key}
            
            response = requests.get(url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json().get('data', {}).get('attributes', {})
                last_analysis = data.get('last_analysis_stats', {})
                
                return {
                    'malicious_count': last_analysis.get('malicious', 0),
                    'suspicious_count': last_analysis.get('suspicious', 0),
                    'harmless_count': last_analysis.get('harmless', 0),
                    'reputation': data.get('reputation', 0),
                    'categories': data.get('categories', {})
                }
        except Exception as e:
            print(f"VirusTotal Domain API error: {e}")
        
        return None

    def _check_virustotal_hash(self, file_hash: str) -> Optional[Dict]:
        """Query VirusTotal File Hash API"""
        if not self.vt_api_key:
            return None
        
        try:
            url = f'https://www.virustotal.com/api/v3/files/{file_hash}'
            headers = {'x-apikey': self.vt_api_key}
            
            response = requests.get(url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json().get('data', {}).get('attributes', {})
                last_analysis = data.get('last_analysis_stats', {})
                
                return {
                    'malicious_count': last_analysis.get('malicious', 0),
                    'suspicious_count': last_analysis.get('suspicious', 0),
                    'file_type': data.get('type_description', ''),
                    'names': data.get('names', [])
                }
        except Exception as e:
            print(f"VirusTotal Hash API error: {e}")
        
        return None

    def _check_local_blacklist(self, url: str) -> bool:
        """Check against local phishing blacklist"""
        # Load local blacklist from file
        try:
            with open('./data/intel_db.json', 'r') as f:
                intel_db = json.load(f)
                bad_domains = intel_db.get('bad_domains', [])
                
                for domain in bad_domains:
                    if domain in url:
                        return True
        except:
            pass
        
        return False

    def _analyze_domain(self, domain: str) -> Dict:
        """Perform heuristic domain analysis"""
        
        suspicious_indicators = []

        # Check for suspicious TLDs
        suspicious_tlds = ['.xyz', '.top', '.tk', '.ml', '.ga', '.cf', '.gq']
        if any(domain.endswith(tld) for tld in suspicious_tlds):
            suspicious_indicators.append('Suspicious TLD')
        
        # Check for typosquatting patterns
        common_brands = ['google', 'microsoft', 'amazon', 'paypal', 'apple', 'facebook']
        for brand in common_brands:
            if brand in domain.lower() and not domain.endswith(f'{brand}.com'):
                suspicious_indicators.append(f'Possible {brand} typosquatting')
        
        # Check for excessive hyphens or numbers
        if domain.count('-') > 2 or sum(c.isdigit() for c in domain) > 4:
            suspicious_indicators.append('Suspicious domain structure')
        
        return {
            'is_suspicious': len(suspicious_indicators) > 0,
            'reasons': suspicious_indicators
        }

    # ===== Cache Management =====

    def _get_from_cache(self, ioc_value: str, ioc_type: str) -> Optional[Dict]:
        """Retrieve from cache if not expired"""
        cached = self.db.query(ThreatIntelCache).filter_by(
            ioc_value=ioc_value,
            ioc_type=ioc_type
        ).first()
        
        if cached and cached.expires_at > datetime.utcnow():
            return {
                'ioc_value': cached.ioc_value,
                'ioc_type': cached.ioc_type,
                'is_malicious': cached.is_malicious,
                'reputation_score': cached.reputation_score,
                'sources': cached.raw_response
            }
        
        return None

    def _save_to_cache(self, ioc_value: str, ioc_type: str, results: Dict):
        """Save threat intel results to cache"""
        expires_at = datetime.utcnow() + timedelta(hours=self.cache_ttl_hours)
        
        cached = ThreatIntelCache(
            ioc_value=ioc_value,
            ioc_type=ioc_type,
            reputation_score=results['reputation_score'],
            is_malicious=results['is_malicious'],
            source_api='multiple',
            raw_response=results['sources'],
            expires_at=expires_at
        )
        
        self.db.add(cached)
        self.db.commit()