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
import logging

logger = logging.getLogger(__name__)

class ThreatIntelligence:
    def __init__(self, db: Session):
        """
        Initialize Threat Intelligence service with caching and API integration
        
        Args:
            db: SQLAlchemy database session
        """
        self.db = db
        self.vt_api_key = None 
        self.abuseipdb_api_key = None
        self.cache_ttl_hours = 24
        
        # Optimization: Reuse TCP connections for all API calls
        self.http_session = requests.Session()
        self.http_session.headers.update({'User-Agent': 'PhishGuard-Pro/1.0'})
        
        # Load blacklist once at startup to avoid repeated disk reads
        self.bad_domains = self._load_local_blacklist()
        self.bad_ips = self._load_local_ip_blacklist()
        
        # API rate limiting (requests per minute)
        self.api_call_limits = {
            'virustotal': {'limit': 4, 'window': 60, 'calls': []},
            'abuseipdb': {'limit': 60, 'window': 60, 'calls': []}
        }
    
    def _load_local_blacklist(self) -> List[str]:
        """
        Load local domain blacklist with multiple fallback paths
        
        Returns:
            List of known malicious domains
        """
        try:
            # Try multiple possible paths
            possible_paths = [
                Path(__file__).resolve().parents[2] / 'data' / 'intel_db.json',
                Path.cwd() / 'data' / 'intel_db.json',
                Path('./data/intel_db.json'),
                Path('../data/intel_db.json')
            ]
            
            for file_path in possible_paths:
                if file_path.exists():
                    with open(file_path, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                        domains = data.get('bad_domains', [])
                        logger.info(f"✓ Loaded {len(domains)} domains from: {file_path}")
                        return domains
            
            logger.warning("⚠️ No blacklist file found, using empty list")
            return []
            
        except json.JSONDecodeError as e:
            logger.error(f"❌ JSON decode error in blacklist: {e}")
            return []
        except IOError as e:
            logger.error(f"❌ IO error loading blacklist: {e}")
            return []
        except Exception as e:
            logger.error(f"❌ Unexpected error loading blacklist: {e}")
            return []
    
    def _load_local_ip_blacklist(self) -> List[str]:
        """
        Load local IP blacklist
        
        Returns:
            List of known malicious IPs
        """
        try:
            possible_paths = [
                Path(__file__).resolve().parents[2] / 'data' / 'intel_db.json',
                Path.cwd() / 'data' / 'intel_db.json',
                Path('./data/intel_db.json')
            ]
            
            for file_path in possible_paths:
                if file_path.exists():
                    with open(file_path, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                        ips = data.get('bad_ips', [])
                        if ips:
                            logger.info(f"✓ Loaded {len(ips)} IPs from blacklist")
                        return ips
            
            return []
            
        except Exception as e:
            logger.error(f"❌ Error loading IP blacklist: {e}")
            return []
    
    def _check_rate_limit(self, api_name: str) -> bool:
        """
        Check if API call is within rate limit
        
        Args:
            api_name: Name of the API ('virustotal' or 'abuseipdb')
        
        Returns:
            True if call is allowed, False if rate limited
        """
        if api_name not in self.api_call_limits:
            return True
        
        limit_info = self.api_call_limits[api_name]
        current_time = datetime.utcnow()
        
        # Remove calls outside the time window
        limit_info['calls'] = [
            call_time for call_time in limit_info['calls']
            if (current_time - call_time).total_seconds() < limit_info['window']
        ]
        
        # Check if under limit
        if len(limit_info['calls']) < limit_info['limit']:
            limit_info['calls'].append(current_time)
            return True
        
        return False
    
    def check_ip(self, ip: str) -> Dict:
        """
        Check IP reputation across multiple sources
        
        Args:
            ip: IP address to check
        
        Returns:
            Dictionary with threat intelligence results
        """
        # Validate IP format
        if not self._is_valid_ip(ip):
            return {
                'ioc_value': ip,
                'ioc_type': 'ip',
                'is_malicious': False,
                'reputation_score': 0,
                'threat_categories': [],
                'sources': {},
                'error': 'Invalid IP format'
            }
        
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
        
        # Check local blacklist (instant, no API needed)
        if ip in self.bad_ips:
            results['is_malicious'] = True
            results['reputation_score'] = 100
            results['threat_categories'].append('Local Blacklist')
            results['sources']['local_blacklist'] = {'matched': True}
            self._save_to_cache(ip, 'ip', results)
            return results
        
        # AbuseIPDB check
        if self.abuseipdb_api_key and self._check_rate_limit('abuseipdb'):
            abuse_data = self._check_abuseipdb(ip)
            if abuse_data:
                results['sources']['abuseipdb'] = abuse_data
                results['reputation_score'] += abuse_data.get('abuse_confidence_score', 0)
                if abuse_data.get('is_malicious'):
                    results['is_malicious'] = True
                    results['threat_categories'].extend(abuse_data.get('categories', []))
        
        # VirusTotal check
        if self.vt_api_key and self._check_rate_limit('virustotal'):
            vt_data = self._check_virustotal_ip(ip)
            if vt_data:
                results['sources']['virustotal'] = vt_data
                malicious = vt_data.get('malicious_count', 0)
                if malicious > 2:
                    results['is_malicious'] = True
                    results['reputation_score'] += min(malicious * 10, 50)
        
        # Normalize score
        results['reputation_score'] = min(results['reputation_score'], 100)
        
        # Cache results
        self._save_to_cache(ip, 'ip', results)
        
        return results
    
    def check_url(self, url: str) -> Dict:
        """
        Check URL reputation
        
        Args:
            url: URL to check
        
        Returns:
            Dictionary with threat intelligence results
        """
        # Validate URL
        if not url or len(url) < 8:
            return {
                'ioc_value': url,
                'ioc_type': 'url',
                'is_malicious': False,
                'reputation_score': 0,
                'threat_categories': [],
                'sources': {},
                'error': 'Invalid URL'
            }
        
        # Check cache
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
        
        # Check local blacklist first (instant)
        if self._check_url_in_blacklist(url):
            results['is_malicious'] = True
            results['reputation_score'] = 100
            results['threat_categories'].append('Known Phishing Domain')
            results['sources']['local_blacklist'] = {'matched': True}
            self._save_to_cache(url, 'url', results)
            return results
        
        # VirusTotal URL check
        if self.vt_api_key and self._check_rate_limit('virustotal'):
            vt_data = self._check_virustotal_url(url)
            if vt_data:
                results['sources']['virustotal'] = vt_data
                malicious = vt_data.get('malicious_count', 0)
                suspicious = vt_data.get('suspicious_count', 0)
                
                if malicious >= 2:
                    results['is_malicious'] = True
                    results['reputation_score'] = min(malicious * 15, 100)
                elif suspicious >= 3:
                    results['reputation_score'] = min(suspicious * 10, 60)
        
        # Cache results
        self._save_to_cache(url, 'url', results)
        
        return results
    
    def check_domain(self, domain: str) -> Dict:
        """
        Check domain reputation
        
        Args:
            domain: Domain to check
        
        Returns:
            Dictionary with threat intelligence results
        """
        # Clean domain
        domain = domain.lower().strip()
        
        # Check cache
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
        
        # Check local blacklist
        if domain in self.bad_domains:
            results['is_malicious'] = True
            results['reputation_score'] = 100
            results['threat_categories'].append('Known Phishing Domain')
            results['sources']['local_blacklist'] = {'matched': True}
            self._save_to_cache(domain, 'domain', results)
            return results
        
        # VirusTotal domain check
        if self.vt_api_key and self._check_rate_limit('virustotal'):
            vt_data = self._check_virustotal_domain(domain)
            if vt_data:
                results['sources']['virustotal'] = vt_data
                malicious = vt_data.get('malicious_count', 0)
                if malicious > 2:
                    results['is_malicious'] = True
                    results['reputation_score'] = min(malicious * 15, 100)
        
        # Cache results
        self._save_to_cache(domain, 'domain', results)
        
        return results
    
    def check_file_hash(self, file_hash: str) -> Dict:
        """
        Check file hash reputation
        
        Args:
            file_hash: SHA256 hash of file
        
        Returns:
            Dictionary with threat intelligence results
        """
        # Validate hash format
        if not file_hash or len(file_hash) != 64:
            return {
                'ioc_value': file_hash,
                'ioc_type': 'hash',
                'is_malicious': False,
                'reputation_score': 0,
                'threat_categories': [],
                'sources': {},
                'error': 'Invalid hash format'
            }
        
        # Check cache
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
        
        # VirusTotal file hash check
        if self.vt_api_key and self._check_rate_limit('virustotal'):
            vt_data = self._check_virustotal_hash(file_hash)
            if vt_data:
                results['sources']['virustotal'] = vt_data
                malicious = vt_data.get('malicious_count', 0)
                if malicious > 5:
                    results['is_malicious'] = True
                    results['reputation_score'] = 100
                elif malicious > 0:
                    results['reputation_score'] = min(malicious * 10, 80)
        
        # Cache results
        self._save_to_cache(file_hash, 'hash', results)
        
        return results
    
    # ===== Helper Methods =====
    
    def _is_valid_ip(self, ip: str) -> bool:
        """Validate IP address format"""
        import re
        ip_pattern = re.compile(
            r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
            r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        )
        return bool(ip_pattern.match(ip))
    
    def _check_url_in_blacklist(self, url: str) -> bool:
        """Check if URL contains blacklisted domain"""
        url_lower = url.lower()
        for domain in self.bad_domains:
            if domain in url_lower:
                return True
        return False
    
    # ===== API Implementation Methods =====
    
    def _check_abuseipdb(self, ip: str) -> Optional[Dict]:
        """
        Query AbuseIPDB API with connection pooling and error handling
        
        Args:
            ip: IP address to check
        
        Returns:
            Dictionary with AbuseIPDB results or None
        """
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
            
            response = self.http_session.get(
                url,
                headers=headers,
                params=params,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json().get('data', {})
                return {
                    'abuse_confidence_score': data.get('abuseConfidenceScore', 0),
                    'is_malicious': data.get('abuseConfidenceScore', 0) > 50,
                    'categories': [str(data.get('usageType', ''))],
                    'total_reports': data.get('totalReports', 0),
                    'last_reported': data.get('lastReportedAt', '')
                }
            elif response.status_code == 429:
                logger.warning("⚠️ AbuseIPDB rate limit exceeded")
                return None
            elif response.status_code == 401:
                logger.error("❌ AbuseIPDB authentication failed (invalid API key)")
                return None
            else:
                logger.warning(f"⚠️ AbuseIPDB returned status code: {response.status_code}")
                return None
                
        except requests.Timeout:
            logger.warning("⚠️ AbuseIPDB request timeout")
            return None
        except requests.RequestException as e:
            logger.error(f"❌ AbuseIPDB request error: {e}")
            return None
        except Exception as e:
            logger.error(f"❌ Unexpected error in AbuseIPDB check: {e}")
            return None
    
    def _check_virustotal_ip(self, ip: str) -> Optional[Dict]:
        """Query VirusTotal IP API"""
        try:
            url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip}'
            headers = {'x-apikey': self.vt_api_key}
            
            response = self.http_session.get(url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json().get('data', {}).get('attributes', {})
                last_analysis = data.get('last_analysis_stats', {})
                
                return {
                    'malicious_count': last_analysis.get('malicious', 0),
                    'suspicious_count': last_analysis.get('suspicious', 0),
                    'harmless_count': last_analysis.get('harmless', 0),
                    'reputation': data.get('reputation', 0)
                }
            elif response.status_code == 404:
                # IP not found in VirusTotal
                return {'malicious_count': 0, 'suspicious_count': 0, 'harmless_count': 0}
            elif response.status_code == 429:
                logger.warning("⚠️ VirusTotal rate limit exceeded")
                return None
                
        except requests.RequestException as e:
            logger.error(f"❌ VirusTotal IP check error: {e}")
            return None
        except Exception as e:
            logger.error(f"❌ Unexpected error in VirusTotal IP check: {e}")
            return None
        
        return None
    
    def _check_virustotal_url(self, url: str) -> Optional[Dict]:
        """
        Check VirusTotal for existing URL report (no scan submission)
        
        Args:
            url: URL to check
        
        Returns:
            Dictionary with VirusTotal results or None
        """
        try:
            # Encode URL for VirusTotal API
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
            endpoint = f'https://www.virustotal.com/api/v3/urls/{url_id}'
            headers = {'x-apikey': self.vt_api_key}
            
            response = self.http_session.get(endpoint, headers=headers, timeout=10)
            
            if response.status_code == 200:
                stats = response.json().get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                return {
                    'malicious_count': stats.get('malicious', 0),
                    'suspicious_count': stats.get('suspicious', 0),
                    'harmless_count': stats.get('harmless', 0),
                    'undetected_count': stats.get('undetected', 0)
                }
            elif response.status_code == 404:
                # URL not found - not necessarily safe, just not analyzed yet
                return {'malicious_count': 0, 'suspicious_count': 0, 'harmless_count': 0}
                
        except requests.RequestException as e:
            logger.error(f"❌ VirusTotal URL check error: {e}")
            return None
        except Exception as e:
            logger.error(f"❌ Unexpected error in VirusTotal URL check: {e}")
            return None
        
        return None
    
    def _check_virustotal_domain(self, domain: str) -> Optional[Dict]:
        """Query VirusTotal Domain API"""
        try:
            url = f'https://www.virustotal.com/api/v3/domains/{domain}'
            headers = {'x-apikey': self.vt_api_key}
            
            response = self.http_session.get(url, headers=headers, timeout=10)
            
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
            elif response.status_code == 404:
                return {'malicious_count': 0, 'suspicious_count': 0, 'harmless_count': 0}
                
        except requests.RequestException as e:
            logger.error(f"❌ VirusTotal domain check error: {e}")
            return None
        except Exception as e:
            logger.error(f"❌ Unexpected error in VirusTotal domain check: {e}")
            return None
        
        return None
    
    def _check_virustotal_hash(self, file_hash: str) -> Optional[Dict]:
        """Query VirusTotal File Hash API"""
        try:
            url = f'https://www.virustotal.com/api/v3/files/{file_hash}'
            headers = {'x-apikey': self.vt_api_key}
            
            response = self.http_session.get(url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json().get('data', {}).get('attributes', {})
                last_analysis = data.get('last_analysis_stats', {})
                
                return {
                    'malicious_count': last_analysis.get('malicious', 0),
                    'suspicious_count': last_analysis.get('suspicious', 0),
                    'file_type': data.get('type_description', ''),
                    'names': data.get('names', [])[:5]  # Limit to 5 names
                }
            elif response.status_code == 404:
                # Hash not found in VirusTotal
                return {'malicious_count': 0, 'suspicious_count': 0}
                
        except requests.RequestException as e:
            logger.error(f"❌ VirusTotal hash check error: {e}")
            return None
        except Exception as e:
            logger.error(f"❌ Unexpected error in VirusTotal hash check: {e}")
            return None
        
        return None
    
    # ===== Cache Management Methods =====
    
    def _get_from_cache(self, ioc_value: str, ioc_type: str) -> Optional[Dict]:
        """
        Retrieve IOC data from cache if not expired
        
        Args:
            ioc_value: The IOC value (IP, URL, domain, etc.)
            ioc_type: Type of IOC ('ip', 'url', 'domain', 'hash')
        
        Returns:
            Cached data or None if not found/expired
        """
        try:
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
                    'sources': cached.raw_response or {},
                    'threat_categories': [],
                    'cached': True
                }
        except SQLAlchemyError as e:
            logger.error(f"❌ Cache retrieval error: {e}")
        except Exception as e:
            logger.error(f"❌ Unexpected cache error: {e}")
        
        return None
    
    def _save_to_cache(self, ioc_value: str, ioc_type: str, results: Dict):
        """
        Save threat intelligence results to cache
        
        Args:
            ioc_value: The IOC value
            ioc_type: Type of IOC
            results: Analysis results to cache
        """
        try:
            expires_at = datetime.utcnow() + timedelta(hours=self.cache_ttl_hours)
            
            # Check if entry already exists
            existing = self.db.query(ThreatIntelCache).filter_by(
                ioc_value=ioc_value,
                ioc_type=ioc_type
            ).first()
            
            if existing:
                # Update existing entry
                existing.reputation_score = results['reputation_score']
                existing.is_malicious = results['is_malicious']
                existing.raw_response = results.get('sources', {})
                existing.expires_at = expires_at
            else:
                # Create new entry
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
            logger.error(f"❌ Database error saving cache: {e}")
        except Exception as e:
            self.db.rollback()
            logger.error(f"❌ Unexpected error saving cache: {e}")
    
    def clear_expired_cache(self):
        """Clear expired cache entries (maintenance task)"""
        try:
            deleted = self.db.query(ThreatIntelCache).filter(
                ThreatIntelCache.expires_at < datetime.utcnow()
            ).delete()
            
            self.db.commit()
            logger.info(f"✓ Cleared {deleted} expired cache entries")
            
        except SQLAlchemyError as e:
            self.db.rollback()
            logger.error(f"❌ Error clearing cache: {e}")
    
    def get_cache_stats(self) -> Dict:
        """Get cache statistics"""
        try:
            total = self.db.query(ThreatIntelCache).count()
            malicious = self.db.query(ThreatIntelCache).filter_by(is_malicious=True).count()
            
            return {
                'total_entries': total,
                'malicious_entries': malicious,
                'clean_entries': total - malicious
            }
        except SQLAlchemyError as e:
            logger.error(f"❌ Error getting cache stats: {e}")
            return {'total_entries': 0, 'malicious_entries': 0, 'clean_entries': 0}