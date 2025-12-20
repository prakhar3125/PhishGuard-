#!/usr/bin/env python3
"""
PhishGuard Pro - Threat Intelligence API Testing Script
Tests VirusTotal and AbuseIPDB integration
"""

import sys
import os
from pathlib import Path
from unittest.mock import MagicMock
from datetime import datetime

# ===== ENVIRONMENT SETUP =====
def setup_environment():
    """Load environment and setup paths"""
    print("=" * 70)
    print("🔧 PhishGuard Pro - API Connection Test")
    print("=" * 70)
    
    # Add project root to Python path
    project_root = Path(__file__).resolve().parent
    sys.path.insert(0, str(project_root))
    
    # Try to load .env file
    try:
        from dotenv import load_dotenv
        
        # Try multiple .env locations
        possible_env_paths = [
            project_root / '.env',
            Path.cwd() / '.env',
            Path('./phishguard-backend/.env')
        ]
        
        env_loaded = False
        for env_path in possible_env_paths:
            if env_path.exists():
                print(f"\n📂 Found .env file at: {env_path}")
                load_dotenv(dotenv_path=env_path, override=True)
                env_loaded = True
                break
        
        if not env_loaded:
            print("\n⚠️  WARNING: No .env file found!")
            print("   Create a .env file in project root with:")
            print("   VIRUSTOTAL_API_KEY=your_key_here")
            print("   ABUSEIPDB_API_KEY=your_key_here")
            
    except ImportError:
        print("\n❌ python-dotenv not installed!")
        print("   Run: pip install python-dotenv")
        sys.exit(1)

def check_api_keys():
    """Check if API keys are configured"""
    print("\n" + "=" * 70)
    print("🔑 Checking API Keys")
    print("=" * 70)
    
    # Import after environment is set up
    from app.config import settings
    
    vt_key = settings.VIRUSTOTAL_API_KEY
    abuse_key = settings.ABUSEIPDB_API_KEY
    
    # VirusTotal
    if vt_key:
        print(f"✅ VirusTotal API Key: Found (starts with {vt_key[:8]}...)")
    else:
        print("❌ VirusTotal API Key: NOT FOUND")
        print("   Set VIRUSTOTAL_API_KEY in .env file")
    
    # AbuseIPDB
    if abuse_key:
        print(f"✅ AbuseIPDB API Key: Found (starts with {abuse_key[:8]}...)")
    else:
        print("❌ AbuseIPDB API Key: NOT FOUND")
        print("   Set ABUSEIPDB_API_KEY in .env file")
    
    if not vt_key and not abuse_key:
        print("\n⚠️  No API keys configured. Tests will use local blacklist only.")
        return False
    
    return True

def initialize_threat_intel():
    """Initialize ThreatIntelligence module with mock database"""
    from app.core.threat_intel import ThreatIntelligence
    
    print("\n" + "=" * 70)
    print("🚀 Initializing Threat Intelligence Module")
    print("=" * 70)
    
    # Create mock database session
    mock_db = MagicMock()
    
    # Mock cache to always return None (force API calls)
    mock_db.query.return_value.filter_by.return_value.first.return_value = None
    
    # Mock successful commit
    mock_db.commit.return_value = None
    
    try:
        ti = ThreatIntelligence(db=mock_db)
        print("✅ Module initialized successfully")
        print(f"   Loaded {len(ti.bad_domains)} domains from blacklist")
        print(f"   Loaded {len(ti.bad_ips)} IPs from blacklist")
        return ti
    except Exception as e:
        print(f"❌ Initialization failed: {e}")
        import traceback
        traceback.print_exc()
        return None

def test_local_blacklist(ti):
    """Test local blacklist functionality"""
    print("\n" + "=" * 70)
    print("📋 Testing Local Blacklist")
    print("=" * 70)
    
    # Test malicious domain from blacklist
    test_domain = "phish-login.com"
    print(f"\n🔍 Checking blacklisted domain: {test_domain}")
    
    try:
        result = ti.check_domain(test_domain)
        
        print(f"   ► Malicious: {result.get('is_malicious')}")
        print(f"   ► Score: {result.get('reputation_score')}/100")
        print(f"   ► Categories: {result.get('threat_categories')}")
        
        if result.get('is_malicious'):
            print("   ✅ SUCCESS: Local blacklist working!")
        else:
            print("   ⚠️  WARNING: Blacklisted domain not flagged")
    
    except Exception as e:
        print(f"   ❌ FAILED: {e}")
        import traceback
        traceback.print_exc()

def test_virustotal(ti):
    """Test VirusTotal API integration"""
    print("\n" + "=" * 70)
    print("🦠 Testing VirusTotal API")
    print("=" * 70)
    
    if not ti.vt_api_key:
        print("⚠️  VirusTotal API key not configured - Skipping")
        return
    
    # Test cases
    test_cases = [
        {
            'type': 'url',
            'value': 'https://malware.wicar.org/data/eicar.com',
            'description': 'Known malware test URL'
        },
        {
            'type': 'domain',
            'value': 'google.com',
            'description': 'Legitimate domain (Google)'
        },
        {
            'type': 'ip',
            'value': '8.8.8.8',
            'description': 'Google DNS (Safe)'
        }
    ]
    
    for i, test in enumerate(test_cases, 1):
        print(f"\n{'─' * 70}")
        print(f"Test {i}: {test['description']}")
        print(f"{'─' * 70}")
        print(f"🔍 Checking {test['type'].upper()}: {test['value']}")
        
        try:
            # Call appropriate check method
            if test['type'] == 'url':
                result = ti.check_url(test['value'])
            elif test['type'] == 'domain':
                result = ti.check_domain(test['value'])
            elif test['type'] == 'ip':
                result = ti.check_ip(test['value'])
            
            # Display results
            print(f"   ► Malicious: {result.get('is_malicious')}")
            print(f"   ► Reputation Score: {result.get('reputation_score')}/100")
            print(f"   ► Threat Categories: {result.get('threat_categories')}")
            
            # Check if VirusTotal data is present
            sources = result.get('sources', {})
            if 'virustotal' in sources:
                vt_data = sources['virustotal']
                print(f"   ► VirusTotal Results:")
                print(f"      • Malicious: {vt_data.get('malicious_count', 0)}")
                print(f"      • Suspicious: {vt_data.get('suspicious_count', 0)}")
                print(f"      • Harmless: {vt_data.get('harmless_count', 0)}")
                print("   ✅ SUCCESS: VirusTotal data retrieved!")
            else:
                print("   ⚠️  No VirusTotal data (may not be in their database)")
        
        except Exception as e:
            print(f"   ❌ FAILED: {e}")
            import traceback
            traceback.print_exc()

def test_abuseipdb(ti):
    """Test AbuseIPDB API integration"""
    print("\n" + "=" * 70)
    print("🚫 Testing AbuseIPDB API")
    print("=" * 70)
    
    if not ti.abuseipdb_api_key:
        print("⚠️  AbuseIPDB API key not configured - Skipping")
        return
    
    # Test cases
    test_ips = [
        {
            'ip': '118.25.6.39',
            'description': 'Known malicious IP (Chinese bot network)'
        },
        {
            'ip': '8.8.8.8',
            'description': 'Google DNS (Safe)'
        },
        {
            'ip': '185.220.101.1',
            'description': 'Tor exit node (suspicious activity)'
        }
    ]
    
    for i, test in enumerate(test_ips, 1):
        print(f"\n{'─' * 70}")
        print(f"Test {i}: {test['description']}")
        print(f"{'─' * 70}")
        print(f"🔍 Checking IP: {test['ip']}")
        
        try:
            result = ti.check_ip(test['ip'])
            
            print(f"   ► Malicious: {result.get('is_malicious')}")
            print(f"   ► Reputation Score: {result.get('reputation_score')}/100")
            
            # Check if AbuseIPDB data is present
            sources = result.get('sources', {})
            if 'abuseipdb' in sources:
                abuse_data = sources['abuseipdb']
                print(f"   ► AbuseIPDB Results:")
                print(f"      • Abuse Confidence: {abuse_data.get('abuse_confidence_score')}%")
                print(f"      • Total Reports: {abuse_data.get('total_reports')}")
                print(f"      • Last Reported: {abuse_data.get('last_reported', 'N/A')}")
                print("   ✅ SUCCESS: AbuseIPDB data retrieved!")
            else:
                print("   ⚠️  No AbuseIPDB data (IP may be clean or not in database)")
        
        except Exception as e:
            print(f"   ❌ FAILED: {e}")
            import traceback
            traceback.print_exc()

def test_file_hash(ti):
    """Test file hash checking (VirusTotal)"""
    print("\n" + "=" * 70)
    print("📦 Testing File Hash Checking")
    print("=" * 70)
    
    if not ti.vt_api_key:
        print("⚠️  VirusTotal API key not configured - Skipping")
        return
    
    # EICAR test file hash (standard malware test file)
    eicar_hash = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
    
    print(f"\n🔍 Checking EICAR test file hash: {eicar_hash[:16]}...")
    
    try:
        result = ti.check_file_hash(eicar_hash)
        
        print(f"   ► Malicious: {result.get('is_malicious')}")
        print(f"   ► Reputation Score: {result.get('reputation_score')}/100")
        
        sources = result.get('sources', {})
        if 'virustotal' in sources:
            vt_data = sources['virustotal']
            print(f"   ► VirusTotal Results:")
            print(f"      • Malicious: {vt_data.get('malicious_count', 0)}")
            print(f"      • File Type: {vt_data.get('file_type', 'Unknown')}")
            print("   ✅ SUCCESS: File hash lookup working!")
        else:
            print("   ⚠️  No VirusTotal data for this hash")
    
    except Exception as e:
        print(f"   ❌ FAILED: {e}")
        import traceback
        traceback.print_exc()

def test_caching(ti):
    """Test caching mechanism"""
    print("\n" + "=" * 70)
    print("💾 Testing Cache Performance")
    print("=" * 70)
    
    test_domain = "example.com"
    
    print(f"\n🔍 First lookup (should hit API): {test_domain}")
    start_time = datetime.now()
    result1 = ti.check_domain(test_domain)
    time1 = (datetime.now() - start_time).total_seconds()
    print(f"   ► Time: {time1:.3f}s")
    print(f"   ► Cached: {result1.get('cached', False)}")
    
    print(f"\n🔍 Second lookup (should hit cache): {test_domain}")
    start_time = datetime.now()
    result2 = ti.check_domain(test_domain)
    time2 = (datetime.now() - start_time).total_seconds()
    print(f"   ► Time: {time2:.3f}s")
    print(f"   ► Cached: {result2.get('cached', False)}")
    
    if time2 < time1:
        speedup = time1 / time2
        print(f"   ✅ SUCCESS: Cache is {speedup:.1f}x faster!")
    else:
        print("   ⚠️  Cache performance unclear (mock DB)")




def main():
    """Main test orchestration"""
    try:
        # Setup
        setup_environment()
        has_keys = check_api_keys()
        
        # Initialize
        ti = initialize_threat_intel()
        if not ti:
            print("\n❌ Cannot proceed - initialization failed")
            return
        
        # Run tests
        test_local_blacklist(ti)
        
        if has_keys:
            test_virustotal(ti)
            test_abuseipdb(ti)
            test_file_hash(ti)
        
        test_caching(ti)
        

        
    except KeyboardInterrupt:
        print("\n\n⚠️  Test interrupted by user")
    except Exception as e:
        print(f"\n\n❌ Unexpected error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()