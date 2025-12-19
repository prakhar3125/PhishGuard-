import sys
import os
from unittest.mock import MagicMock
from pathlib import Path
from dotenv import load_dotenv

# Force load .env
load_dotenv()

sys.path.append(os.getcwd())

from app.config import settings
from app.core.threat_intel import ThreatIntelligence

def test_abuseipdb():
    print("🚀 Initializing AbuseIPDB Test...")
    
    # Check Key
    key = settings.ABUSEIPDB_API_KEY
    print(f"🔑 AbuseIPDB Key Loaded? {'YES' if key else 'NO'}")
    if key:
        print(f"   (Key starts with: {str(key)[:4]}...)")
    else:
        print("   ❌ ERROR: AbuseIPDB Key missing in .env")
        return

    mock_db = MagicMock()
    ti = ThreatIntelligence(db=mock_db)

    print("\n" + "="*50)
    print("📡 Testing AbuseIPDB Connection")
    print("="*50)

    # --- Test: Known Malicious IP (Example: 185.220.101.1 - Common Tor Exit Node) ---
    # This IP is frequently reported for abusive behavior
    test_ip = "185.220.101.1"
    print(f"\n🔍 Checking Suspect IP: {test_ip}")
    
    try:
        result = ti.check_ip(test_ip)
        score = result.get('reputation_score', 0)
        
        print(f"   ► Score: {score}/100")
        print(f"   ► Malicious: {result.get('is_malicious')}")
        
        # Check if AbuseIPDB specifically provided data
        sources = result.get('sources', {})
        if 'abuseipdb' in sources:
            data = sources['abuseipdb']
            print(f"   ► Abuse Confidence Score: {data.get('abuse_confidence_score')}%")
            print(f"   ► Total Reports: {data.get('total_reports')}")
            print("   ✅ SUCCESS: AbuseIPDB data retrieved!")
        else:
            print("   ⚠️ WARNING: No data from AbuseIPDB. Check your API key/limit.")
            
    except Exception as e:
        print(f"   ❌ FAILED: {e}")

if __name__ == "__main__":
    test_abuseipdb()