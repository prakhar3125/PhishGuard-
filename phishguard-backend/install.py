"""
PhishGuard Pro - Installation Script
Sets up MySQL database and creates necessary directories
"""

import os
import sys
import subprocess

def install_dependencies():
    """Install Python dependencies"""
    print("📦 Installing Python dependencies...")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
        print("✓ Dependencies installed\n")
    except Exception as e:
        print(f"✗ Error installing dependencies: {e}")
        return False
    return True

def create_directories():
    """Create necessary directories"""
    print("📁 Creating directories...")
    directories = [
        'data',
        'data/mock_emails',
        'models',
        'logs'
    ]
    
    for directory in directories:
        os.makedirs(directory, exist_ok=True)
        print(f"  ✓ {directory}/")
    
    print()

def create_mock_data():
    """Create mock threat intelligence database"""
    print("📝 Creating mock data...")
    
    intel_db = {
        "bad_ips": [
            "192.168.6.66",
            "45.33.22.11",
            "185.220.101.1",
            "103.253.145.34"
        ],
        "bad_domains": [
            "phish-login.com",
            "secure-bank-verify.xyz",
            "paypal-security.top",
            "account-verify.ml"
        ],
        "malicious_strings": [
            "AutoOpen",
            "Document_Open",
            "ShellExecute",
            "powershell.exe -enc",
            "WScript.Shell",
            "URLDownloadToFile"
        ]
    }
    
    import json
    with open('data/intel_db.json', 'w') as f:
        json.dump(intel_db, f, indent=2)
    
    print("  ✓ data/intel_db.json")
    print()

def setup_mysql():
    """Setup MySQL database"""
    print("🗄️  Setting up MySQL database...")
    
    try:
        from setup_mysql import create_database
        if create_database():
            print()
            
            # Initialize tables
            print("📊 Creating database tables...")
            from app.database import init_db
            init_db()
            print()
            return True
    except Exception as e:
        print(f"✗ Error setting up MySQL: {e}")
        print("\nPlease ensure:")
        print("1. MySQL is installed and running")
        print("2. Update DATABASE_URL in .env file")
        print("3. MySQL user has proper permissions")
        return False
    
    return True

def create_env_file():
    """Create .env file if it doesn't exist"""
    if os.path.exists('.env'):
        print("✓ .env file already exists\n")
        return
    
    print("📝 Creating .env file...")
    
    env_content = """# MySQL Database Configuration
DATABASE_URL=mysql+pymysql://root:312531@localhost:3306/phishguard

# Threat Intelligence API Keys (Optional)
VIRUSTOTAL_API_KEY=
ABUSEIPDB_API_KEY=

# Application Settings
DEBUG=True
"""
    
    with open('.env', 'w') as f:
        f.write(env_content)
    
    print("  ✓ .env file created")
    print("\n⚠️  IMPORTANT: Edit .env and set your MySQL password!\n")

def main():
    print("=" * 60)
    print("PhishGuard Pro - Installation")
    print("=" * 60)
    print()
    
    # Step 1: Create .env
    create_env_file()
    
    # Step 2: Install dependencies
    if not install_dependencies():
        print("\n⚠️  Dependency installation failed.")
        return
    
    # Step 3: Create directories
    create_directories()
    
    # Step 4: Create mock data
    create_mock_data()
    
    # Step 5: Setup MySQL
    if not setup_mysql():
        print("\n⚠️  MySQL setup incomplete. Please configure manually.")
        return
    
    print("=" * 60)
    print("✓ Installation Complete!")
    print("=" * 60)
    print("\nNext steps:")
    print("1. Edit .env and set your MySQL password")
    print("2. Run: python -m app.main")
    print("3. Visit: http://localhost:8000/docs")
    print()

if __name__ == "__main__":
    main()