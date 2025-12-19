import pymysql
from app.config import settings

def create_database():
    """Create PhishGuard database if it doesn't exist"""
    
    # Parse database URL
    # Format: mysql+pymysql://user:password@host:port/dbname
    db_url = settings.DATABASE_URL.replace('mysql+pymysql://', '')
    
    # Extract credentials
    auth_part, host_part = db_url.split('@')
    username, password = auth_part.split(':')
    host_db = host_part.split('/')
    host, port = host_db[0].split(':') if ':' in host_db[0] else (host_db[0], '3306')
    database_name = host_db[1] if len(host_db) > 1 else 'phishguard'
    
    print(f"Connecting to MySQL at {host}:{port}...")
    
    try:
        # Connect to MySQL server (without database)
        connection = pymysql.connect(
            host=host,
            port=int(port),
            user=username,
            password=password
        )
        
        cursor = connection.cursor()
        
        # Create database if not exists
        cursor.execute(f"CREATE DATABASE IF NOT EXISTS {database_name} CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci")
        print(f"✓ Database '{database_name}' created/verified")
        
        cursor.close()
        connection.close()
        
        print("\n✓ MySQL setup complete!")
        print(f"Database URL: {settings.DATABASE_URL}")
        
    except pymysql.Error as e:
        print(f"✗ MySQL Error: {e}")
        print("\nPlease ensure:")
        print("1. MySQL is running")
        print("2. Username and password are correct")
        print("3. User has CREATE DATABASE permission")
        return False
    
    return True

if __name__ == "__main__":
    create_database()