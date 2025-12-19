from pydantic_settings import BaseSettings
from typing import Optional

class Settings(BaseSettings):
    # API Configuration
    APP_NAME: str = "PhishGuard Pro"
    VERSION: str = "1.0.0"
    API_PREFIX: str = "/api/v1"
    DEBUG: bool = True
    
    # MySQL Database - CHANGED
    DATABASE_URL: str = "mysql+pymysql://root:your_mysql_password@localhost:3306/phishguard"
    
    # Threat Intelligence API Keys
    VIRUSTOTAL_API_KEY: Optional[str] = None
    ABUSEIPDB_API_KEY: Optional[str] = None
    URLHAUS_API_KEY: Optional[str] = None
    
    # Analysis Settings
    MAX_EMAIL_SIZE_MB: int = 25
    MAX_ATTACHMENT_SIZE_MB: int = 10
    ATTACHMENT_SCAN_TIMEOUT: int = 30
    
    # Risk Scoring Thresholds
    MALICIOUS_THRESHOLD: int = 70
    SUSPICIOUS_THRESHOLD: int = 40
    
    # ML Model
    ML_MODEL_PATH: str = "./models/phishing_model.pkl"
    ML_VECTORIZER_PATH: str = "./models/vectorizer.pkl"
    
    class Config:
        env_file = ".env"
        case_sensitive = True

settings = Settings()