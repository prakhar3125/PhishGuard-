import time
import logging
from typing import Callable
from sqlalchemy.orm import Session

from app.services.email_service import EmailService, create_email_service
from app.services.analysis_service import AnalysisService
from app.database import SessionLocal

logger = logging.getLogger(__name__)

class EmailMonitor:
    """
    Monitors email inbox and automatically analyzes suspicious emails
    """
    
    def __init__(self, 
                 provider: str,
                 email_address: str,
                 password: str,
                 check_interval: int = 60,
                 auto_quarantine: bool = True):
        """
        Initialize email monitor
        
        Args:
            provider: Email provider ('gmail', 'office365', 'imap')
            email_address: Email account to monitor
            password: Account password
            check_interval: Seconds between checks
            auto_quarantine: Automatically move malicious emails
        """
        self.email_service = create_email_service(provider, email_address, password)
        self.check_interval = check_interval
        self.auto_quarantine = auto_quarantine
        self.running = False
    
    def start_monitoring(self):
        """Start continuous email monitoring"""
        logger.info("🔍 Starting email monitoring...")
        self.running = True
        
        while self.running:
            try:
                self._check_and_analyze()
                time.sleep(self.check_interval)
            
            except KeyboardInterrupt:
                logger.info("Monitoring stopped by user")
                self.running = False
            
            except Exception as e:
                logger.error(f"Monitoring error: {e}")
                time.sleep(self.check_interval)
    
    def stop_monitoring(self):
        """Stop monitoring"""
        self.running = False
        self.email_service.disconnect()
    
    def _check_and_analyze(self):
        """Check for new emails and analyze them"""
        # Get database session
        db = SessionLocal()
        
        try:
            # Fetch unread emails
            emails = self.email_service.fetch_unread_emails(limit=10)
            
            if not emails:
                return
            
            logger.info(f"Found {len(emails)} new emails")
            
            # Analyze each email
            analysis_service = AnalysisService(db)
            
            for email_data in emails:
                try:
                    logger.info(f"Analyzing: {email_data['subject']}")
                    
                    # Perform analysis
                    result = analysis_service.analyze_email(
                        email_data['raw_email'],
                        email_id=email_data['email_id']
                    )
                    
                    # Take action based on verdict
                    self._handle_verdict(email_data, result)
                    
                except Exception as e:
                    logger.error(f"Analysis failed for email {email_data['subject']}: {e}")
            
        finally:
            db.close()
    
    def _handle_verdict(self, email_data: dict, analysis_result: dict):
        """Handle email based on analysis verdict"""
        verdict = analysis_result['verdict']
        
        if verdict == 'MALICIOUS' and self.auto_quarantine:
            logger.warning(f"🚨 MALICIOUS email detected: {email_data['subject']}")
            self.email_service.move_to_folder(
                email_data['email_id'].encode(),
                'Quarantine'
            )
        
        elif verdict == 'SUSPICIOUS':
            logger.warning(f"⚠️ SUSPICIOUS email: {email_data['subject']}")
            # Could move to a review folder
        
        else:
            logger.info(f"✓ CLEAN email: {email_data['subject']}")
            self.email_service.mark_as_read(email_data['email_id'].encode())


# ===== CLI Entry Point =====

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='PhishGuard Email Monitor')
    parser.add_argument('--provider', required=True, choices=['gmail', 'office365', 'imap'])
    parser.add_argument('--email', required=True, help='Email address to monitor')
    parser.add_argument('--password', required=True, help='Email password')
    parser.add_argument('--interval', type=int, default=60, help='Check interval in seconds')
    
    args = parser.parse_args()
    
    monitor = EmailMonitor(
        provider=args.provider,
        email_address=args.email,
        password=args.password,
        check_interval=args.interval
    )
    
    monitor.start_monitoring()