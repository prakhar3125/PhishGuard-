import imaplib
import email
from email import policy
from email.parser import BytesParser
import time
from typing import List, Dict, Optional
from datetime import datetime
import logging

from app.config import settings

logger = logging.getLogger(__name__)

class EmailService:
    def __init__(self, 
                 imap_server: str = None,
                 email_address: str = None, 
                 password: str = None,
                 port: int = 993):
        """
        Initialize email service for IMAP monitoring
        
        Args:
            imap_server: IMAP server address (e.g., 'imap.gmail.com')
            email_address: Email account to monitor
            password: Email password or app-specific password
            port: IMAP port (default 993 for SSL)
        """
        self.imap_server = imap_server
        self.email_address = email_address
        self.password = password
        self.port = port
        self.connection = None
        self.is_connected = False
    
    def connect(self) -> bool:
        """Connect to IMAP server"""
        try:
            self.connection = imaplib.IMAP4_SSL(self.imap_server, self.port)
            self.connection.login(self.email_address, self.password)
            self.is_connected = True
            logger.info(f"✓ Connected to {self.imap_server} as {self.email_address}")
            return True
        except Exception as e:
            logger.error(f"✗ IMAP connection failed: {e}")
            self.is_connected = False
            return False
    
    def disconnect(self):
        """Disconnect from IMAP server"""
        if self.connection:
            try:
                self.connection.logout()
                logger.info("✓ Disconnected from IMAP server")
            except:
                pass
            self.is_connected = False
    
    def select_mailbox(self, mailbox: str = "INBOX") -> bool:
        """Select mailbox to monitor"""
        if not self.is_connected:
            return False
        
        try:
            self.connection.select(mailbox)
            logger.info(f"✓ Selected mailbox: {mailbox}")
            return True
        except Exception as e:
            logger.error(f"✗ Failed to select mailbox {mailbox}: {e}")
            return False
    
    def fetch_unread_emails(self, limit: int = 10) -> List[Dict]:
        """
        Fetch unread emails from mailbox
        
        Returns:
            List of email dictionaries containing raw email data
        """
        if not self.is_connected:
            logger.error("Not connected to IMAP server")
            return []
        
        emails = []
        
        try:
            # Search for unread emails
            status, messages = self.connection.search(None, 'UNSEEN')
            
            if status != 'OK':
                logger.error("Failed to search for emails")
                return []
            
            email_ids = messages[0].split()
            
            # Limit number of emails to process
            email_ids = email_ids[:limit]
            
            logger.info(f"Found {len(email_ids)} unread emails")
            
            for email_id in email_ids:
                email_data = self._fetch_email_by_id(email_id)
                if email_data:
                    emails.append(email_data)
            
            return emails
        
        except Exception as e:
            logger.error(f"Error fetching emails: {e}")
            return []
    
    def fetch_all_emails(self, limit: int = 50) -> List[Dict]:
        """Fetch all emails (read and unread)"""
        if not self.is_connected:
            logger.error("Not connected to IMAP server")
            return []
        
        emails = []
        
        try:
            status, messages = self.connection.search(None, 'ALL')
            
            if status != 'OK':
                return []
            
            email_ids = messages[0].split()
            
            # Get most recent emails
            email_ids = email_ids[-limit:] if len(email_ids) > limit else email_ids
            
            for email_id in email_ids:
                email_data = self._fetch_email_by_id(email_id)
                if email_data:
                    emails.append(email_data)
            
            return emails
        
        except Exception as e:
            logger.error(f"Error fetching all emails: {e}")
            return []
    
    def fetch_emails_by_criteria(self, 
                                  sender: str = None,
                                  subject: str = None,
                                  since_date: datetime = None,
                                  limit: int = 50) -> List[Dict]:
        """
        Fetch emails matching specific criteria
        
        Args:
            sender: Filter by sender email
            subject: Filter by subject (partial match)
            since_date: Only fetch emails after this date
            limit: Maximum number of emails to fetch
        """
        if not self.is_connected:
            return []
        
        # Build search criteria
        search_criteria = []
        
        if sender:
            search_criteria.append(f'FROM "{sender}"')
        
        if subject:
            search_criteria.append(f'SUBJECT "{subject}"')
        
        if since_date:
            date_str = since_date.strftime("%d-%b-%Y")
            search_criteria.append(f'SINCE {date_str}')
        
        # If no criteria, search all
        search_string = ' '.join(search_criteria) if search_criteria else 'ALL'
        
        try:
            status, messages = self.connection.search(None, search_string)
            
            if status != 'OK':
                return []
            
            email_ids = messages[0].split()
            email_ids = email_ids[:limit]
            
            emails = []
            for email_id in email_ids:
                email_data = self._fetch_email_by_id(email_id)
                if email_data:
                    emails.append(email_data)
            
            return emails
        
        except Exception as e:
            logger.error(f"Error fetching emails by criteria: {e}")
            return []
    
    def _fetch_email_by_id(self, email_id: bytes) -> Optional[Dict]:
        """Fetch a single email by ID"""
        try:
            status, msg_data = self.connection.fetch(email_id, '(RFC822)')
            
            if status != 'OK':
                return None
            
            raw_email = msg_data[0][1]
            
            # Parse email
            msg = BytesParser(policy=policy.default).parsebytes(raw_email)
            
            return {
                'email_id': email_id.decode(),
                'raw_email': raw_email,
                'sender': msg.get('from', ''),
                'recipient': msg.get('to', ''),
                'subject': msg.get('subject', ''),
                'date': msg.get('date', ''),
                'message_id': msg.get('message-id', ''),
                'parsed_message': msg
            }
        
        except Exception as e:
            logger.error(f"Error fetching email {email_id}: {e}")
            return None
    
    def mark_as_read(self, email_id: bytes):
        """Mark email as read"""
        try:
            self.connection.store(email_id, '+FLAGS', '\\Seen')
        except Exception as e:
            logger.error(f"Error marking email as read: {e}")
    
    def move_to_folder(self, email_id: bytes, folder: str):
        """Move email to a specific folder"""
        try:
            self.connection.copy(email_id, folder)
            self.connection.store(email_id, '+FLAGS', '\\Deleted')
            self.connection.expunge()
            logger.info(f"Moved email {email_id} to {folder}")
        except Exception as e:
            logger.error(f"Error moving email to folder: {e}")
    
    def delete_email(self, email_id: bytes):
        """Delete email permanently"""
        try:
            self.connection.store(email_id, '+FLAGS', '\\Deleted')
            self.connection.expunge()
            logger.info(f"Deleted email {email_id}")
        except Exception as e:
            logger.error(f"Error deleting email: {e}")
    
    def monitor_inbox(self, 
                     callback, 
                     interval: int = 60,
                     mailbox: str = "INBOX"):
        """
        Continuously monitor inbox for new emails
        
        Args:
            callback: Function to call when new emails arrive
            interval: Check interval in seconds
            mailbox: Mailbox to monitor
        """
        logger.info(f"Starting inbox monitor (checking every {interval}s)...")
        
        if not self.connect():
            return
        
        if not self.select_mailbox(mailbox):
            self.disconnect()
            return
        
        try:
            while True:
                # Fetch unread emails
                new_emails = self.fetch_unread_emails()
                
                if new_emails:
                    logger.info(f"Processing {len(new_emails)} new emails")
                    
                    for email_data in new_emails:
                        try:
                            # Call the callback function with email data
                            callback(email_data)
                            
                            # Mark as read
                            self.mark_as_read(email_data['email_id'].encode())
                        
                        except Exception as e:
                            logger.error(f"Error processing email: {e}")
                
                # Wait before next check
                time.sleep(interval)
        
        except KeyboardInterrupt:
            logger.info("Inbox monitoring stopped by user")
        
        except Exception as e:
            logger.error(f"Inbox monitoring error: {e}")
        
        finally:
            self.disconnect()


class Office365EmailService(EmailService):
    """
    Extended service for Office 365 / Exchange Online
    Uses EWS (Exchange Web Services) for better integration
    """
    
    def __init__(self, email_address: str, password: str):
        """
        Initialize Office 365 email service
        Requires: pip install exchangelib
        """
        try:
            from exchangelib import Credentials, Account, Configuration, DELEGATE
            
            self.email_address = email_address
            credentials = Credentials(email_address, password)
            
            # Auto-discover Exchange server
            self.account = Account(
                email_address,
                credentials=credentials,
                autodiscover=True,
                access_type=DELEGATE
            )
            
            self.is_connected = True
            logger.info(f"✓ Connected to Office 365 as {email_address}")
        
        except ImportError:
            logger.error("exchangelib not installed. Run: pip install exchangelib")
            self.is_connected = False
        
        except Exception as e:
            logger.error(f"Office 365 connection failed: {e}")
            self.is_connected = False
    
    def fetch_unread_emails(self, limit: int = 10) -> List[Dict]:
        """Fetch unread emails from Office 365"""
        if not self.is_connected:
            return []
        
        try:
            emails = []
            
            # Get unread items from inbox
            for item in self.account.inbox.filter(is_read=False)[:limit]:
                emails.append({
                    'email_id': item.message_id,
                    'raw_email': item.mime_content,
                    'sender': str(item.sender.email_address),
                    'recipient': str(item.to_recipients[0].email_address) if item.to_recipients else '',
                    'subject': item.subject,
                    'date': item.datetime_received,
                    'message_id': item.message_id,
                    'body': item.body,
                    'has_attachments': item.has_attachments,
                    'attachments': [att.name for att in item.attachments] if item.has_attachments else []
                })
            
            return emails
        
        except Exception as e:
            logger.error(f"Error fetching Office 365 emails: {e}")
            return []


class GmailService(EmailService):
    """
    Gmail-specific service with Gmail API support
    Requires Google API credentials
    """
    
    def __init__(self, email_address: str, credentials_file: str = 'credentials.json'):
        """
        Initialize Gmail service using Gmail API
        Requires: pip install google-auth google-auth-oauthlib google-auth-httplib2 google-api-python-client
        """
        try:
            from google.auth.transport.requests import Request
            from google.oauth2.credentials import Credentials
            from google_auth_oauthlib.flow import InstalledAppFlow
            from googleapiclient.discovery import build
            
            SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']
            
            creds = None
            
            # Load credentials
            if os.path.exists('token.json'):
                creds = Credentials.from_authorized_user_file('token.json', SCOPES)
            
            # Authenticate
            if not creds or not creds.valid:
                if creds and creds.expired and creds.refresh_token:
                    creds.refresh(Request())
                else:
                    flow = InstalledAppFlow.from_client_secrets_file(credentials_file, SCOPES)
                    creds = flow.run_local_server(port=0)
                
                # Save credentials
                with open('token.json', 'w') as token:
                    token.write(creds.to_json())
            
            self.service = build('gmail', 'v1', credentials=creds)
            self.email_address = email_address
            self.is_connected = True
            logger.info(f"✓ Connected to Gmail as {email_address}")
        
        except ImportError:
            logger.error("Google API libraries not installed")
            self.is_connected = False
        
        except Exception as e:
            logger.error(f"Gmail API connection failed: {e}")
            self.is_connected = False
    
    def fetch_unread_emails(self, limit: int = 10) -> List[Dict]:
        """Fetch unread emails using Gmail API"""
        if not self.is_connected:
            return []
        
        try:
            import base64
            
            # Get unread messages
            results = self.service.users().messages().list(
                userId='me',
                labelIds=['UNREAD'],
                maxResults=limit
            ).execute()
            
            messages = results.get('messages', [])
            emails = []
            
            for msg in messages:
                # Get full message
                message = self.service.users().messages().get(
                    userId='me',
                    id=msg['id'],
                    format='raw'
                ).execute()
                
                # Decode raw email
                raw_email = base64.urlsafe_b64decode(message['raw'])
                
                # Parse email
                msg_parsed = BytesParser(policy=policy.default).parsebytes(raw_email)
                
                emails.append({
                    'email_id': msg['id'],
                    'raw_email': raw_email,
                    'sender': msg_parsed.get('from', ''),
                    'recipient': msg_parsed.get('to', ''),
                    'subject': msg_parsed.get('subject', ''),
                    'date': msg_parsed.get('date', ''),
                    'message_id': msg_parsed.get('message-id', ''),
                    'parsed_message': msg_parsed
                })
            
            return emails
        
        except Exception as e:
            logger.error(f"Error fetching Gmail emails: {e}")
            return []


# ===== Helper Functions =====

def create_email_service(provider: str, email_address: str, password: str) -> EmailService:
    """
    Factory function to create appropriate email service
    
    Args:
        provider: 'gmail', 'office365', 'imap'
        email_address: Email account
        password: Password or app-specific password
    """
    if provider.lower() == 'gmail':
        return GmailService(email_address)
    
    elif provider.lower() == 'office365':
        return Office365EmailService(email_address, password)
    
    elif provider.lower() == 'imap':
        # Detect IMAP server from email domain
        domain = email_address.split('@')[1]
        
        imap_servers = {
            'gmail.com': 'imap.gmail.com',
            'outlook.com': 'outlook.office365.com',
            'hotmail.com': 'outlook.office365.com',
            'yahoo.com': 'imap.mail.yahoo.com',
            'icloud.com': 'imap.mail.me.com'
        }
        
        imap_server = imap_servers.get(domain, f'imap.{domain}')
        return EmailService(imap_server, email_address, password)
    
    else:
        raise ValueError(f"Unknown email provider: {provider}")


# ===== Example Usage =====

if __name__ == "__main__":
    import os
    
    # Example 1: IMAP monitoring
    def process_email(email_data):
        """Callback function to process incoming emails"""
        print(f"Processing: {email_data['subject']}")
        # Here you would call the analysis service
    
    # Example IMAP connection
    email_service = EmailService(
        imap_server='imap.gmail.com',
        email_address='your-email@gmail.com',
        password='your-app-password'
    )
    
    # Monitor inbox
    # email_service.monitor_inbox(process_email, interval=60)
    
    # Example 2: Fetch specific emails
    if email_service.connect():
        email_service.select_mailbox("INBOX")
        emails = email_service.fetch_unread_emails(limit=5)
        
        for email_data in emails:
            print(f"From: {email_data['sender']}")
            print(f"Subject: {email_data['subject']}")
            print("---")
        
        email_service.disconnect()