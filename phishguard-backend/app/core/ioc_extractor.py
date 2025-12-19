import re
import hashlib
from email import policy
from email.parser import BytesParser
from typing import Dict, List, Set
from bs4 import BeautifulSoup
import tldextract

class IOCExtractor:
    def __init__(self):
        # Regex patterns
        self.ip_pattern = re.compile(
            r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
            r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        )
        
        self.url_pattern = re.compile(
            r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|'
            r'(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        )
        
        self.email_pattern = re.compile(
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        )
        
        self.domain_pattern = re.compile(
            r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
        )
        
        self.md5_pattern = re.compile(r'\b[a-fA-F0-9]{32}\b')
        self.sha1_pattern = re.compile(r'\b[a-fA-F0-9]{40}\b')
        self.sha256_pattern = re.compile(r'\b[a-fA-F0-9]{64}\b')

    def extract_from_raw_email(self, raw_email: bytes) -> Dict:
        """Extract IOCs from raw email bytes"""
        msg = BytesParser(policy=policy.default).parsebytes(raw_email)
        
        # Extract text content
        body_text = self._get_email_body(msg)
        
        # Extract from headers
        headers = self._extract_header_iocs(msg)
        
        # Extract from body
        body_iocs = self._extract_from_text(body_text)
        
        # Extract attachments
        attachments = self._extract_attachments(msg)
        
        return {
            'sender': msg.get('from', ''),
            'recipient': msg.get('to', ''),
            'subject': msg.get('subject', ''),
            'headers': headers,
            'body': body_text[:5000],  # Truncate for storage
            'ips': list(set(headers['ips'] + body_iocs['ips'])),
            'urls': list(set(body_iocs['urls'])),
            'domains': list(set(headers['domains'] + body_iocs['domains'])),
            'email_addresses': list(set(body_iocs['emails'])),
            'hashes': body_iocs['hashes'],
            'attachments': attachments
        }

    def _get_email_body(self, msg) -> str:
        """Extract plain text and HTML body"""
        body = ""
        
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                if content_type == "text/plain":
                    body += part.get_content()
                elif content_type == "text/html":
                    html_body = part.get_content()
                    body += self._extract_text_from_html(html_body)
        else:
            body = msg.get_content()
            
        return body

    def _extract_text_from_html(self, html: str) -> str:
        """Extract text from HTML content"""
        try:
            soup = BeautifulSoup(html, 'lxml')
            return soup.get_text(separator=' ')
        except:
            return html

    def _extract_header_iocs(self, msg) -> Dict:
        """Extract IOCs from email headers"""
        header_text = ""
        for header in ['Received', 'X-Originating-IP', 'X-Sender', 'Return-Path']:
            if header in msg:
                header_text += str(msg[header])
        
        ips = self.ip_pattern.findall(header_text)
        
        # Extract sender domain
        sender = msg.get('from', '')
        sender_domain = self._extract_domain_from_email(sender)
        
        return {
            'ips': ips,
            'domains': [sender_domain] if sender_domain else [],
            'sender': sender,
            'return_path': msg.get('Return-Path', '')
        }

    def _extract_from_text(self, text: str) -> Dict:
        """Extract IOCs from text content"""
        # Defang common obfuscations
        text = self._defang(text)
        
        ips = self.ip_pattern.findall(text)
        urls = self.url_pattern.findall(text)
        emails = self.email_pattern.findall(text)
        
        # Extract domains from URLs
        domains = []
        for url in urls:
            domain = self._extract_domain_from_url(url)
            if domain:
                domains.append(domain)
        
        # Extract standalone domains
        potential_domains = self.domain_pattern.findall(text)
        domains.extend([d for d in potential_domains if self._is_valid_domain(d)])
        
        # Extract file hashes
        hashes = {
            'md5': self.md5_pattern.findall(text),
            'sha1': self.sha1_pattern.findall(text),
            'sha256': self.sha256_pattern.findall(text)
        }
        
        return {
            'ips': ips,
            'urls': urls,
            'domains': list(set(domains)),
            'emails': emails,
            'hashes': hashes
        }

    def _extract_attachments(self, msg) -> List[Dict]:
        """Extract attachment metadata"""
        attachments = []
        
        for part in msg.walk():
            if part.get_content_disposition() == 'attachment':
                filename = part.get_filename()
                content = part.get_content()
                
                if isinstance(content, bytes):
                    file_hash = hashlib.sha256(content).hexdigest()
                    file_size = len(content)
                    
                    attachments.append({
                        'filename': filename,
                        'size': file_size,
                        'sha256': file_hash,
                        'content_type': part.get_content_type(),
                        'content': content  # For further analysis
                    })
        
        return attachments

    def _defang(self, text: str) -> str:
        """Convert defanged IOCs to normal format"""
        text = text.replace('[.]', '.')
        text = text.replace('hxxp', 'http')
        text = text.replace('[:]', ':')
        return text

    def _extract_domain_from_email(self, email: str) -> str:
        """Extract domain from email address"""
        match = re.search(r'@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', email)
        return match.group(1) if match else ""

    def _extract_domain_from_url(self, url: str) -> str:
        """Extract domain from URL"""
        try:
            extracted = tldextract.extract(url)
            return f"{extracted.domain}.{extracted.suffix}"
        except:
            return ""

    def _is_valid_domain(self, domain: str) -> bool:
        """Validate if string is a valid domain"""
        # Filter out common false positives
        invalid_patterns = [
            r'^\d+\.\d+$',  # Version numbers
            r'^localhost',
            r'example\.com$',
        ]
        
        for pattern in invalid_patterns:
            if re.match(pattern, domain):
                return False
        
        return '.' in domain and len(domain) > 4