import re
import hashlib
from email import policy
from email.parser import BytesParser
from typing import Dict, List, Set, Optional, Tuple
from bs4 import BeautifulSoup
import tldextract
from urllib.parse import urlparse, unquote
import logging

logger = logging.getLogger(__name__)


class IOCExtractor:
    """
    Enhanced Indicator of Compromise (IOC) Extractor
    
    Extracts and analyzes security indicators from email messages including:
    - IP addresses (IPv4 and IPv6)
    - URLs and domains
    - Email addresses
    - File hashes (MD5, SHA1, SHA256)
    - Attachments with metadata
    - Bitcoin addresses
    - Phone numbers
    """
    
    def __init__(self):
        # ===== ENHANCED REGEX PATTERNS =====
        
        # IPv4 pattern (unchanged, already good)
        self.ipv4_pattern = re.compile(
            r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
            r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        )
        
        # IPv6 pattern (NEW)
        self.ipv6_pattern = re.compile(
            r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|'
            r'\b(?:[0-9a-fA-F]{1,4}:){1,7}:\b|'
            r'\b::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}\b'
        )
        
        # Enhanced URL pattern with better protocol support
        self.url_pattern = re.compile(
            r'(?:(?:https?|ftp|ftps)://|www\.)'
            r'(?:[a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]+)',
            re.IGNORECASE
        )
        
        # Email pattern (unchanged, already RFC-compliant)
        self.email_pattern = re.compile(
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        )
        
        # Enhanced domain pattern with better TLD support
        self.domain_pattern = re.compile(
            r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
        )
        
        # Hash patterns
        self.md5_pattern = re.compile(r'\b[a-fA-F0-9]{32}\b')
        self.sha1_pattern = re.compile(r'\b[a-fA-F0-9]{40}\b')
        self.sha256_pattern = re.compile(r'\b[a-fA-F0-9]{64}\b')
        
        # Bitcoin address pattern (NEW)
        self.bitcoin_pattern = re.compile(
            r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b|'  # Legacy (P2PKH/P2SH)
            r'\bbc1[a-z0-9]{39,59}\b'  # SegWit (Bech32)
        )
        
        # Phone number pattern (NEW) - International format
        self.phone_pattern = re.compile(
            r'\+?[1-9]\d{0,3}[-.\s]?\(?\d{1,4}\)?[-.\s]?\d{1,4}[-.\s]?\d{1,9}'
        )
        
        # CVE pattern (NEW) - Common Vulnerabilities and Exposures
        self.cve_pattern = re.compile(r'\bCVE-\d{4}-\d{4,7}\b', re.IGNORECASE)
        
        # ===== DEFANGING PATTERNS =====
        self.defang_patterns = [
            (r'\[\.?\]', '.'),
            (r'\[\.\]', '.'),
            (r'\[:\]', ':'),
            (r'hxxp', 'http'),
            (r'hXXp', 'http'),
            (r'h\[tt\]p', 'http'),
            (r'h\*\*p', 'http'),
            (r'\[@\]', '@'),
            (r'\[at\]', '@'),
            (r'\(dot\)', '.'),
            (r'\[dot\]', '.'),
            (r' dot ', '.'),
            (r' at ', '@'),
        ]
        
        # ===== FILTERS FOR FALSE POSITIVES =====
        self.invalid_domain_patterns = [
            r'^\d+\.\d+$',  # Version numbers (1.2, 2.0, etc.)
            r'^localhost',  # Localhost
            r'example\.com$',  # RFC example domains
            r'example\.org$',
            r'example\.net$',
            r'test\.com$',
            r'domain\.com$',
            r'^\d+\.\d+\.\d+$',  # More version numbers
            r'^255\.255\.255\.255$',  # Broadcast
            r'^0\.0\.0\.0$',  # Any address
        ]
        
        # Private/internal IP ranges to filter out
        self.private_ip_ranges = [
            re.compile(r'^10\.'),  # 10.0.0.0/8
            re.compile(r'^172\.(1[6-9]|2[0-9]|3[0-1])\.'),  # 172.16.0.0/12
            re.compile(r'^192\.168\.'),  # 192.168.0.0/16
            re.compile(r'^127\.'),  # 127.0.0.0/8 (loopback)
            re.compile(r'^169\.254\.'),  # 169.254.0.0/16 (link-local)
        ]
        
        # ===== OPTIMIZATION: Pre-compiled sets =====
        self.seen_iocs = {
            'ips': set(),
            'urls': set(),
            'domains': set(),
            'emails': set()
        }

    def extract_from_raw_email(self, raw_email: bytes) -> Dict:
        """
        Extract IOCs from raw email bytes with enhanced analysis
        
        Args:
            raw_email: Raw email bytes
            
        Returns:
            Dictionary containing all extracted IOCs and metadata
        """
        try:
            msg = BytesParser(policy=policy.default).parsebytes(raw_email)
        except Exception as e:
            logger.error(f"Failed to parse email: {e}")
            return self._empty_result()
        
        # Reset seen IOCs for this email
        self._reset_seen_iocs()
        
        # Extract text content
        body_text = self._get_email_body(msg)
        
        # Extract from headers (with enhanced metadata)
        headers = self._extract_header_iocs(msg)
        
        # Extract from body
        body_iocs = self._extract_from_text(body_text)
        
        # Extract attachments
        attachments = self._extract_attachments(msg)
        
        # Combine and deduplicate results
        all_ips = self._deduplicate_ips(headers['ips'] + body_iocs['ips'])
        all_domains = list(set(headers['domains'] + body_iocs['domains']))
        
        # Extract metadata from headers
        email_metadata = self._extract_email_metadata(msg)
        
        return {
            'sender': msg.get('from', ''),
            'recipient': msg.get('to', ''),
            'subject': msg.get('subject', ''),
            'date': msg.get('date', ''),
            'message_id': msg.get('message-id', ''),
            
            # Enhanced metadata
            'metadata': email_metadata,
            'headers': headers,
            'body': body_text[:10000],  # Increased limit
            'body_length': len(body_text),
            
            # IOCs
            'ips': all_ips,
            'ipv6': body_iocs.get('ipv6', []),
            'urls': list(set(body_iocs['urls'])),
            'domains': all_domains,
            'email_addresses': list(set(body_iocs['emails'])),
            'hashes': body_iocs['hashes'],
            'bitcoin_addresses': body_iocs.get('bitcoin_addresses', []),
            'phone_numbers': body_iocs.get('phone_numbers', []),
            'cve_ids': body_iocs.get('cve_ids', []),
            
            # Attachments
            'attachments': attachments,
            'attachment_count': len(attachments),
            'has_attachments': len(attachments) > 0,
            
            # Statistics
            'stats': {
                'ip_count': len(all_ips),
                'url_count': len(body_iocs['urls']),
                'domain_count': len(all_domains),
                'email_count': len(body_iocs['emails']),
                'attachment_count': len(attachments),
                'total_iocs': (
                    len(all_ips) + 
                    len(body_iocs['urls']) + 
                    len(all_domains) +
                    sum(len(v) for v in body_iocs['hashes'].values())
                )
            }
        }

    def _get_email_body(self, msg) -> str:
        """
        Extract plain text and HTML body with improved handling
        """
        body_parts = []
        
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                content_disposition = part.get_content_disposition()
                
                # Skip attachments
                if content_disposition == 'attachment':
                    continue
                
                try:
                    if content_type == "text/plain":
                        body_parts.append(part.get_content())
                    elif content_type == "text/html":
                        html_body = part.get_content()
                        text = self._extract_text_from_html(html_body)
                        body_parts.append(text)
                except Exception as e:
                    logger.warning(f"Error extracting body part: {e}")
        else:
            try:
                content = msg.get_content()
                if msg.get_content_type() == "text/html":
                    body_parts.append(self._extract_text_from_html(content))
                else:
                    body_parts.append(content)
            except Exception as e:
                logger.warning(f"Error extracting non-multipart body: {e}")
        
        return '\n'.join(body_parts)

    def _extract_text_from_html(self, html: str) -> str:
        """
        Extract text from HTML content with URL preservation
        """
        try:
            soup = BeautifulSoup(html, 'lxml')
            
            # Extract URLs from href and src attributes before getting text
            for tag in soup.find_all(['a', 'img', 'script']):
                if tag.name == 'a' and tag.get('href'):
                    tag.string = f" {tag.get('href')} "
                elif tag.get('src'):
                    tag.string = f" {tag.get('src')} "
            
            text = soup.get_text(separator=' ')
            # Clean up excessive whitespace
            text = re.sub(r'\s+', ' ', text)
            return text.strip()
        except Exception as e:
            logger.warning(f"HTML parsing error: {e}")
            # Fallback: strip tags manually
            return re.sub(r'<[^>]+>', ' ', html)

    def _extract_header_iocs(self, msg) -> Dict:
        """
        Extract IOCs from email headers with enhanced metadata
        """
        header_text = ""
        received_ips = []
        
        # Extract from multiple Received headers
        if 'Received' in msg:
            received_headers = msg.get_all('Received', [])
            for received in received_headers:
                header_text += str(received) + " "
                # Extract IPs from Received headers specifically
                ips = self.ipv4_pattern.findall(str(received))
                received_ips.extend(ips)
        
        # Extract from other headers
        for header in ['X-Originating-IP', 'X-Sender-IP', 'X-Sender', 
                       'Return-Path', 'Reply-To', 'X-Mailer']:
            if header in msg:
                header_text += str(msg[header]) + " "
        
        # Extract all IPs from headers
        all_header_ips = self.ipv4_pattern.findall(header_text)
        
        # Filter out private IPs from received chain
        public_ips = self._filter_private_ips(all_header_ips)
        
        # Extract sender domain
        sender = msg.get('from', '')
        sender_domain = self._extract_domain_from_email(sender)
        
        # Extract reply-to domain if different
        reply_to = msg.get('reply-to', '')
        reply_to_domain = self._extract_domain_from_email(reply_to)
        
        domains = []
        if sender_domain:
            domains.append(sender_domain)
        if reply_to_domain and reply_to_domain != sender_domain:
            domains.append(reply_to_domain)
        
        return {
            'ips': public_ips,
            'received_ips': received_ips[:5],  # First 5 hops
            'domains': domains,
            'sender': sender,
            'reply_to': reply_to,
            'return_path': msg.get('Return-Path', ''),
            'x_mailer': msg.get('X-Mailer', ''),
            'sender_mismatch': sender != reply_to if reply_to else False
        }

    def _extract_from_text(self, text: str) -> Dict:
        """
        Extract IOCs from text content with enhanced patterns
        """
        if not text:
            return self._empty_ioc_dict()
        
        # Defang common obfuscations
        text = self._defang(text)
        
        # Extract IPv4 addresses
        ips = self._filter_private_ips(self.ipv4_pattern.findall(text))
        
        # Extract IPv6 addresses (NEW)
        ipv6 = self.ipv6_pattern.findall(text)
        
        # Extract URLs with deduplication
        raw_urls = self.url_pattern.findall(text)
        urls = self._clean_and_deduplicate_urls(raw_urls)
        
        # Extract email addresses
        emails = self.email_pattern.findall(text)
        
        # Extract domains from URLs
        domains = []
        for url in urls:
            domain = self._extract_domain_from_url(url)
            if domain:
                domains.append(domain)
        
        # Extract standalone domains (not in URLs)
        potential_domains = self.domain_pattern.findall(text)
        for domain in potential_domains:
            if self._is_valid_domain(domain) and domain not in domains:
                domains.append(domain)
        
        # Extract file hashes
        hashes = {
            'md5': list(set(self.md5_pattern.findall(text))),
            'sha1': list(set(self.sha1_pattern.findall(text))),
            'sha256': list(set(self.sha256_pattern.findall(text)))
        }
        
        # Extract Bitcoin addresses (NEW)
        bitcoin_addresses = list(set(self.bitcoin_pattern.findall(text)))
        
        # Extract phone numbers (NEW)
        phone_numbers = self._extract_phone_numbers(text)
        
        # Extract CVE IDs (NEW)
        cve_ids = list(set(self.cve_pattern.findall(text)))
        
        return {
            'ips': ips,
            'ipv6': ipv6,
            'urls': urls,
            'domains': list(set(domains)),
            'emails': list(set(emails)),
            'hashes': hashes,
            'bitcoin_addresses': bitcoin_addresses,
            'phone_numbers': phone_numbers,
            'cve_ids': cve_ids
        }

    def _extract_attachments(self, msg) -> List[Dict]:
        """
        Extract attachment metadata with enhanced analysis
        """
        attachments = []
        
        for part in msg.walk():
            if part.get_content_disposition() == 'attachment':
                try:
                    filename = part.get_filename()
                    if not filename:
                        filename = 'unnamed_attachment'
                    
                    content = part.get_content()
                    
                    if isinstance(content, bytes):
                        # Calculate multiple hashes
                        sha256_hash = hashlib.sha256(content).hexdigest()
                        md5_hash = hashlib.md5(content).hexdigest()
                        sha1_hash = hashlib.sha1(content).hexdigest()
                        
                        file_size = len(content)
                        
                        # Extract file extension
                        file_ext = filename.split('.')[-1].lower() if '.' in filename else ''
                        
                        attachments.append({
                            'filename': filename,
                            'size': file_size,
                            'size_kb': round(file_size / 1024, 2),
                            'extension': file_ext,
                            'sha256': sha256_hash,
                            'md5': md5_hash,
                            'sha1': sha1_hash,
                            'content_type': part.get_content_type(),
                            'content': content  # For further analysis
                        })
                except Exception as e:
                    logger.warning(f"Error extracting attachment: {e}")
        
        return attachments

    def _extract_email_metadata(self, msg) -> Dict:
        """
        Extract comprehensive email metadata (NEW)
        """
        return {
            'spf': msg.get('Received-SPF', ''),
            'dkim': msg.get('DKIM-Signature', ''),
            'dmarc': msg.get('Authentication-Results', ''),
            'message_id': msg.get('Message-ID', ''),
            'in_reply_to': msg.get('In-Reply-To', ''),
            'references': msg.get('References', ''),
            'x_mailer': msg.get('X-Mailer', ''),
            'user_agent': msg.get('User-Agent', ''),
            'priority': msg.get('X-Priority', ''),
            'importance': msg.get('Importance', ''),
        }

    def _defang(self, text: str) -> str:
        """
        Convert defanged IOCs to normal format with expanded patterns
        """
        for pattern, replacement in self.defang_patterns:
            text = re.sub(pattern, replacement, text, flags=re.IGNORECASE)
        return text

    def _extract_domain_from_email(self, email: str) -> str:
        """
        Extract domain from email address with better parsing
        """
        if not email:
            return ""
        
        # Handle "Name <email@domain.com>" format
        email = re.sub(r'^.*<([^>]+)>.*$', r'\1', email)
        
        match = re.search(r'@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', email)
        return match.group(1).lower() if match else ""

    def _extract_domain_from_url(self, url: str) -> str:
        """
        Extract domain from URL with better error handling
        """
        try:
            # Add scheme if missing
            if not url.startswith(('http://', 'https://', 'ftp://')):
                url = 'http://' + url
            
            # URL decode
            url = unquote(url)
            
            extracted = tldextract.extract(url)
            if extracted.domain and extracted.suffix:
                return f"{extracted.domain}.{extracted.suffix}".lower()
        except Exception as e:
            logger.debug(f"Error extracting domain from URL {url}: {e}")
        
        return ""

    def _is_valid_domain(self, domain: str) -> bool:
        """
        Validate if string is a valid domain with improved filtering
        """
        if not domain or len(domain) < 4:
            return False
        
        # Filter out invalid patterns
        for pattern in self.invalid_domain_patterns:
            if re.match(pattern, domain, re.IGNORECASE):
                return False
        
        # Must have at least one dot
        if '.' not in domain:
            return False
        
        # Check if TLD is at least 2 characters
        tld = domain.split('.')[-1]
        if len(tld) < 2:
            return False
        
        # Filter out domains that are all numeric
        if domain.replace('.', '').isdigit():
            return False
        
        return True

    def _filter_private_ips(self, ips: List[str]) -> List[str]:
        """
        Filter out private/internal IP addresses (NEW)
        """
        public_ips = []
        for ip in ips:
            is_private = any(pattern.match(ip) for pattern in self.private_ip_ranges)
            if not is_private:
                public_ips.append(ip)
        return list(set(public_ips))

    def _deduplicate_ips(self, ips: List[str]) -> List[str]:
        """
        Deduplicate IP addresses while preserving order
        """
        seen = set()
        result = []
        for ip in ips:
            if ip not in seen:
                seen.add(ip)
                result.append(ip)
        return result

    def _clean_and_deduplicate_urls(self, urls: List[str]) -> List[str]:
        """
        Clean and deduplicate URLs (NEW)
        """
        cleaned = set()
        for url in urls:
            # Remove trailing punctuation
            url = re.sub(r'[.,;:)\]]+$', '', url)
            # Normalize
            url = url.strip()
            if len(url) > 10:  # Minimum URL length
                cleaned.add(url)
        return list(cleaned)

    def _extract_phone_numbers(self, text: str) -> List[str]:
        """
        Extract and validate phone numbers (NEW)
        """
        potential_phones = self.phone_pattern.findall(text)
        validated = []
        
        for phone in potential_phones:
            # Clean up
            phone = re.sub(r'[^\d+]', '', phone)
            # Must be at least 10 digits
            if len(phone) >= 10:
                validated.append(phone)
        
        return list(set(validated))

    def _reset_seen_iocs(self):
        """Reset seen IOCs for new email processing"""
        for key in self.seen_iocs:
            self.seen_iocs[key].clear()

    def _empty_result(self) -> Dict:
        """Return empty result structure"""
        return {
            'sender': '',
            'recipient': '',
            'subject': '',
            'date': '',
            'message_id': '',
            'metadata': {},
            'headers': {},
            'body': '',
            'body_length': 0,
            'ips': [],
            'ipv6': [],
            'urls': [],
            'domains': [],
            'email_addresses': [],
            'hashes': {'md5': [], 'sha1': [], 'sha256': []},
            'bitcoin_addresses': [],
            'phone_numbers': [],
            'cve_ids': [],
            'attachments': [],
            'attachment_count': 0,
            'has_attachments': False,
            'stats': {
                'ip_count': 0,
                'url_count': 0,
                'domain_count': 0,
                'email_count': 0,
                'attachment_count': 0,
                'total_iocs': 0
            }
        }

    def _empty_ioc_dict(self) -> Dict:
        """Return empty IOC dictionary"""
        return {
            'ips': [],
            'ipv6': [],
            'urls': [],
            'domains': [],
            'emails': [],
            'hashes': {'md5': [], 'sha1': [], 'sha256': []},
            'bitcoin_addresses': [],
            'phone_numbers': [],
            'cve_ids': []
        }