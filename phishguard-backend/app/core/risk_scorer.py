from typing import Dict, List, Any
import math

class RiskScorer:
    def __init__(self):
        """
        Initialize RiskScorer with optimized data structures and max-strategy logic
        """
        # Weights for different detection methods (used for calculation, not just max)
        self.weights = {
            'threat_intel': 0.35,
            'ml': 0.30,
            'attachment': 0.20,
            'heuristic': 0.15
        }
        
        # Verdict thresholds
        self.thresholds = {
            'malicious': 75,
            'suspicious': 45
        }

        # --- OPTIMIZATION: Sets for O(1) lookup ---
        self.legitimate_domains = {
            # Government & Educational
            '.gov', '.edu', '.ac.uk', '.gov.uk', '.gov.ca', '.gov.au', '.mil', '.int',
            # Tech Giants
            'microsoft.com', 'office.com', 'outlook.com', 'live.com', 'hotmail.com',
            'google.com', 'gmail.com', 'googlemail.com', 'youtube.com',
            'apple.com', 'icloud.com', 'me.com', 'mac.com',
            'meta.com', 'facebook.com', 'instagram.com', 'twitter.com', 'x.com',
            'linkedin.com', 'amazon.com', 'aws.amazon.com',
            # Financial
            'paypal.com', 'stripe.com', 'chase.com', 'bankofamerica.com', 'wellsfargo.com',
            'citi.com', 'americanexpress.com', 'visa.com', 'mastercard.com',
            # Services
            'netflix.com', 'fedex.com', 'ups.com', 'usps.com', 'dhl.com'
        }

        self.high_trust_domains = {
            '.gov', '.edu', '.mil',
            'chase.com', 'paypal.com', 'amazon.com', 'google.com', 
            'microsoft.com', 'apple.com'
        }

        # Suspicious TLDs with risk scores
        self.suspicious_tlds = {
            # Critical (50 points)
            '.tk': 50, '.ml': 50, '.ga': 50, '.cf': 50, '.gq': 50,
            '.zip': 50, '.mov': 50,
            # High Risk (35 points)
            '.xyz': 35, '.top': 35, '.work': 35, '.click': 35, '.link': 35,
            '.download': 35, '.racing': 35, '.loan': 35, '.win': 35, '.bid': 35,
            # Moderate Risk (25 points)
            '.online': 25, '.site': 25, '.website': 25, '.space': 25, '.host': 25,
            '.fun': 25, '.tech': 25, '.store': 25, '.company': 25, '.email': 25,
            # Country abuse (20 points)
            '.cc': 20, '.cd': 20, '.nu': 20, '.ws': 20, '.cm': 20,
            '.ru': 15, '.cn': 15 
        }

        # Brand mapping for typosquatting checks
        self.brand_domains = {
            'paypal': ['paypal.com', 'paypal.co.uk', 'paypal.ca'],
            'amazon': ['amazon.com', 'amazon.co.uk', 'amazon.ca', 'amazon.de'],
            'microsoft': ['microsoft.com', 'office.com', 'outlook.com', 'live.com'],
            'google': ['google.com', 'gmail.com', 'googlemail.com'],
            'apple': ['apple.com', 'icloud.com', 'me.com', 'mac.com'],
            'chase': ['chase.com', 'alertsp.chase.com'],
            'netflix': ['netflix.com', 'netflix.net']
        }

    def _extract_domain(self, sender: str) -> str:
        """Extract domain from email address efficiently"""
        if '@' not in sender:
            return ''
        parts = sender.split('@')
        if len(parts) > 1:
            # Handle cases like "User <user@domain.com>"
            return parts[-1].split('>')[0].lower().strip()
        return ''

    def _is_legitimate_domain(self, domain: str) -> bool:
        """Fast domain legitimacy check using set lookup"""
        if not domain:
            return False
        
        # Direct match (O(1))
        if domain in self.legitimate_domains:
            return True
            
        # Check TLD match (for .gov, .edu, etc.)
        for legit in self.legitimate_domains:
            if legit.startswith('.') and domain.endswith(legit):
                return True
        return False

    def _get_trust_level(self, domain: str) -> str:
        """Determine trust level of domain"""
        # Check against high trust sets
        if domain in self.high_trust_domains:
            return 'high'
        # Check for TLD trust
        for trusted in self.high_trust_domains:
            if trusted.startswith('.') and domain.endswith(trusted):
                return 'high'
                
        if self._is_legitimate_domain(domain):
            return 'medium'
        return 'low'

    def _levenshtein_distance(self, s1: str, s2: str) -> int:
        """Calculate Levenshtein distance between two strings"""
        if len(s1) < len(s2):
            return self._levenshtein_distance(s2, s1)
        if len(s2) == 0:
            return len(s1)
        
        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
        return previous_row[-1]

    def _check_typosquatting(self, domain: str) -> dict:
        """
        Detect typosquatting attempts
        Returns: {'is_typosquatting': bool, 'brand': str, 'score': int}
        """
        result = {'is_typosquatting': False, 'brand': None, 'score': 0}
        
        if not domain:
            return result

        # Common character substitutions
        substitutions = {
            'o': '0', 'l': '1', 'i': '1', 
            'a': '@', 'e': '3', 's': '5'
        }
        
        domain_parts = domain.split('.')
        if len(domain_parts) < 2: 
            return result
            
        # Focus on the main domain part (e.g., 'amazon' from 'amazon.co.uk')
        domain_base = domain_parts[0] 

        # Check against each brand
        for brand, official_domains in self.brand_domains.items():
            for official in official_domains:
                official_base = official.split('.')[0]
                
                # Skip exact matches
                if domain_base == official_base:
                    continue

                # Check substitution attacks
                modified_base = domain_base
                for char, sub in substitutions.items():
                    modified_base = modified_base.replace(sub, char)
                
                if modified_base == official_base:
                     result['is_typosquatting'] = True
                     result['brand'] = brand
                     result['score'] = 45
                     return result

                # Check Levenshtein distance
                # Only check if lengths are close to avoid false positives on short strings
                if abs(len(domain_base) - len(official_base)) <= 2:
                    dist = self._levenshtein_distance(domain_base, official_base)
                    if dist > 0 and dist <= 2: # Distance 1 or 2 is suspicious
                        result['is_typosquatting'] = True
                        result['brand'] = brand
                        result['score'] = 40
                        return result
        return result

    def calculate_risk_score(self, analysis_data: Dict) -> Dict:
        """Calculate comprehensive risk score"""
        scores = {
            'threat_intel_score': 0,
            'ml_score': 0,
            'attachment_score': 0,
            'heuristic_score': 0,
            'total_score': 0
        }
        
        # --- EARLY EXIT: Whitelist Check ---
        sender = analysis_data.get('sender', '').lower()
        sender_domain = self._extract_domain(sender)
        
        if self._get_trust_level(sender_domain) == 'high':
             # Fast-track trusted domains
             return {
                "score": 0,
                "verdict": "CLEAN",
                "breakdown": {
                    "threat_intel": 0,
                    "ml_analysis": 0,
                    "attachment_risk": 0,
                    "heuristic_risk": 0
                },
                "explanation": f"Trusted domain detected: {sender_domain}"
            }

        # 1. Threat Intelligence Score
        threat_intel_results = analysis_data.get('threat_intel_results', [])
        if threat_intel_results:
            if any(r.get('is_malicious') for r in threat_intel_results):
                scores['threat_intel_score'] = 100
            else:
                avg_reputation = sum(r.get('reputation_score', 0) for r in threat_intel_results)
                scores['threat_intel_score'] = min(int(avg_reputation / len(threat_intel_results)), 100)
        
        # 2. ML Prediction Score
        ml_result = analysis_data.get('ml_prediction', {})
        if ml_result:
            phishing_prob = ml_result.get('phishing_probability', 0)
            scores['ml_score'] = int(phishing_prob * 100)
        
        # 3. Attachment Analysis Score
        attachment_results = analysis_data.get('attachment_analysis', [])
        if attachment_results:
            max_attachment_risk = max((a.get('risk_score', 0) for a in attachment_results), default=0)
            scores['attachment_score'] = max_attachment_risk
        
        # 4. Heuristic Score
        scores['heuristic_score'] = self._calculate_heuristic_score(analysis_data)
        
        # --- MAX STRATEGY ---
        scores['total_score'] = max(
            scores['threat_intel_score'],
            scores['ml_score'],
            scores['attachment_score'],
            scores['heuristic_score']
        )
        
        return {
            "score": scores['total_score'],
            "verdict": self._determine_verdict(scores['total_score']),
            "breakdown": {
                "threat_intel": scores['threat_intel_score'],
                "ml_analysis": scores['ml_score'],
                "attachment_risk": scores['attachment_score'],
                "heuristic_risk": scores['heuristic_score']
            }
        }
    
    def _calculate_heuristic_score(self, analysis_data: Dict) -> int:
        """Enhanced and optimized heuristic scoring"""
        score = 0
        indicators = []
        
        sender = analysis_data.get('sender', '').lower()
        subject = analysis_data.get('subject', '').lower()
        body = analysis_data.get('body', '').lower()
        full_text = f"{subject} {body}"
        
        # Extract domain once
        sender_domain = self._extract_domain(sender)
        
        # ===== 1. SUSPICIOUS TLDs WITH WEIGHTED SCORING =====
        for tld, tld_score in self.suspicious_tlds.items():
            if sender_domain.endswith(tld):
                score += tld_score
                break  # Only count the highest risk TLD match

        # ===== 2. TYPOSQUATTING DETECTION =====
        typo_check = self._check_typosquatting(sender_domain)
        if typo_check['is_typosquatting']:
            score += typo_check['score']
            indicators.append(f"Typosquatting detected: impersonating {typo_check['brand']}")

        # ===== 3. CRITICAL KEYWORDS (40 points each) =====
        critical_keywords = {
            'wire transfer': 40, 'bitcoin': 40, 'cryptocurrency': 35,
            'gift card': 40, 'western union': 40, 'moneygram': 40,
            'green dot': 40, 'itunes card': 35, 'steam card': 35
        }
        
        for keyword, points in critical_keywords.items():
            if keyword in full_text:
                score += points
                indicators.append(f"Critical keyword: {keyword}")

        # ===== 4. URGENCY TACTICS (max 40 points) =====
        urgency_words = {
            'urgent', 'immediately', 'act now', 'expires today',
            'final notice', 'last chance', 'limited time', 'right now',
            'deadline', 'asap', 'expire', 'suspended', 'locked'
        }
        urgency_count = sum(1 for word in urgency_words if word in full_text)
        urgency_score = min(urgency_count * 8, 40)
        score += urgency_score

        # ===== 5. CREDENTIAL REQUESTS (max 40 points) =====
        credential_keywords = {
            'password', 'ssn', 'social security', 'credit card',
            'bank account', 'routing number', 'pin', 'cvv',
            'date of birth', 'mother\'s maiden name', 'driver\'s license'
        }
        cred_count = sum(1 for kw in credential_keywords if kw in body)
        cred_score = min(cred_count * 20, 40)
        score += cred_score

        # ===== 6. SENDER MISMATCH (35 points) =====
        if self._check_sender_mismatch(analysis_data):
            score += 35
            indicators.append("Sender mismatch detected")

        # ===== 7. EXCESSIVE LINKS (graduated scoring) =====
        link_count = full_text.count('http')
        if link_count > 8:
            score += 25
        elif link_count > 5:
            score += 15
        elif link_count > 3:
            score += 5

        # ===== 8. URL SHORTENERS (15 points) =====
        shorteners = {'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'tiny.cc'}
        if any(shortener in body for shortener in shorteners):
            score += 15

        # ===== 9. LEGITIMATE INDICATORS REDUCE SCORE =====
        legit_indicators = {
            'unsubscribe', 'manage preferences', 'privacy policy',
            'terms of service', 'contact us', 'customer service',
            'customer support', 'help center'
        }
        legit_count = sum(1 for indicator in legit_indicators if indicator in body)
        
        if legit_count >= 3:
            score = int(score * 0.6)  # 40% reduction
        elif legit_count >= 2:
            score = int(score * 0.7)  # 30% reduction

        # ===== 10. TRUST LEVEL ADJUSTMENT =====
        trust_level = self._get_trust_level(sender_domain)
        if trust_level == 'high':
            score = int(score * 0.5)  # 50% reduction
        elif trust_level == 'medium':
            score = int(score * 0.75)  # 25% reduction
            
        analysis_data['heuristic_indicators'] = indicators
        return min(score, 100)
    
    def _check_sender_mismatch(self, analysis_data: Dict) -> bool:
        """Check if sender display name doesn't match email domain"""
        sender = analysis_data.get('sender', '')
        if '<' in sender and '>' in sender:
            try:
                display_name = sender.split('<')[0].strip().lower()
                email_address = sender.split('<')[1].split('>')[0].lower()
                
                for brand in self.brand_domains.keys():
                    if brand in display_name and brand not in email_address:
                        return True
            except:
                pass
        return False
    
    def _determine_verdict(self, risk_score: int) -> str:
        if risk_score >= self.thresholds['malicious']:
            return "MALICIOUS"
        elif risk_score >= self.thresholds['suspicious']:
            return "SUSPICIOUS"
        else:
            return "CLEAN"