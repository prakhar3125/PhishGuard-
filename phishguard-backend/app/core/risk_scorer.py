from typing import Dict, List

class RiskScorer:
    def __init__(self):
        self.weights = {
            'threat_intel': 0.4,
            'ml_prediction': 0.3,
            'attachment_analysis': 0.2,
            'heuristics': 0.1
        }
    
    def calculate_risk_score(self, analysis_data: Dict) -> Dict:
        """Calculate comprehensive risk score"""
        scores = {
            'threat_intel_score': 0,
            'ml_score': 0,
            'attachment_score': 0,
            'heuristic_score': 0,
            'total_score': 0
        }
        
        # Threat Intelligence Score
        threat_intel_results = analysis_data.get('threat_intel_results', [])
        if threat_intel_results:
            malicious_count = sum(1 for r in threat_intel_results if r.get('is_malicious'))
            avg_reputation = sum(r.get('reputation_score', 0) for r in threat_intel_results) / len(threat_intel_results)
            
            scores['threat_intel_score'] = min((malicious_count * 30) + (avg_reputation * 0.5), 100)
        
        # ML Prediction Score
        ml_result = analysis_data.get('ml_prediction', {})
        if ml_result:
            phishing_prob = ml_result.get('phishing_probability', 0)
            scores['ml_score'] = phishing_prob * 100
        
        # Attachment Analysis Score
        attachment_results = analysis_data.get('attachment_analysis', [])
        if attachment_results:
            max_attachment_risk = max((a.get('risk_score', 0) for a in attachment_results), default=0)
            scores['attachment_score'] = max_attachment_risk
        
        # Heuristic Score
        heuristic_score = self._calculate_heuristic_score(analysis_data)
        scores['heuristic_score'] = heuristic_score
        
        # Calculate weighted total
        total = (
            scores['threat_intel_score'] * self.weights['threat_intel'] +
            scores['ml_score'] * self.weights['ml_prediction'] +
            scores['attachment_score'] * self.weights['attachment_analysis'] +
            scores['heuristic_score'] * self.weights['heuristics']
        )
        
        scores['total_score'] = min(int(total), 100)
        
        # Determine verdict
        verdict = self._determine_verdict(scores['total_score'])
        scores['verdict'] = verdict
        
        return scores
    
    def _calculate_heuristic_score(self, analysis_data: Dict) -> int:
        """Calculate heuristic-based risk score"""
        score = 0
        
        # Check for suspicious sender
        sender = analysis_data.get('sender', '').lower()
        suspicious_tlds = ['.xyz', '.top', '.tk', '.ml', '.ru', '.cn']
        if any(tld in sender for tld in suspicious_tlds):
            score += 20
        
        # Check subject for red flags
        subject = analysis_data.get('subject', '').lower()
        red_flag_words = ['urgent', 'verify', 'suspended', 'unusual', 'click here', 'act now']
        score += sum(10 for word in red_flag_words if word in subject)
        
        # Check for mismatched sender/display name
        if self._check_sender_mismatch(analysis_data):
            score += 30
        
        # Check for excessive links
        body = analysis_data.get('body', '')
        link_count = body.count('http')
        if link_count > 5:
            score += 15
        
        # Check for requests for sensitive info
        sensitive_keywords = ['password', 'credit card', 'ssn', 'bank account']
        if any(keyword in body.lower() for keyword in sensitive_keywords):
            score += 25
        
        return min(score, 100)
    
    def _check_sender_mismatch(self, analysis_data: Dict) -> bool:
        """Check if sender display name doesn't match email domain"""
        sender = analysis_data.get('sender', '')
        
        # Extract display name and email
        if '<' in sender and '>' in sender:
            display_name = sender.split('<')[0].strip().lower()
            email_address = sender.split('<')[1].split('>')[0].lower()
            
            # Check for brand impersonation
            brands = ['paypal', 'amazon', 'microsoft', 'apple', 'google', 'facebook']
            for brand in brands:
                if brand in display_name and brand not in email_address:
                    return True
        
        return False
    
    def _determine_verdict(self, risk_score: int) -> str:
        """Determine verdict based on risk score"""
        if risk_score >= 70:
            return "MALICIOUS"
        elif risk_score >= 40:
            return "SUSPICIOUS"
        else:
            return "CLEAN"
    
    def get_risk_explanation(self, scores: Dict) -> List[str]:
        """Generate human-readable risk explanation"""
        explanations = []
        
        if scores['threat_intel_score'] > 50:
            explanations.append(f"Threat intelligence indicates malicious indicators (Score: {scores['threat_intel_score']}/100)")
        
        if scores['ml_score'] > 70:
            explanations.append(f"ML model predicts high phishing probability (Score: {scores['ml_score']}/100)")
        
        if scores['attachment_score'] > 50:
            explanations.append(f"Suspicious attachments detected (Score: {scores['attachment_score']}/100)")
        
        if scores['heuristic_score'] > 40:
            explanations.append(f"Multiple phishing indicators found (Score: {scores['heuristic_score']}/100)")
        
        if not explanations:
            explanations.append("No significant threats detected")
        
        return explanations