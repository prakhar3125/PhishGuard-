import time
from typing import Dict, List
from sqlalchemy.orm import Session
from datetime import datetime

from app.core.ioc_extractor import IOCExtractor
from app.core.threat_intel import ThreatIntelligence
from app.core.attachment_analyzer import AttachmentAnalyzer
from app.core.ml_classifier import PhishingClassifier
from app.core.risk_scorer import RiskScorer
from app.models import PhishingCase, IOC
from app.config import settings

class AnalysisService:
    def __init__(self, db: Session):
        self.db = db
        self.ioc_extractor = IOCExtractor()
        self.threat_intel = ThreatIntelligence(db)
        self.attachment_analyzer = AttachmentAnalyzer()
        self.ml_classifier = PhishingClassifier(settings.ML_MODEL_PATH)
        self.risk_scorer = RiskScorer()
    
    def analyze_email(self, raw_email: bytes, email_id: str = None) -> Dict:
        """Complete email analysis pipeline"""
        start_time = time.time()
        
        # Step 1: Extract IOCs
        print(f"[1/5] Extracting IOCs...")
        extraction_result = self.ioc_extractor.extract_from_raw_email(raw_email)
        
        # Step 2: Threat Intelligence Enrichment
        print(f"[2/5] Checking threat intelligence...")
        threat_intel_results = self._enrich_threat_intelligence(extraction_result)
        
        # Step 3: Attachment Analysis
        print(f"[3/5] Analyzing attachments...")
        attachment_results = self._analyze_attachments(extraction_result.get('attachments', []))
        
        # Step 4: ML Classification
        print(f"[4/5] Running ML classification...")
        ml_prediction = self.ml_classifier.predict({
            'subject': extraction_result.get('subject', ''),
            'body': extraction_result.get('body', ''),
            'sender': extraction_result.get('sender', '')
        })
        
        # Step 5: Risk Scoring
        print(f"[5/5] Calculating risk score...")
        risk_analysis = self.risk_scorer.calculate_risk_score({
            'sender': extraction_result.get('sender', ''),
            'subject': extraction_result.get('subject', ''),
            'body': extraction_result.get('body', ''),
            'threat_intel_results': threat_intel_results,
            'attachment_analysis': attachment_results,
            'ml_prediction': ml_prediction
        })
        
        processing_time = time.time() - start_time
        
        # Save to database
        case = self._save_case(
            email_id=email_id or self._generate_email_id(),
            extraction_result=extraction_result,
            threat_intel_results=threat_intel_results,
            attachment_results=attachment_results,
            ml_prediction=ml_prediction,
            risk_analysis=risk_analysis,
            processing_time=processing_time
        )
        
        print(f"✓ Analysis complete in {processing_time:.2f}s - Verdict: {risk_analysis['verdict']}")
        
        return {
            'case_id': case.id,
            'email_id': case.email_id,
            'verdict': risk_analysis['verdict'],
            'risk_score': risk_analysis['total_score'],
            'processing_time': processing_time,
            'extraction': extraction_result,
            'threat_intel': threat_intel_results,
            'attachments': attachment_results,
            'ml_prediction': ml_prediction,
            'risk_breakdown': risk_analysis
        }
    
    def _enrich_threat_intelligence(self, extraction_result: Dict) -> List[Dict]:
        """Enrich IOCs with threat intelligence"""
        results = []
        
        # Check IPs
        for ip in extraction_result.get('ips', [])[:10]:  # Limit to avoid rate limits
            result = self.threat_intel.check_ip(ip)
            results.append(result)
        
        # Check URLs
        for url in extraction_result.get('urls', [])[:10]:
            result = self.threat_intel.check_url(url)
            results.append(result)
        
        # Check Domains
        for domain in extraction_result.get('domains', [])[:10]:
            result = self.threat_intel.check_domain(domain)
            results.append(result)
        
        # Check file hashes
        for attachment in extraction_result.get('attachments', []):
            file_hash = attachment.get('sha256')
            if file_hash:
                result = self.threat_intel.check_file_hash(file_hash)
                results.append(result)
        
        return results
    
    def _analyze_attachments(self, attachments: List[Dict]) -> List[Dict]:
        """Analyze all attachments"""
        results = []
        
        for attachment in attachments:
            filename = attachment.get('filename', '')
            content = attachment.get('content', b'')
            
            if content:
                analysis = self.attachment_analyzer.analyze_attachment(filename, content)
                results.append(analysis)
        
        return results
    
    def _save_case(self, email_id: str, extraction_result: Dict, 
                   threat_intel_results: List, attachment_results: List,
                   ml_prediction: Dict, risk_analysis: Dict, processing_time: float) -> PhishingCase:
        """Save analysis results to database"""
        
        # Extract sender domain
        sender = extraction_result.get('sender', '')
        sender_domain = sender.split('@')[1] if '@' in sender else ''
        
        # Create case
        case = PhishingCase(
            email_id=email_id,
            sender=sender,
            sender_domain=sender_domain,
            recipient=extraction_result.get('recipient', ''),
            subject=extraction_result.get('subject', ''),
            verdict=risk_analysis['verdict'],
            risk_score=risk_analysis['total_score'],
            ml_prediction=ml_prediction.get('phishing_probability', 0),
            extracted_ips=extraction_result.get('ips', []),
            extracted_urls=extraction_result.get('urls', []),
            extracted_domains=extraction_result.get('domains', []),
            extracted_hashes=[a.get('sha256') for a in extraction_result.get('attachments', [])],
            threat_intel_results=[self._serialize_threat_intel(t) for t in threat_intel_results],
            attachment_analysis=[self._serialize_attachment(a) for a in attachment_results],
            header_analysis=extraction_result.get('headers', {}),
            body_analysis={'ml_prediction': ml_prediction, 'risk_breakdown': risk_analysis},
            processing_time=processing_time,
            processed_at=datetime.utcnow()
        )
        
        self.db.add(case)
        self.db.flush()
        
        # Create IOC records
        for result in threat_intel_results:
            ioc = IOC(
                case_id=case.id,
                ioc_type=result.get('ioc_type', ''),
                ioc_value=result.get('ioc_value', ''),
                reputation_score=result.get('reputation_score', 0),
                is_malicious=result.get('is_malicious', False),
                threat_categories=result.get('threat_categories', []),
                source_api='multiple',
                raw_response=result.get('sources', {})
            )
            self.db.add(ioc)
        
        self.db.commit()
        return case
    
    def _generate_email_id(self) -> str:
        """Generate unique email ID"""
        import uuid
        return f"email_{uuid.uuid4().hex[:12]}"
    
    def _serialize_threat_intel(self, result: Dict) -> Dict:
        """Serialize threat intel result for JSON storage"""
        return {
            'ioc_value': result.get('ioc_value'),
            'ioc_type': result.get('ioc_type'),
            'is_malicious': result.get('is_malicious'),
            'reputation_score': result.get('reputation_score'),
            'threat_categories': result.get('threat_categories', [])
        }
    
    def _serialize_attachment(self, result: Dict) -> Dict:
        """Serialize attachment analysis for JSON storage"""
        return {
            'filename': result.get('filename'),
            'file_type': result.get('file_type'),
            'risk_score': result.get('risk_score'),
            'is_suspicious': result.get('is_suspicious'),
            'findings': result.get('findings', []),
            'sha256': result.get('sha256')
        }