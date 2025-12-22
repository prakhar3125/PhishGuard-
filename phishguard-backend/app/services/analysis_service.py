import time
import os
import uuid
from typing import Dict, List, Optional
from sqlalchemy.orm import Session
from datetime import datetime

from app.core.ioc_extractor import IOCExtractor
from app.core.threat_intel import ThreatIntelligence
from app.core.attachment_analyzer import AttachmentAnalyzer
from app.core.ml_classifier import PhishingClassifier
from app.core.risk_scorer import RiskScorer
from app.models import PhishingCase, IOC
from app.config import settings

# Define where emails will be stored on disk
UPLOAD_DIR = "data/uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

class AnalysisService:
    def __init__(self, db: Session):
        self.db = db
        self.ioc_extractor = IOCExtractor()
        self.threat_intel = ThreatIntelligence(db)
        self.attachment_analyzer = AttachmentAnalyzer()
        # Initialize ML Classifier (handle if model path is missing)
        try:
            self.ml_classifier = PhishingClassifier(settings.ML_MODEL_PATH)
        except:
            self.ml_classifier = PhishingClassifier()
        
        self.risk_scorer = RiskScorer()
    
    def analyze_email(self, raw_email: bytes, email_id: str = None) -> Dict:
        """Complete email analysis pipeline"""
        start_time = time.time()
        
        # 1. Save Email to Disk
        file_ext = ".eml"
        unique_filename = f"{datetime.now().strftime('%Y%m%d')}_{uuid.uuid4().hex[:8]}{file_ext}"
        file_path = os.path.join(UPLOAD_DIR, unique_filename)
        
        try:
            with open(file_path, "wb") as f:
                f.write(raw_email)
            print(f"💾 Email saved to disk: {file_path}")
        except Exception as e:
            print(f"⚠️ Failed to save email to disk: {e}")
            file_path = None

        # 2. Extract IOCs
        print(f"[1/5] Extracting IOCs...")
        extraction_result = self.ioc_extractor.extract_from_raw_email(raw_email)
        
        # 3. Threat Intelligence
        print(f"[2/5] Checking threat intelligence...")
        threat_intel_results = self._enrich_threat_intelligence(extraction_result)
        
        # 4. Attachment Analysis
        print(f"[3/5] Analyzing attachments...")
        attachment_results = self._analyze_attachments(extraction_result.get('attachments', []))
        
        # 5. ML Classification
        print(f"[4/5] Running ML classification...")
        ml_prediction = self.ml_classifier.predict({
            'subject': extraction_result.get('subject', ''),
            'body': extraction_result.get('body', ''),
            'sender': extraction_result.get('sender', '')
        })
        
        # 6. Risk Scoring
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
        
        # 7. Generate Body Analysis (Snippet & Urgency) [MISSING IN YOUR FILE]
        body_text = extraction_result.get('body', '')
        body_analysis = {
            "snippet": body_text[:500] + "..." if len(body_text) > 500 else body_text,
            "urgency_detected": self._check_urgency(body_text),
            "heuristic_indicators": risk_analysis.get('breakdown', {}).get('heuristic_risk', 0) > 0
        }

        # 8. Save to Database
        final_score = risk_analysis.get('score', 0)
        
        case = self._save_case(
            email_id=email_id or self._generate_email_id(),
            extraction_result=extraction_result,
            threat_intel_results=threat_intel_results,
            attachment_results=attachment_results,
            ml_prediction=ml_prediction,
            risk_analysis=risk_analysis,
            body_analysis=body_analysis, # Pass the new body analysis
            processing_time=processing_time,
            file_path=file_path,
            final_score=final_score
        )
        
        print(f"✓ Analysis complete in {processing_time:.2f}s - Verdict: {risk_analysis['verdict']}")
        
        return {
            'case_id': case.id,
            'email_id': case.email_id,
            'verdict': risk_analysis.get('verdict', 'UNKNOWN'),
            'risk_score': final_score, 
            'breakdown': risk_analysis.get('breakdown', {}),
            'processing_time': processing_time,
            'extraction': extraction_result,
            'threat_intel': threat_intel_results,
            'attachments': attachment_results,
            'ml_prediction': ml_prediction,
            'body_analysis': body_analysis
        }

    def get_email_content(self, case_id: int) -> Optional[str]:
        """Fetch raw content from disk"""
        case = self.db.query(PhishingCase).filter(PhishingCase.id == case_id).first()
        if not case:
            return None
            
        if case.file_path and os.path.exists(case.file_path):
            try:
                with open(case.file_path, 'r', encoding='utf-8', errors='replace') as f:
                    return f.read()
            except Exception as e:
                return f"Error reading file: {str(e)}"
        
        return case.body or "Content not found."
    
    def _enrich_threat_intelligence(self, extraction_result: Dict) -> List[Dict]:
        results = []
        for ip in extraction_result.get('ips', [])[:5]:
            results.append(self.threat_intel.check_ip(ip))
        for url in extraction_result.get('urls', [])[:5]:
            results.append(self.threat_intel.check_url(url))
        for domain in extraction_result.get('domains', [])[:5]:
            results.append(self.threat_intel.check_domain(domain))
        return results
    
    def _analyze_attachments(self, attachments: List[Dict]) -> List[Dict]:
        results = []
        for attachment in attachments:
            filename = attachment.get('filename', '')
            content = attachment.get('content', b'')
            if content:
                results.append(self.attachment_analyzer.analyze_attachment(filename, content))
        return results
    
    def _check_urgency(self, text: str) -> bool:
        """Simple helper to re-check urgency for UI display"""
        urgency_words = ['urgent', 'immediate', 'asap', 'action required', 'suspended', 'limited time']
        return any(w in text.lower() for w in urgency_words)

    def _save_case(self, email_id: str, extraction_result: Dict, 
                   threat_intel_results: List, attachment_results: List,
                   ml_prediction: Dict, risk_analysis: Dict, body_analysis: Dict,
                   processing_time: float, file_path: str, final_score: int) -> PhishingCase:
        
        sender = extraction_result.get('sender', '')
        sender_domain = sender.split('@')[1] if '@' in sender else ''
        
        case = PhishingCase(
            email_id=email_id,
            sender=sender,
            sender_domain=sender_domain,
            recipient=extraction_result.get('recipient', ''),
            subject=extraction_result.get('subject', ''),
            verdict=risk_analysis.get('verdict'),
            risk_score=final_score, 
            
            # [FIXED] Save the FULL ML dictionary, not just the float score
            ml_prediction=ml_prediction,
            
            extracted_ips=extraction_result.get('ips', []),
            extracted_urls=extraction_result.get('urls', []),
            extracted_domains=extraction_result.get('domains', []),
            extracted_hashes=[a.get('sha256') for a in extraction_result.get('attachments', [])],
            threat_intel_results=[self._serialize_threat_intel(t) for t in threat_intel_results],
            attachment_analysis=[self._serialize_attachment(a) for a in attachment_results],
            header_analysis=extraction_result.get('headers', {}),
            breakdown=risk_analysis.get('breakdown', {}),
            
            # [FIXED] Save the body analysis (snippet/urgency)
            body_analysis=body_analysis,
            
            file_path=file_path,
            processing_time=processing_time,
            processed_at=datetime.utcnow()
        )
        
        self.db.add(case)
        self.db.flush()
        
        # Save IOCs
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
        return f"email_{uuid.uuid4().hex[:12]}"
    
    def _serialize_threat_intel(self, result: Dict) -> Dict:
        return {
            'ioc_value': result.get('ioc_value'),
            'ioc_type': result.get('ioc_type'),
            'is_malicious': result.get('is_malicious'),
            'reputation_score': result.get('reputation_score'),
            'threat_categories': result.get('threat_categories', [])
        }
    
    def _serialize_attachment(self, result: Dict) -> Dict:
        return {
            'filename': result.get('filename'),
            'file_type': result.get('file_type'),
            'risk_score': result.get('risk_score'),
            'is_suspicious': result.get('is_suspicious'),
            'findings': result.get('findings', []),
            'sha256': result.get('sha256')
        }