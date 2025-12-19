from pydantic import BaseModel, EmailStr, Field
from typing import Optional, List, Dict, Any
from datetime import datetime

class IOCExtraction(BaseModel):
    ips: List[str] = []
    urls: List[str] = []
    domains: List[str] = []
    email_addresses: List[str] = []
    hashes: List[str] = []

class ThreatIntelResult(BaseModel):
    ioc_value: str
    ioc_type: str
    is_malicious: bool
    reputation_score: int
    threat_categories: List[str] = []
    source: str

class AnalysisResult(BaseModel):
    case_id: int
    verdict: str
    risk_score: int
    ml_prediction: Optional[float]
    processing_time: float
    iocs: IOCExtraction
    threat_intel: List[ThreatIntelResult]
    attachment_findings: Dict[str, Any]

class EmailSubmission(BaseModel):
    raw_email: Optional[str] = None
    sender: Optional[EmailStr] = None
    recipient: Optional[EmailStr] = None
    subject: Optional[str] = None
    body: Optional[str] = None
    attachments: Optional[List[Dict[str, Any]]] = None

class CaseResponse(BaseModel):
    id: int
    email_id: Optional[str] = None
    sender: Optional[str] = None       # <--- ADD THIS
    subject: Optional[str] = None
    body: Optional[str] = None         # <--- ADD THIS (Critical for the dropdown!)
    verdict: str
    risk_score: int
    received_time: datetime
    processed_at: Optional[datetime]
    
    class Config:
        from_attributes = True

class StatisticsResponse(BaseModel):
    total_processed: int
    malicious: int
    suspicious: int
    clean: int
    avg_processing_time: float
    recent_cases: List[CaseResponse]