from pydantic import BaseModel, EmailStr, Field
from typing import Optional, List, Dict, Any
from datetime import datetime

# ==========================================
# 🧱 SHARED MODELS
# ==========================================

class IOCExtraction(BaseModel):
    ips: List[str] = []
    urls: List[str] = []
    domains: List[str] = []
    email_addresses: List[str] = []
    hashes: List[str] = []

class ThreatIntelResult(BaseModel):
    ioc_value: Optional[str] = None
    ioc_type: Optional[str] = None
    is_malicious: bool = False
    reputation_score: int = 0
    threat_categories: List[str] = []
    source: Optional[str] = "Multiple"

# ==========================================
# 📤 RESPONSE MODELS
# ==========================================

class CaseResponse(BaseModel):
    """
    Schema for sending case data to the Frontend.
    Used in /cases list and /statistics.
    """
    id: int
    email_id: Optional[str] = None
    sender: Optional[str] = None
    subject: Optional[str] = None
    
    body: Optional[str] = None
    
    verdict: Optional[str] = "UNKNOWN"
    risk_score: int
    
    breakdown: Optional[Dict[str, int]] = {}
    
    # [FIX 2] Changed from float to Dict to allow JSON objects
    ml_prediction: Optional[Dict[str, Any]] = None
    
    # [FIX 3] Added this field so the React Text Snippet works
    body_analysis: Optional[Dict[str, Any]] = None
    
    received_time: Optional[datetime] = None
    processed_at: Optional[datetime] = None
    
    class Config:
        from_attributes = True

class StatisticsResponse(BaseModel):
    total_processed: int
    malicious: int
    suspicious: int
    clean: int
    avg_processing_time: float
    recent_cases: List[CaseResponse]

# ==========================================
# 📥 INPUT MODELS
# ==========================================

class EmailSubmission(BaseModel):
    raw_email: Optional[str] = None
    sender: Optional[EmailStr] = None
    recipient: Optional[EmailStr] = None
    subject: Optional[str] = None
    body: Optional[str] = None
    attachments: Optional[List[Dict[str, Any]]] = None

class AnalysisResult(BaseModel):
    """Internal model for analysis results"""
    case_id: int
    verdict: str
    risk_score: int
    breakdown: Dict[str, int]
    ml_prediction: Optional[Dict[str, Any]] # Changed to Dict here too
    processing_time: float
    iocs: IOCExtraction
    threat_intel: List[ThreatIntelResult]
    attachment_findings: Dict[str, Any]