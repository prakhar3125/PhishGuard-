from sqlalchemy import Column, Integer, String, DateTime, JSON, Float, Text, Boolean, ForeignKey
from sqlalchemy.orm import relationship
from datetime import datetime
from app.database import Base

class PhishingCase(Base):
    __tablename__ = "cases"
    
    id = Column(Integer, primary_key=True, index=True)
    email_id = Column(String(255), unique=True, index=True)
    
    # Email Metadata
    sender = Column(String(255), index=True)
    sender_domain = Column(String(255), index=True)
    recipient = Column(String(255))
    subject = Column(Text)
    
    file_path = Column(String(500), nullable=True)
    body = Column(Text, nullable=True)
    
    received_time = Column(DateTime, default=datetime.utcnow)
    
    # Analysis Results
    verdict = Column(String(50), index=True)
    risk_score = Column(Integer, default=0)
    
    # [FIX 1] Changed from Float to JSON to store full ML details
    ml_prediction = Column(JSON) 
    
    breakdown = Column(JSON, default={})
    
    extracted_ips = Column(JSON)
    extracted_urls = Column(JSON)
    extracted_domains = Column(JSON)
    extracted_hashes = Column(JSON)
    
    threat_intel_results = Column(JSON)
    attachment_analysis = Column(JSON)
    header_analysis = Column(JSON)
    body_analysis = Column(JSON)
    
    processing_time = Column(Float)
    processed_at = Column(DateTime, default=datetime.utcnow)
    analyst_notes = Column(Text)
    
    iocs = relationship("IOC", back_populates="case", cascade="all, delete-orphan")
    
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class IOC(Base):
    __tablename__ = "iocs"
    
    id = Column(Integer, primary_key=True, index=True)
    case_id = Column(Integer, ForeignKey("cases.id"), index=True)
    
    ioc_type = Column(String(50), index=True)
    ioc_value = Column(String(512), index=True)
    
    reputation_score = Column(Integer, default=0)
    is_malicious = Column(Boolean, default=False)
    threat_categories = Column(JSON)
    
    source_api = Column(String(100))
    raw_response = Column(JSON)
    
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)
    times_seen = Column(Integer, default=1)
    
    case = relationship("PhishingCase", back_populates="iocs")
    
    created_at = Column(DateTime, default=datetime.utcnow)


class ThreatIntelCache(Base):
    __tablename__ = "threat_intel_cache"
    
    id = Column(Integer, primary_key=True, index=True)
    ioc_value = Column(String(512), unique=True, index=True)
    ioc_type = Column(String(50))
    
    reputation_score = Column(Integer)
    is_malicious = Column(Boolean)
    source_api = Column(String(100))
    raw_response = Column(JSON)
    
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime)