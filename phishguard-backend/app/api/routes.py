from fastapi import APIRouter, UploadFile, File, Depends, HTTPException, BackgroundTasks
from sqlalchemy.orm import Session
from sqlalchemy import func, desc
from typing import List, Dict, Any
from datetime import datetime

from app.database import get_db
from app.models import PhishingCase, IOC
from app.schemas import CaseResponse
from app.services.analysis_service import AnalysisService

router = APIRouter()

# ============================================================================
# ANALYSIS ENDPOINTS
# ============================================================================

@router.post("/analyze", response_model=dict)
async def analyze_email(
    file: UploadFile = File(...),
    background_tasks: BackgroundTasks = None,  # Kept for future async processing
    db: Session = Depends(get_db)
):
    """
    Analyze an uploaded email file (.eml format)
    """
    try:
        # 1. Read email content
        raw_email = await file.read()
        
        # 2. Initialize Service
        service = AnalysisService(db)
        
        # 3. Perform Analysis (Saves to Disk & DB)
        result = service.analyze_email(raw_email)
        
        # 4. Construct Response with Safety Defaults
        # We ensure 'breakdown' always has values so the Frontend Graph works.
        breakdown = result.get('breakdown', {}) or {}
        
        return {
            "status": "success",
            "case_id": result['case_id'],
            "verdict": result['verdict'],
            "risk_score": result['risk_score'],
            "processing_time": result['processing_time'],
            # ✅ CRITICAL FIX: Ensure specific keys exist for the Graph
            "breakdown": {
                "threat_intel": breakdown.get("threat_intel", 0),
                "ml_analysis": breakdown.get("ml_analysis", 0),
                "attachment_risk": breakdown.get("attachment_risk", 0),
                "heuristic_risk": breakdown.get("heuristic_risk", 0)
            }
        }
    
    except Exception as e:
        print(f"❌ Error in /analyze: {e}") # Print error to server logs
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")


# ============================================================================
# CASE MANAGEMENT ENDPOINTS
# ============================================================================

@router.get("/cases", response_model=List[CaseResponse])
def list_cases(
    skip: int = 0,
    limit: int = 50,
    verdict: str = None,
    db: Session = Depends(get_db)
):
    """List recent cases with optional filtering"""
    query = db.query(PhishingCase)
    
    if verdict:
        query = query.filter(PhishingCase.verdict == verdict.upper())
    
    # Return newest first
    return query.order_by(desc(PhishingCase.received_time)).offset(skip).limit(limit).all()


@router.get("/cases/{case_id}", response_model=dict)
def get_case(case_id: int, db: Session = Depends(get_db)):
    """Get full details of a specific case"""
    case = db.query(PhishingCase).filter(PhishingCase.id == case_id).first()
    
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    
    return {
        "id": case.id,
        "email_id": case.email_id,
        "sender": case.sender,
        "subject": case.subject,
        "verdict": case.verdict,
        "risk_score": case.risk_score,
        "breakdown": case.breakdown, # ✅ Includes the math for the UI
        "ml_prediction": case.ml_prediction,
        "received_time": case.received_time,
        "processed_at": case.processed_at,
        "processing_time": case.processing_time,
        "iocs": {
            "ips": case.extracted_ips,
            "urls": case.extracted_urls,
            "domains": case.extracted_domains,
            "hashes": case.extracted_hashes
        },
        "threat_intel": case.threat_intel_results,
        "attachments": case.attachment_analysis,
        "body_analysis": case.body_analysis
    }


@router.get("/cases/{case_id}/content")
def get_case_content(case_id: int, db: Session = Depends(get_db)):
    """
    Fetch raw email content from the file system (Lazy Loading)
    """
    service = AnalysisService(db)
    content = service.get_email_content(case_id)
    
    if not content:
        raise HTTPException(status_code=404, detail="Content not found or file missing")
    
    return {"content": content}


@router.delete("/cases/{case_id}")
def delete_case(case_id: int, db: Session = Depends(get_db)):
    """Delete a case from the database"""
    case = db.query(PhishingCase).filter(PhishingCase.id == case_id).first()
    
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    
    db.delete(case)
    db.commit()
    
    return {"status": "success", "message": f"Case {case_id} deleted"}


# ============================================================================
# STATISTICS & IOC ENDPOINTS
# ============================================================================

@router.get("/statistics", response_model=dict)
def get_statistics(db: Session = Depends(get_db)):
    """Get dashboard statistics"""
    total = db.query(func.count(PhishingCase.id)).scalar()
    
    # Efficient counting
    malicious = db.query(func.count(PhishingCase.id)).filter(PhishingCase.verdict == 'MALICIOUS').scalar()
    suspicious = db.query(func.count(PhishingCase.id)).filter(PhishingCase.verdict == 'SUSPICIOUS').scalar()
    clean = db.query(func.count(PhishingCase.id)).filter(PhishingCase.verdict == 'CLEAN').scalar()
    
    avg_time = db.query(func.avg(PhishingCase.processing_time)).scalar() or 0
    
    # Get recent cases for the mini-table
    recent_cases = db.query(PhishingCase).order_by(desc(PhishingCase.processed_at)).limit(10).all()
    
    return {
        "total_processed": total,
        "malicious": malicious,
        "suspicious": suspicious,
        "clean": clean,
        "avg_processing_time": round(avg_time, 2),
        "recent_cases": [
            {
                "id": c.id,
                "sender": c.sender,
                "subject": c.subject,
                "verdict": c.verdict,
                "risk_score": c.risk_score,
                "breakdown": c.breakdown or {}, # Safety fallback
                "processed_at": c.processed_at
            }
            for c in recent_cases
        ]
    }


@router.get("/iocs", response_model=List[dict])
def search_iocs(
    ioc_value: str = None,
    ioc_type: str = None,
    is_malicious: bool = None,
    db: Session = Depends(get_db)
):
    """Search for IOCs across all cases"""
    query = db.query(IOC)
    
    if ioc_value:
        query = query.filter(IOC.ioc_value.contains(ioc_value))
    if ioc_type:
        query = query.filter(IOC.ioc_type == ioc_type)
    if is_malicious is not None:
        query = query.filter(IOC.is_malicious == is_malicious)
    
    iocs = query.order_by(desc(IOC.last_seen)).limit(100).all()
    
    return [
        {
            "id": ioc.id,
            "type": ioc.ioc_type,
            "value": ioc.ioc_value,
            "is_malicious": ioc.is_malicious,
            "reputation_score": ioc.reputation_score,
            "times_seen": ioc.times_seen,
            "last_seen": ioc.last_seen,
            "case_id": ioc.case_id
        }
        for ioc in iocs
    ]


@router.get("/health")
def health_check():
    """Simple health check"""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow(),
        "service": "PhishGuard Pro"
    }