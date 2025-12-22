import os
import json
import requests
import re 
from fastapi import APIRouter, UploadFile, File, Depends, HTTPException, BackgroundTasks
from sqlalchemy.orm import Session
from sqlalchemy import func, desc
from typing import List, Dict, Any, Optional
from datetime import datetime
from pydantic import BaseModel 

from app.database import get_db
from app.models import PhishingCase, IOC
from app.schemas import CaseResponse
from app.services.analysis_service import AnalysisService
from app.config import settings 

router = APIRouter()

# ============================================================================
# DATA MODELS
# ============================================================================

class AISummaryRequest(BaseModel):
    subject: str
    sender: str
    risk_score: int
    verdict: str
    body: str

# ============================================================================
# ANALYSIS ENDPOINTS
# ============================================================================

@router.post("/analyze", response_model=dict)
async def analyze_email(
    file: UploadFile = File(...),
    background_tasks: BackgroundTasks = None,
    db: Session = Depends(get_db)
):
    """Analyze an uploaded email file (.eml format)"""
    try:
        raw_email = await file.read()
        service = AnalysisService(db)
        result = service.analyze_email(raw_email)
        breakdown = result.get('breakdown', {}) or {}
        
        return {
            "status": "success",
            "case_id": result['case_id'],
            "verdict": result['verdict'],
            "risk_score": result['risk_score'],
            "processing_time": result['processing_time'],
            "breakdown": {
                "threat_intel": breakdown.get("threat_intel", 0),
                "ml_analysis": breakdown.get("ml_analysis", 0),
                "attachment_risk": breakdown.get("attachment_risk", 0),
                "heuristic_risk": breakdown.get("heuristic_risk", 0)
            }
        }
    except Exception as e:
        print(f"❌ Error in /analyze: {e}")
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")


@router.post("/ai-summary")
def generate_ai_summary(request: AISummaryRequest):
    """
    Generate an executive threat summary using Perplexity API with robust error handling.
    """

    api_key = getattr(settings, "PERPLEXITY_API_KEY", None) or os.getenv("PERPLEXITY_API_KEY")
    if not api_key:
        print("❌ Error: Perplexity API Key is missing.")
        raise HTTPException(status_code=500, detail="Server configuration error: API key missing")

    safe_body = (request.body or "No body content.")[:1500]

    prompt = f"""
You are a Tier 3 SOC analyst. Analyze the following email metadata and produce only JSON.

Subject: {request.subject}
Sender: {request.sender}
Risk Score: {request.risk_score}/100 ({request.verdict})
Body Snippet: {safe_body}...

Instructions:
1. Return valid JSON only, with no surrounding text or formatting.
2. "summary": A concise 2-sentence executive threat summary.
3. "actions": An array of 3 specific, actionable steps for a junior analyst.
4. Do NOT include any citations or bracketed references such as [1], [2], etc.
5. Escape all double quotes inside strings, e.g. "The user said \"Hello\"".

Output format:
{{
  "summary": "...",
  "actions": ["...", "...", "..."]
}}
"""

    payload = {
        "model": "sonar-pro",
        "messages": [
            {
                "role": "system",
                "content": (
                    "You are a cybersecurity expert assistant. "
                    "Always respond with STRICT JSON only. No markdown, no prose."
                ),
            },
            {"role": "user", "content": prompt},
        ],
        "temperature": 0.1,
    }

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }

    try:
        print("🤖 Sending request to AI...")
        response = requests.post(
            "https://api.perplexity.ai/chat/completions",
            json=payload,
            headers=headers,
            timeout=20,
        )

        if response.status_code != 200:
            print(f"⚠️ Perplexity API error ({response.status_code}): {response.text}")
            raise HTTPException(
                status_code=response.status_code,
                detail=f"AI provider error: {response.text}",
            )

        data = response.json()
        content = data["choices"][0]["message"]["content"]

        # Extract JSON block
        start_idx = content.find("{")
        end_idx = content.rfind("}")

        if start_idx == -1 or end_idx == -1:
            print(f"❌ Invalid AI output format: {content}")
            raise ValueError("AI did not return a JSON object")

        clean_json_str = content[start_idx : end_idx + 1]

        try:
            json_data = json.loads(clean_json_str)
        except json.JSONDecodeError as e:
            print(f"❌ Raw invalid JSON content: {clean_json_str}")
            raise e

        # Final safety pass: strip any remaining simple numeric citations [1], [2, 3]
        citation_pattern = r"\[\d+(?:\s*,\s*\d+)*\]"

        if isinstance(json_data, dict):
            if "summary" in json_data and isinstance(json_data["summary"], str):
                json_data["summary"] = re.sub(citation_pattern, "", json_data["summary"]).strip()

            if "actions" in json_data and isinstance(json_data["actions"], list):
                cleaned_actions = []
                for idx, action in enumerate(json_data["actions"], start=1):
                    if isinstance(action, str):
                        # Remove citations and add hardcoded numbering
                        clean_action = re.sub(citation_pattern, "", action).strip()
                        numbered_action = f"{idx}. {clean_action}"
                        cleaned_actions.append(numbered_action)
                    else:
                        cleaned_actions.append(action)
                json_data["actions"] = cleaned_actions

        return json_data

    except json.JSONDecodeError as je:
        print(f"❌ JSON parse error: {je}")
        return {
            "summary": "AI generated content, but it was not valid JSON. Please try again.",
            "actions": ["1. Check server logs for raw AI output and investigate parsing issues."],
        }
    except Exception as e:
        print(f"❌ General error in /ai-summary: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# ============================================================================
# CASE MANAGEMENT ENDPOINTS
# ============================================================================

@router.get("/cases", response_model=List[CaseResponse])
def list_cases(skip: int = 0, limit: int = 50, verdict: str = None, db: Session = Depends(get_db)):
    query = db.query(PhishingCase)
    if verdict:
        query = query.filter(PhishingCase.verdict == verdict.upper())
    return query.order_by(desc(PhishingCase.received_time)).offset(skip).limit(limit).all()

@router.get("/cases/{case_id}", response_model=dict)
def get_case(case_id: int, db: Session = Depends(get_db)):
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
        "breakdown": case.breakdown,
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
    service = AnalysisService(db)
    content = service.get_email_content(case_id)
    if not content:
        raise HTTPException(status_code=404, detail="Content not found or file missing")
    return {"content": content}

@router.delete("/cases/{case_id}")
def delete_case(case_id: int, db: Session = Depends(get_db)):
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
    total = db.query(func.count(PhishingCase.id)).scalar()
    malicious = db.query(func.count(PhishingCase.id)).filter(PhishingCase.verdict == 'MALICIOUS').scalar()
    suspicious = db.query(func.count(PhishingCase.id)).filter(PhishingCase.verdict == 'SUSPICIOUS').scalar()
    clean = db.query(func.count(PhishingCase.id)).filter(PhishingCase.verdict == 'CLEAN').scalar()
    avg_time = db.query(func.avg(PhishingCase.processing_time)).scalar() or 0
    
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
    return {"status": "healthy", "timestamp": datetime.utcnow(), "service": "PhishGuard Pro"}