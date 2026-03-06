"""
Text Analysis API Router
Provides /analyze endpoint for AI text classification
"""

import asyncio
import logging
import re
import time
from typing import Dict, Any, Optional, List
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field, field_validator
from datetime import datetime, UTC

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/analyze", tags=["analyze"])

# Simple in-memory rate limiter (per-IP) - production should use Redis
_RATE_LIMIT_STORE: Dict[str, Dict[str, Any]] = {}
_RATE_LIMIT_LOCK = asyncio.Lock()
RATE_LIMIT = 30  # requests
RATE_WINDOW = 60  # seconds

# Maximum text length
MAX_TEXT_LENGTH = 10000

# Analysis log for dataset expansion
_ANALYSIS_LOG: list = []


async def rate_limiter(request: Request):
    """Simple rate limiter based on client IP"""
    client = request.client.host if request.client else "anonymous"
    now = time.time()
    async with _RATE_LIMIT_LOCK:
        rec = _RATE_LIMIT_STORE.get(client)
        if not rec or now - rec['start'] > RATE_WINDOW:
            _RATE_LIMIT_STORE[client] = {'count': 1, 'start': now}
            return
        if rec['count'] >= RATE_LIMIT:
            raise HTTPException(
                status_code=429, 
                detail="Too many requests. Please try again later."
            )
        rec['count'] += 1


class TextAnalyzeRequest(BaseModel):
    """Request model for text analysis"""
    text: str = Field(
        ..., 
        min_length=1, 
        max_length=MAX_TEXT_LENGTH,
        description="The text message to analyze"
    )
    # Text specific signals (15 features)
    urgency_deadline: bool = Field(False, description="Detects fabricated deadlines or false urgency.")
    financial_lure: bool = Field(False, description="Detects lottery, prize, or unlikely financial reward lures.")
    impersonation: bool = Field(False, description="Detects spoofing of authority figures, brands, or executives.")
    credential_theft: bool = Field(False, description="Detects direct requests for passwords, OTPs, or PII.")
    suspicious_url: bool = Field(False, description="Detects obfuscated, deceptive, or malicious URLs within text.")
    ai_generated_tone: bool = Field(False, description="Detects hyper-formal, repetitive, or anomalous AI-generated phrasing.")
    spelling_grammar_forensics: bool = Field(False, description="Detects intentional spelling errors used to bypass basic spam filters.")
    social_engineering: bool = Field(False, description="Detects psychological manipulation strategies (fear, greed, trust).")
    crypto_pitch: bool = Field(False, description="Detects 'get-rich-quick' crypto investment or mining schemes.")
    threat_extortion: bool = Field(False, description="Detects blackmail, sextortion, or legal threats.")
    job_scam: bool = Field(False, description="Detects fake employment offers requiring upfront payment.")
    spam_marketing: bool = Field(False, description="Detects unsolicited bulk marketing spam.")
    regional_upi_fraud: bool = Field(False, description="Detects localized payment system, UPI, or cashapp scams.")
    tech_support_refund: bool = Field(False, description="Detects fake tech support or overpayment refund scams.")
    user_id: Optional[str] = Field(
        None, 
        description="Optional user ID for logging"
    )
    metadata: Optional[Dict[str, Any]] = Field(
        default_factory=dict,
        description="Optional metadata"
    )
    
    @field_validator("text")
    @classmethod
    def text_must_be_meaningful(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("Text cannot be empty or whitespace only")
        return value.strip()


class TextErrorAnalysis(BaseModel):
    typos: List[str]
    grammar_issues: List[str]
    score: int

class LinkIntelligence(BaseModel):
    domain_age_days: int
    tld_risk: bool
    brand_spoofing: bool
    google_presence: str
    reputation_summary: str

class TextAnalyzeResponse(BaseModel):
    """Response model for text analysis - V2"""
    is_fraud: bool
    risk_score: float
    risk_level: str
    text_category: str = Field(..., description="Type of message detected (e.g., Phishing Attempt, Job Scam, Benign Personal/Business Message)")
    fraud_type: List[str]
    why_fraud: List[str]
    detected_signals: Dict[str, bool]
    link_intelligence: Optional[LinkIntelligence]
    text_error_analysis: Optional[TextErrorAnalysis] = None
    author_prediction: str = Field("Unknown", description="Predicts if text is 'AI Generated' or 'Human Typed'")
    api_signals: Optional[List[Dict[str, Any]]] = Field(None, description="Individual API verdict signals")
    api_report: Optional[Dict[str, Any]] = Field(None, description="Raw multi-API combined report")
    recommended_action: List[str]
    confidence: float
    processing_time: float
    timestamp: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())


class HealthResponse(BaseModel):
    """Health check response"""
    status: str = "healthy"
    model: str = "text-classifier-v2"
    version: str = "2.0.0"


def sanitize_text(text: str) -> str:
    """Sanitize input text"""
    if not text:
        return text
    # Remove excessive whitespace
    cleaned = " ".join(text.strip().split())
    # Remove null bytes and control characters
    cleaned = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', cleaned)
    return cleaned


def log_analysis(request: Dict[str, Any], response: Dict[str, Any]):
    """Log analysis for dataset expansion"""
    log_entry = {
        "timestamp": datetime.now(UTC).isoformat(),
        "request": {
            "text_length": len(request.get("text", "")),
            "user_id": request.get("user_id"),
            "metadata": request.get("metadata", {})
        },
        "response": {
            "is_fraud": response.get("is_fraud"),
            "risk_score": response.get("risk_score"),
            "risk_level": response.get("risk_level"),
            "processing_time": response.get("processing_time")
        }
    }
    _ANALYSIS_LOG.append(log_entry)
    logger.debug(f"Logged analysis: {log_entry}")


@router.post("/text", response_model=TextAnalyzeResponse)
async def analyze_text(
    payload: TextAnalyzeRequest,
    request: Request,
    _rl: None = Depends(rate_limiter)
) -> TextAnalyzeResponse:
    """
    Analyze a text message for fraud classification (V2).
    Runs multi-API analysis via the orchestrator when available.
    """
    
    try:
        # Sanitize input
        text = sanitize_text(payload.text)
        start_time = time.time()
        
        # Import classifier
        from backend.ai_modules.text_classifier import TextClassifier
        
        # Initialize and classify (heuristic baseline)
        classifier = TextClassifier()
        result = classifier.classify(text)
        response_data = result.to_json()
        
        # --- Run external API orchestrator in parallel (non-blocking) ---
        api_report = None
        api_signals = None
        try:
            from backend.integrations.api_orchestrator import run_full_analysis
            api_report = await run_full_analysis(text)
            api_signals = api_report.get("api_signals", [])
            
            # Blend the combined API risk score with the heuristic score
            api_score = api_report.get("combined_risk_score", 0)
            if api_score > 0:
                # Weighted blend: 40% heuristic, 60% real APIs
                blended = int(response_data["risk_score"] * 0.4 + api_score * 0.6)
                response_data["risk_score"] = blended
                
                # Update risk level from blended score
                if blended >= 80:
                    response_data["risk_level"] = "Critical"
                    response_data["is_fraud"] = True
                elif blended >= 60:
                    response_data["risk_level"] = "High"
                    response_data["is_fraud"] = True
                elif blended >= 35:
                    response_data["risk_level"] = "Suspicious"
                else:
                    response_data["risk_level"] = "Safe"
                    response_data["is_fraud"] = False
                    
        except ImportError:
            logger.info("API orchestrator not available, using heuristic only")
        except Exception as api_err:
            logger.warning(f"API orchestrator error (continuing without): {api_err}")
        
        response_data["timestamp"] = datetime.now(UTC).isoformat()
        response_data["processing_time"] = time.time() - start_time
        response_data["api_signals"] = api_signals
        response_data["api_report"] = api_report
        
        # Log analysis
        log_analysis(payload.model_dump(), response_data)
        
        logger.info(
            f"Analyzed text: is_fraud={response_data['is_fraud']}, "
            f"score={response_data['risk_score']}, "
            f"time={float(response_data.get('processing_time', 0)):.3f}s"
        )
        
        return TextAnalyzeResponse(**response_data)
        
    except ImportError as e:
        logger.error(f"Failed to import text classifier: {e}")
        raise HTTPException(
            status_code=500, 
            detail="Classification service unavailable"
        )
    except Exception as e:
        logger.exception(f"Error analyzing text: {e}")
        raise HTTPException(
            status_code=500, 
            detail="Internal server error"
        )


@router.get("/health")
async def health_check() -> HealthResponse:
    """Health check endpoint"""
    return HealthResponse()


@router.get("/log")
async def get_analysis_log():
    """Get analysis log (for debugging/dataset export)"""
    return {
        "count": len(_ANALYSIS_LOG),
        "entries": _ANALYSIS_LOG[-100:]  # Last 100 entries
    }


@router.delete("/log")
async def clear_analysis_log():
    """Clear the analysis log"""
    global _ANALYSIS_LOG
    _ANALYSIS_LOG = []
    return {"status": "cleared", "count": 0}
