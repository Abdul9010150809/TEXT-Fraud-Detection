"""
Email Analysis API Router
Provides endpoint for email spam/fraud detection and risk scoring
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

router = APIRouter(prefix="/api/v1/email", tags=["email-analysis"])

# Simple in-memory rate limiter (per-IP)
_RATE_LIMIT_STORE: Dict[str, Dict[str, Any]] = {}
_RATE_LIMIT_LOCK = asyncio.Lock()
RATE_LIMIT = 50  # requests
RATE_WINDOW = 60  # seconds


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


class EmailAnalyzeRequest(BaseModel):
    """Request model for email analysis"""
    email: str = Field(
        ..., 
        min_length=1, 
        max_length=10000,
        description="The email content (subject + body) to analyze"
    )
    sender: Optional[str] = Field(
        None,
        description="Email sender address (optional)"
    )
    subject: Optional[str] = Field(
        None,
        description="Email subject line (optional)"
    )
    
    @field_validator("email")
    @classmethod
    def email_must_be_valid(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("Email content cannot be empty")
        return value


class EmailAnalyzeResponse(BaseModel):
    """Response model for email analysis"""
    is_spam: bool
    risk_score: float
    risk_level: str
    message_type: str
    grammar_score: int
    scam_type: List[str]
    why_spam: List[str]
    detected_signals: Dict[str, bool]
    sender_analysis: Optional[Dict[str, Any]] = None
    subject_analysis: Optional[Dict[str, Any]] = None
    content_analysis: Dict[str, Any]
    recommended_action: List[str]
    confidence: float
    processing_time: float
    timestamp: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())


class EmailAnalyzer:
    """Email spam and fraud analyzer"""
    
    SPAM_SENDER_PATTERNS = {
        "noreply", "no-reply", "donotreply", "notification", "alert",
        "automated", "service", "support", "team", "admin"
    }
    
    SUSPICIOUS_SENDER_TLDS = {
        "tk", "ml", "ga", "cf", "gq", "xyz", "top", "click"
    }
    
    TRUSTED_DOMAINS = {
        "gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "icloud.com",
        "protonmail.com", "zoho.com", "mail.com", "aol.com", "live.com"
    }
    
    SPAM_SUBJECT_KEYWORDS = {
        "urgent", "important", "action required", "verify", "confirm",
        "suspended", "blocked", "expired", "winner", "prize", "free",
        "claim", "congratulations", "limited time", "act now", "final notice"
    }
    
    PHISHING_INDICATORS = {
        "verify account", "confirm identity", "update payment", "suspended account",
        "unusual activity", "security alert", "immediate action", "click here",
        "reset password", "confirm email", "validate information"
    }
    
    def analyze_email(self, email_content: str, sender: Optional[str] = None, subject: Optional[str] = None) -> Dict[str, Any]:
        """Analyze email for spam/fraud"""
        start_time = time.time()
        
        # Use the text classifier for content analysis
        from backend.ai_modules.text_classifier import TextClassifier
        text_classifier = TextClassifier()
        
        # Analyze the email content using our text classifier
        content_result = text_classifier.classify(email_content)
        content_data = content_result.to_json()
        
        # Initialize email-specific signals
        email_signals = {
            "suspicious_sender": False,
            "suspicious_subject": False,
            "phishing_content": False,
            "spam_keywords": False,
            "spoofed_domain": False,
            "urgent_language": False,
        }
        
        reasons = list(content_data.get("why_fraud", []))
        score_additions = 0
        
        # Analyze sender if provided
        sender_analysis = None
        if sender:
            sender_analysis = self._analyze_sender(sender)
            if sender_analysis["is_suspicious"]:
                email_signals["suspicious_sender"] = True
                score_additions += 20
                reasons.append(f"Suspicious sender: {sender_analysis['reason']}")
        
        # Analyze subject if provided
        subject_analysis = None
        if subject:
            subject_analysis = self._analyze_subject(subject)
            if subject_analysis["is_suspicious"]:
                email_signals["suspicious_subject"] = True
                score_additions += 25
                reasons.append(f"Suspicious subject: {subject_analysis['reason']}")
        
        # Check for phishing indicators in content
        phishing_count = sum(1 for phrase in self.PHISHING_INDICATORS if phrase in email_content.lower())
        if phishing_count > 0:
            email_signals["phishing_content"] = True
            score_additions += min(30, 15 + phishing_count * 10)
            reasons.append("Email contains phishing-style phrases and requests.")
        
        # Calculate final risk score (blend content + email-specific)
        base_score = content_data.get("risk_score", 0)
        total_score = min(100, int(base_score * 0.6 + score_additions * 0.4))
        
        # Apply multiplier for multiple signals
        all_signals = {**content_data.get("detected_signals", {}), **email_signals}
        detected_count = sum(1 for value in all_signals.values() if value)
        if detected_count >= 5:
            total_score = min(100, int(total_score * 1.25))
        elif detected_count >= 3:
            total_score = min(100, int(total_score * 1.15))
        
        # Determine risk level
        if total_score >= 70:
            risk_level = "Critical"
            is_spam = True
        elif total_score >= 50:
            risk_level = "High"
            is_spam = True
        elif total_score >= 30:
            risk_level = "Suspicious"
            is_spam = False
        else:
            risk_level = "Safe"
            is_spam = False
        
        # Determine scam types
        scam_types = self._derive_scam_types(all_signals, content_data)
        
        # Generate recommendations
        recommendations = self._generate_recommendations(all_signals, risk_level)
        
        # Compute confidence
        confidence = self._compute_confidence(total_score, detected_count)
        
        # Content analysis summary
        message_type = content_data.get("text_category", "General Message")
        grammar_score = int(content_data.get("text_error_analysis", {}).get("score", 60))
        content_analysis = {
            "text_category": message_type,
            "grammar_score": grammar_score,
            "author_style": content_data.get("author_prediction", "Unknown"),
            "fraud_signals": content_data.get("fraud_type", []),
        }
        
        if not reasons:
            reasons = ["No significant spam/fraud indicators detected."]
        
        processing_time = time.time() - start_time
        
        return {
            "is_spam": is_spam,
            "risk_score": total_score,
            "risk_level": risk_level,
            "message_type": message_type,
            "grammar_score": grammar_score,
            "scam_type": scam_types,
            "why_spam": reasons,
            "detected_signals": all_signals,
            "sender_analysis": sender_analysis,
            "subject_analysis": subject_analysis,
            "content_analysis": content_analysis,
            "recommended_action": recommendations,
            "confidence": confidence,
            "processing_time": processing_time,
        }
    
    def _analyze_sender(self, sender: str) -> Dict[str, Any]:
        """Analyze email sender address"""
        sender_lower = sender.lower()
        is_suspicious = False
        reason = ""
        
        # Extract domain
        domain = ""
        if "@" in sender:
            domain = sender.split("@")[-1].lower()
        
        # Check for suspicious patterns
        if any(pattern in sender_lower for pattern in self.SPAM_SENDER_PATTERNS):
            is_suspicious = True
            reason = "Generic sender address (noreply, automated, etc.)"
        elif domain and any(tld in domain for tld in self.SUSPICIOUS_SENDER_TLDS):
            is_suspicious = True
            reason = "Sender domain uses high-risk TLD"
        elif "@" not in sender:
            is_suspicious = True
            reason = "Invalid email format"
        
        return {
            "email": sender,
            "domain": domain,
            "is_suspicious": is_suspicious,
            "is_trusted_domain": domain in self.TRUSTED_DOMAINS,
            "reason": reason or "Sender appears normal"
        }
    
    def _analyze_subject(self, subject: str) -> Dict[str, Any]:
        """Analyze email subject line"""
        subject_lower = subject.lower()
        is_suspicious = False
        reason = ""
        
        # Check for spam keywords
        spam_hits = sum(1 for keyword in self.SPAM_SUBJECT_KEYWORDS if keyword in subject_lower)
        if spam_hits >= 2:
            is_suspicious = True
            reason = "Contains multiple spam trigger words"
        elif spam_hits == 1:
            is_suspicious = True
            reason = "Contains spam-like urgency language"
        
        # Check for excessive caps
        if len(subject) > 10 and sum(1 for c in subject if c.isupper()) / len(subject) > 0.6:
            is_suspicious = True
            reason = "Excessive capitalization"
        
        return {
            "subject": subject,
            "spam_keyword_count": spam_hits,
            "is_suspicious": is_suspicious,
            "reason": reason or "Subject appears normal"
        }
    
    def _derive_scam_types(self, signals: Dict[str, bool], content_data: Dict[str, Any]) -> List[str]:
        """Determine scam types"""
        scam_types = []
        
        # From content analysis
        content_fraud_types = content_data.get("fraud_type", [])
        scam_types.extend(content_fraud_types)
        
        # Email-specific
        if signals.get("phishing_content"):
            scam_types.append("Email Phishing")
        if signals.get("suspicious_sender"):
            scam_types.append("Sender Spoofing")
        if signals.get("spam_keywords"):
            scam_types.append("Email Spam")
        
        if not scam_types or scam_types == ["None"]:
            return ["None"]
        
        return sorted(set(scam_types))
    
    def _generate_recommendations(self, signals: Dict[str, bool], risk_level: str) -> List[str]:
        """Generate action recommendations"""
        actions = []
        
        if risk_level in {"High", "Critical"}:
            actions.append("DO NOT respond to this email or click any links.")
            actions.append("Do not provide any personal or financial information.")
        
        if signals.get("phishing_content"):
            actions.append("Report this email as phishing to your email provider.")
        if signals.get("suspicious_sender"):
            actions.append("Verify the sender through an official channel before responding.")
        if signals.get("suspicious_subject"):
            actions.append("Be cautious of urgent/pressuring subject lines.")
        
        if risk_level == "Suspicious":
            actions.append("Proceed with caution - verify sender identity independently.")
        elif risk_level == "Safe":
            actions.append("Email appears relatively safe, but stay vigilant with links/attachments.")
        
        if not actions:
            actions.append("No major red flags detected, but exercise normal email caution.")
        
        return actions[:6]
    
    def _compute_confidence(self, score: int, detected_count: int) -> float:
        """Calculate confidence level"""
        base = 0.55
        score_factor = min(0.30, score / 350)
        signal_factor = min(0.12, detected_count * 0.025)
        
        return round(min(0.97, base + score_factor + signal_factor), 2)


@router.post("/analyze", response_model=EmailAnalyzeResponse)
async def analyze_email(
    payload: EmailAnalyzeRequest,
    request: Request,
    _rl: None = Depends(rate_limiter)
) -> EmailAnalyzeResponse:
    """
    Analyze an email for spam and fraud indicators.
    Returns risk score, scam type, and recommendations.
    """
    
    try:
        analyzer = EmailAnalyzer()
        result = analyzer.analyze_email(
            payload.email,
            sender=payload.sender,
            subject=payload.subject
        )
        
        logger.info(
            f"Analyzed email - spam={result['is_spam']}, score={result['risk_score']}"
        )
        
        return EmailAnalyzeResponse(**result)
        
    except Exception as e:
        logger.exception(f"Error analyzing email: {e}")
        raise HTTPException(
            status_code=500, 
            detail="Internal server error during email analysis"
        )


@router.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "service": "email-analyzer",
        "version": "1.0.0"
    }
