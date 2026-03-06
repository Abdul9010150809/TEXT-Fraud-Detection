"""
Link Analysis API Router
Provides endpoint for URL/link spam detection and risk scoring
"""

import asyncio
import logging
import re
import time
from typing import Dict, Any, Optional, List
from urllib.parse import urlparse
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field, field_validator
from datetime import datetime, UTC

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/link", tags=["link-analysis"])

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


class LinkAnalyzeRequest(BaseModel):
    """Request model for link analysis"""
    url: str = Field(
        ..., 
        min_length=1, 
        max_length=2048,
        description="The URL to analyze for spam/fraud"
    )
    
    @field_validator("url")
    @classmethod
    def url_must_be_valid(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("URL cannot be empty")
        # Add http:// if no scheme
        if not re.match(r'^https?://', value, re.IGNORECASE):
            value = 'http://' + value
        return value


class LinkAnalyzeResponse(BaseModel):
    """Response model for link analysis"""
    is_spam: bool
    risk_score: float
    risk_level: str
    message_type: str
    grammar_score: int
    url: str
    domain: str
    scam_type: List[str]
    why_spam: List[str]
    detected_signals: Dict[str, bool]
    domain_analysis: Dict[str, Any]
    recommended_action: List[str]
    confidence: float
    processing_time: float
    timestamp: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())


class LinkAnalyzer:
    """Link spam and fraud analyzer"""
    
    HIGH_RISK_TLDS = {
        "xyz", "top", "click", "work", "tk", "ml", "gq", "cf", "ga", "pw",
        "loan", "download", "bid", "stream", "review", "science", "racing"
    }
    
    SHORTENER_DOMAINS = {
        "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly",
        "ow.ly", "buff.ly", "adf.ly", "tiny.cc", "short.io", "rb.gy"
    }
    
    SAFE_DOMAINS = {
        "google.com", "github.com", "wikipedia.org", "microsoft.com", "apple.com",
        "amazon.com", "paypal.com", "facebook.com", "twitter.com", "instagram.com",
        "linkedin.com", "youtube.com", "reddit.com", "stackoverflow.com",
        "sbi.co.in", "hdfcbank.com", "icicibank.com", "axisbank.com"
    }
    
    PHISHING_KEYWORDS = {
        "verify", "secure", "update", "login", "account", "confirm",
        "validate", "recover", "restore", "unlock", "limited", "suspended"
    }
    
    SCAM_KEYWORDS = {
        "free", "prize", "winner", "claim", "urgent", "alert", "warning",
        "confirm", "reset", "blocked", "suspended", "payment", "refund"
    }
    
    def analyze_url(self, url: str) -> Dict[str, Any]:
        """Analyze URL for spam/fraud indicators"""
        start_time = time.time()
        
        # Parse URL
        parsed = urlparse(url)
        domain = (parsed.netloc or "").lower().replace("www.", "")
        path = parsed.path.lower()
        scheme = parsed.scheme.lower()
        
        # Extract TLD
        tld = domain.split(".")[-1] if "." in domain else ""
        url_quality = self._analyze_url_quality(url, domain, path)
        
        # Initialize signals
        signals = {
            "high_risk_tld": False,
            "url_shortener": False,
            "phishing_keywords": False,
            "scam_keywords": False,
            "no_https": False,
            "suspicious_domain": False,
            "ip_address_url": False,
            "excessive_subdomains": False,
            "suspicious_path": False,
        }
        
        score_breakdown = {}
        reasons = []
        
        # Check if it's a known safe domain
        is_safe_domain = domain in self.SAFE_DOMAINS
        is_shortener = domain in self.SHORTENER_DOMAINS
        
        # TLD risk check
        if tld in self.HIGH_RISK_TLDS:
            signals["high_risk_tld"] = True
            score_breakdown["high_risk_tld"] = 25
            reasons.append(f"Uses high-risk TLD (.{tld}) often associated with spam/scams.")
        
        # URL shortener check
        if is_shortener:
            signals["url_shortener"] = True
            score_breakdown["url_shortener"] = 30
            reasons.append("URL shortener detected - destination is hidden, high phishing risk.")
        
        # HTTPS check
        if scheme != "https" and not is_safe_domain:
            signals["no_https"] = True
            score_breakdown["no_https"] = 15
            reasons.append("No HTTPS encryption - connection may not be secure.")
        
        # Phishing keyword check
        phishing_hits = sum(1 for keyword in self.PHISHING_KEYWORDS if keyword in domain or keyword in path)
        if phishing_hits > 0:
            signals["phishing_keywords"] = True
            score_breakdown["phishing_keywords"] = min(35, 15 + phishing_hits * 10)
            reasons.append("Contains phishing-related keywords in domain/path (verify, login, secure, etc.).")
        
        # Scam keyword check
        scam_hits = sum(1 for keyword in self.SCAM_KEYWORDS if keyword in domain or keyword in path)
        if scam_hits > 0:
            signals["scam_keywords"] = True
            score_breakdown["scam_keywords"] = min(25, 10 + scam_hits * 8)
            reasons.append("Contains scam-related keywords (free, prize, urgent, etc.).")
        
        # IP address URL check
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain):
            signals["ip_address_url"] = True
            score_breakdown["ip_address_url"] = 40
            reasons.append("URL uses IP address instead of domain name - highly suspicious.")
        
        # Excessive subdomains check
        subdomain_count = domain.count('.')
        if subdomain_count >= 3 and not is_safe_domain:
            signals["excessive_subdomains"] = True
            score_breakdown["excessive_subdomains"] = 20
            reasons.append("Excessive subdomains detected - may indicate domain spoofing.")
        
        # Suspicious domain pattern check
        suspicious_patterns = ["-secure-", "-verify-", "-update-", "-login-", "-account-"]
        if any(pattern in domain for pattern in suspicious_patterns):
            signals["suspicious_domain"] = True
            score_breakdown["suspicious_domain"] = 30
            reasons.append("Domain contains suspicious patterns often used in phishing attacks.")
        
        # Suspicious path check
        suspicious_path_patterns = ["signin", "verify", "confirm", "account", "payment", "secure"]
        if any(pattern in path for pattern in suspicious_path_patterns) and not is_safe_domain:
            signals["suspicious_path"] = True
            score_breakdown["suspicious_path"] = 15
            reasons.append("URL path contains suspicious authentication-related keywords.")
        
        # Calculate total risk score
        total_score = sum(score_breakdown.values())
        
        # Apply multiplier for multiple signals
        detected_count = sum(1 for value in signals.values() if value)
        if detected_count >= 4:
            total_score = min(100, int(total_score * 1.3))
        elif detected_count == 3:
            total_score = min(100, int(total_score * 1.15))
        
        # Safe domain override
        if is_safe_domain and scheme == "https":
            total_score = 0
            reasons = ["This is a known safe domain with HTTPS encryption."]
        
        total_score = max(0, min(100, total_score))
        
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
        scam_types = self._derive_scam_types(signals, domain, path)
        message_type = "Suspicious Link" if scam_types != ["None"] else "Benign Link"

        risk_grammar_penalty = 0
        if signals["high_risk_tld"]:
            risk_grammar_penalty += 18
        if signals["url_shortener"]:
            risk_grammar_penalty += 15
        if signals["suspicious_domain"] or signals["phishing_keywords"]:
            risk_grammar_penalty += 12
        if signals["ip_address_url"]:
            risk_grammar_penalty += 20
        if signals["no_https"]:
            risk_grammar_penalty += 8
        grammar_score = max(20, url_quality["score"] - risk_grammar_penalty)
        
        # Generate recommendations
        recommendations = self._generate_recommendations(signals, risk_level, is_safe_domain)
        
        # Compute confidence
        confidence = self._compute_confidence(total_score, detected_count, is_safe_domain)
        
        # Domain analysis
        domain_analysis = {
            "domain": domain,
            "tld": tld,
            "scheme": scheme,
            "is_shortener": is_shortener,
            "is_safe_domain": is_safe_domain,
            "subdomain_count": subdomain_count,
            "path_length": len(path),
            "url_quality_issues": url_quality["issues"],
        }
        
        if not reasons:
            reasons = ["No high-risk indicators detected."]
        
        processing_time = time.time() - start_time
        
        return {
            "is_spam": is_spam,
            "risk_score": total_score,
            "risk_level": risk_level,
            "message_type": message_type,
            "grammar_score": grammar_score,
            "url": url,
            "domain": domain,
            "scam_type": scam_types,
            "why_spam": reasons,
            "detected_signals": signals,
            "domain_analysis": domain_analysis,
            "recommended_action": recommendations,
            "confidence": confidence,
            "processing_time": processing_time,
        }
    
    def _derive_scam_types(self, signals: Dict[str, bool], domain: str, path: str) -> List[str]:
        """Determine the type of scam based on signals"""
        scam_types = []
        
        if signals["phishing_keywords"]:
            scam_types.append("Phishing")
        if signals["url_shortener"]:
            scam_types.append("Hidden Destination")
        if signals["ip_address_url"] or signals["suspicious_domain"]:
            scam_types.append("Domain Spoofing")
        if signals["scam_keywords"]:
            scam_types.append("Social Engineering")
        if signals["high_risk_tld"]:
            scam_types.append("High-Risk Domain")
        
        if not scam_types:
            scam_types = ["None"]
        
        return sorted(set(scam_types))
    
    def _generate_recommendations(self, signals: Dict[str, bool], risk_level: str, is_safe_domain: bool) -> List[str]:
        """Generate action recommendations"""
        actions = []
        
        if risk_level in {"High", "Critical"}:
            actions.append("DO NOT CLICK this link - high fraud risk detected.")
            actions.append("Do not enter any personal, financial, or login information.")
        
        if signals["url_shortener"]:
            actions.append("Avoid URL shorteners from unknown sources - use link expanders to preview destination.")
        if signals["no_https"]:
            actions.append("Link does not use HTTPS - connection is not encrypted.")
        if signals["phishing_keywords"] or signals["suspicious_domain"]:
            actions.append("Verify the sender through an official channel before clicking.")
        if signals["ip_address_url"]:
            actions.append("IP-based URLs are highly unusual - likely malicious.")
        
        if is_safe_domain:
            actions.append("This appears to be a legitimate domain, but always verify the exact URL.")
        
        if not actions:
            actions.append("Link appears relatively safe, but exercise caution with unknown sources.")
        
        return actions[:6]
    
    def _compute_confidence(self, score: int, detected_count: int, is_safe_domain: bool) -> float:
        """Calculate confidence level"""
        base = 0.60
        score_factor = min(0.25, score / 400)
        signal_factor = min(0.10, detected_count * 0.02)
        domain_factor = 0.05 if is_safe_domain else 0.0
        
        return round(min(0.98, base + score_factor + signal_factor + domain_factor), 2)

    def _analyze_url_quality(self, url: str, domain: str, path: str) -> Dict[str, Any]:
        """Estimate URL grammar/quality score (0-100) based on obfuscation patterns."""
        issues: List[str] = []
        penalty = 0

        if "%" in url:
            issues.append("Percent-encoded characters present")
            penalty += 10

        if "@" in url:
            issues.append("Contains @ redirect-style pattern")
            penalty += 20

        if re.search(r"[A-Z]", url) and re.search(r"[a-z]", url):
            issues.append("Mixed case URL tokens")
            penalty += 5

        long_tokens = [part for part in re.split(r"[^a-zA-Z0-9]", f"{domain}{path}") if len(part) >= 18]
        if long_tokens:
            issues.append("Unusually long URL tokens")
            penalty += min(20, 6 * len(long_tokens))

        digit_runs = re.findall(r"\d{4,}", url)
        if digit_runs:
            issues.append("Long numeric sequences in URL")
            penalty += 8

        repeated_separators = re.search(r"([\-_])\1{2,}", url)
        if repeated_separators:
            issues.append("Repeated separator characters")
            penalty += 8

        if len(url) > 120:
            issues.append("Excessively long URL length")
            penalty += 12

        score = max(20, min(100, 100 - penalty))
        return {"score": score, "issues": issues}


@router.post("/analyze", response_model=LinkAnalyzeResponse)
async def analyze_link(
    payload: LinkAnalyzeRequest,
    request: Request,
    _rl: None = Depends(rate_limiter)
) -> LinkAnalyzeResponse:
    """
    Analyze a URL/link for spam and fraud indicators.
    Returns risk score, scam type, and recommendations.
    """
    
    try:
        analyzer = LinkAnalyzer()
        result = analyzer.analyze_url(payload.url)
        
        logger.info(
            f"Analyzed link: {payload.url} - "
            f"spam={result['is_spam']}, score={result['risk_score']}"
        )
        
        return LinkAnalyzeResponse(**result)
        
    except Exception as e:
        logger.exception(f"Error analyzing link: {e}")
        raise HTTPException(
            status_code=500, 
            detail="Internal server error during link analysis"
        )


@router.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "service": "link-analyzer",
        "version": "1.0.0"
    }
