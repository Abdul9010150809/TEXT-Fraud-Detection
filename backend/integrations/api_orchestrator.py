"""
API Orchestrator
Calls all configured free-tier APIs in parallel and combines
their results into a single CombinedRiskReport.

Flow:
  1. LibreTranslate  → translate non-English text
  2. HuggingFace     → BERT spam/scam score
  3. MeaningCloud    → sentiment & irony
  4. IPQualityScore  → fraud probability
  5. URL analysis    → Google Safe Browsing, VirusTotal, PhishTank
  6. Merge all into a CombinedRiskReport
"""

import asyncio
import logging
from typing import Optional

from backend.integrations.huggingface_client import classify_spam
from backend.integrations.meaningcloud_client import analyze_sentiment
from backend.integrations.ipqualityscore_client import check_message
from backend.integrations.url_threat_client import analyze_urls_in_text
from backend.integrations.translation_client import detect_and_translate

logger = logging.getLogger(__name__)


async def run_full_analysis(text: str) -> dict:
    """
    Run all API integrations on the input text and return a CombinedRiskReport.

    Returns:
    {
        "translated_text": str,
        "source_language": str,
        "was_translated": bool,
        "huggingface": { label, score, ... },
        "meaningcloud": { polarity, irony, ... },
        "ipqualityscore": { spam_score, fraud_score, verdict, ... },
        "url_threats": { urls_found, total_threats_detected, ... },
        "combined_risk_score": 0-100,
        "combined_verdict": "Safe" | "Suspicious" | "High" | "Critical",
        "api_signals": [ { name, verdict, score }, ... ]
    }
    """
    # Step 1: Detect language and translate to English if needed
    translation = await detect_and_translate(text, target_lang="en")
    analysis_text = translation.get("translated_text", text)

    # Step 2: Run all APIs in parallel on the (possibly translated) text
    hf_task = classify_spam(analysis_text)
    mc_task = analyze_sentiment(analysis_text)
    ipqs_task = check_message(analysis_text)
    url_task = analyze_urls_in_text(analysis_text)

    hf_result, mc_result, ipqs_result, url_result = await asyncio.gather(
        hf_task, mc_task, ipqs_task, url_task, return_exceptions=True
    )

    # Deal with exceptions (if an API completely fails)
    if isinstance(hf_result, Exception):
        hf_result = {"label": "UNKNOWN", "score": 0, "error": str(hf_result), "source": "huggingface"}
    if isinstance(mc_result, Exception):
        mc_result = {"polarity": "Unknown", "irony": False, "error": str(mc_result), "source": "meaningcloud"}
    if isinstance(ipqs_result, Exception):
        ipqs_result = {"spam_score": 0, "fraud_score": 0, "verdict": "unknown", "error": str(ipqs_result), "source": "ipqualityscore"}
    if isinstance(url_result, Exception):
        url_result = {"urls_found": 0, "total_threats_detected": 0, "error": str(url_result)}

    # Step 3: Compute a combined risk score (0-100)
    combined_score = _compute_combined_score(hf_result, mc_result, ipqs_result, url_result)

    # Step 4: Map to verdict
    if combined_score >= 80:
        verdict = "Critical"
    elif combined_score >= 60:
        verdict = "High"
    elif combined_score >= 35:
        verdict = "Suspicious"
    else:
        verdict = "Safe"

    # Step 5: Build human-readable API signals list
    api_signals = _build_signals(hf_result, mc_result, ipqs_result, url_result)

    return {
        "translated_text": analysis_text,
        "source_language": translation.get("source_language", "unknown"),
        "was_translated": translation.get("was_translated", False),
        "huggingface": hf_result,
        "meaningcloud": mc_result,
        "ipqualityscore": ipqs_result,
        "url_threats": url_result,
        "combined_risk_score": combined_score,
        "combined_verdict": verdict,
        "api_signals": api_signals
    }


def _compute_combined_score(hf: dict, mc: dict, ipqs: dict, url: dict) -> int:
    """Weighted average of all API signals to produce a 0-100 risk score."""
    score = 0
    weight_total = 0

    # --- HuggingFace weight: 30% ---
    if not hf.get("error") and hf.get("label") != "UNKNOWN":
        hf_score = hf.get("score", 0) * 100 if hf.get("label") == "SPAM" else (1 - hf.get("score", 0)) * 100
        score += hf_score * 0.30
        weight_total += 0.30

    # --- IPQualityScore weight: 35% ---
    if not ipqs.get("error"):
        ipqs_score = max(ipqs.get("spam_score", 0), ipqs.get("fraud_score", 0))
        score += ipqs_score * 0.35
        weight_total += 0.35

    # --- MeaningCloud: irony/negative adds 10% ---
    if not mc.get("error"):
        mc_score = 0
        if mc.get("irony"):
            mc_score += 50
        polarity = mc.get("polarity_raw", "NONE")
        if polarity in ("N", "N+"):
            mc_score += 30
        score += mc_score * 0.10
        weight_total += 0.10

    # --- URL threats weight: 25% ---
    if not url.get("error"):
        url_threats = url.get("total_threats_detected", 0)
        url_score = min(url_threats * 40, 100)  # each threat adds 40 points, cap at 100
        score += url_score * 0.25
        weight_total += 0.25

    if weight_total == 0:
        return 0

    # Normalize by actual weight used
    final = int(score / weight_total) if weight_total > 0 else int(score)
    return min(max(final, 0), 100)


def _build_signals(hf: dict, mc: dict, ipqs: dict, url: dict) -> list:
    """Build a list of readable signal badges for the frontend."""
    signals = []

    # HuggingFace
    if not hf.get("error"):
        label = hf.get("label", "UNKNOWN")
        score = round(hf.get("score", 0) * 100, 1)
        is_spam = label == "SPAM"
        signals.append({
            "api": "HuggingFace BERT",
            "icon": "🤗",
            "verdict": "Spam" if is_spam else "Clean",
            "score": score,
            "flagged": is_spam,
            "detail": f"{score}% confidence"
        })

    # IPQS
    if not ipqs.get("error"):
        spam_s = ipqs.get("spam_score", 0)
        fraud_s = ipqs.get("fraud_score", 0)
        ipqs_verdict = ipqs.get("verdict", "unknown")
        signals.append({
            "api": "IPQualityScore",
            "icon": "🛡️",
            "verdict": ipqs_verdict.title(),
            "score": max(spam_s, fraud_s),
            "flagged": ipqs_verdict in ("spam", "suspicious"),
            "detail": f"Spam: {spam_s}% | Fraud: {fraud_s}%"
        })

    # MeaningCloud
    if not mc.get("error"):
        polarity = mc.get("polarity", "Unknown")
        irony = mc.get("irony", False)
        signals.append({
            "api": "MeaningCloud",
            "icon": "🧠",
            "verdict": polarity + (" (Ironic)" if irony else ""),
            "score": mc.get("confidence", 0),
            "flagged": mc.get("polarity_raw") in ("N", "N+") or irony,
            "detail": f"Tone: {polarity}"
        })

    # URL threats
    url_threats = url.get("total_threats_detected", 0)
    urls_found = url.get("urls_found", 0)
    if urls_found > 0:
        signals.append({
            "api": "URL Threat Intel",
            "icon": "🔗",
            "verdict": f"{url_threats} Threat(s) Found" if url_threats > 0 else "No Threats",
            "score": min(url_threats * 40, 100),
            "flagged": url_threats > 0,
            "detail": f"{urls_found} URL(s) checked via Safe Browsing, VirusTotal & PhishTank"
        })

    return signals
