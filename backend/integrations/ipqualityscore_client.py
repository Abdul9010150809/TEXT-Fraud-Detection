"""
IPQualityScore (IPQS) Fraud & Spam Detection Client
Sign up: https://www.ipqualityscore.com/create-account
Free: 5,000 requests/month
"""

import os
import httpx
import logging

logger = logging.getLogger(__name__)

IPQS_API_KEY = os.getenv("IPQUALITYSCORE_API_KEY", "")
# Message validation endpoint
IPQS_MESSAGE_URL = "https://ipqualityscore.com/api/json/message/{api_key}"
# URL scanner endpoint
IPQS_URL_SCAN = "https://ipqualityscore.com/api/json/url/{api_key}/{url}"


async def check_message(text: str) -> dict:
    """
    Check a text message for spam/fraud probability using IPQS.
    Returns:
        {
            "spam_score": 0-100,
            "fraud_score": 0-100,
            "disposable": True/False,
            "risky": True/False,
            "verdict": "clean" | "suspicious" | "spam",
            "source": "ipqualityscore",
            "error": None or message
        }
    """
    if not IPQS_API_KEY or os.getenv("USE_IPQUALITYSCORE", "1") == "0":
        return _fallback_msg("IPQualityScore API key not configured or disabled")

    try:
        url = IPQS_MESSAGE_URL.format(api_key=IPQS_API_KEY)
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(url, data={"message": text[:5000]})
            response.raise_for_status()
            data = response.json()

        if not data.get("success"):
            return _fallback_msg(data.get("message", "IPQS API error"))

        spam_score = data.get("spam_score", 0) * 100  # API returns 0-1
        fraud_score = data.get("fraud_score", 0) * 100

        if spam_score >= 75 or fraud_score >= 75:
            verdict = "spam"
        elif spam_score >= 40 or fraud_score >= 40:
            verdict = "suspicious"
        else:
            verdict = "clean"

        return {
            "spam_score": round(spam_score, 1),
            "fraud_score": round(fraud_score, 1),
            "disposable": data.get("disposable", False),
            "risky": data.get("risky", False),
            "verdict": verdict,
            "source": "ipqualityscore",
            "error": None
        }

    except Exception as e:
        logger.error(f"IPQS message check error: {e}")
        return _fallback_msg(str(e))


async def check_url(url_to_check: str) -> dict:
    """
    Check a URL for fraud/phishing using IPQS URL scanner.
    """
    if not IPQS_API_KEY or os.getenv("USE_IPQUALITYSCORE", "1") == "0":
        return _fallback_url("IPQualityScore API key not configured or disabled")

    try:
        import urllib.parse
        encoded_url = urllib.parse.quote(url_to_check, safe='')
        api_url = IPQS_URL_SCAN.format(api_key=IPQS_API_KEY, url=encoded_url)

        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(api_url)
            response.raise_for_status()
            data = response.json()

        return {
            "url": url_to_check,
            "risk_score": data.get("risk_score", 0),
            "phishing": data.get("phishing", False),
            "malware": data.get("malware", False),
            "suspicious": data.get("suspicious", False),
            "domain": data.get("domain", ""),
            "source": "ipqualityscore",
            "error": None
        }
    except Exception as e:
        logger.error(f"IPQS URL check error: {e}")
        return _fallback_url(str(e))


def _fallback_msg(reason: str) -> dict:
    return {"spam_score": 0, "fraud_score": 0, "disposable": False,
            "risky": False, "verdict": "unknown", "source": "ipqualityscore", "error": reason}


def _fallback_url(reason: str) -> dict:
    return {"url": "", "risk_score": 0, "phishing": False, "malware": False,
            "suspicious": False, "domain": "", "source": "ipqualityscore", "error": reason}
