"""
URL Threat Intelligence Client
Checks URLs found in text messages against:
- Google Safe Browsing API (free)
- VirusTotal API (4 req/min free)
- PhishTank (public free database)

Sign up links:
- Google Safe Browsing: https://console.cloud.google.com/apis/library/safebrowsing.googleapis.com
- VirusTotal: https://www.virustotal.com/gui/join-us
- PhishTank: https://www.phishtank.com/register.php
"""

import os
import re
import asyncio
import httpx
import base64
import logging
from typing import List

logger = logging.getLogger(__name__)

GSB_API_KEY = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "")
VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
PHISHTANK_APP_KEY = os.getenv("PHISHTANK_APP_KEY", "")

GSB_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
VT_URL = "https://www.virustotal.com/api/v3/urls"
PHISHTANK_URL = "https://checkurl.phishtank.com/checkurl/"

URL_REGEX = re.compile(
    r'https?://[^\s<>"{}|\\^`\[\]]+|'
    r'www\.[^\s<>"{}|\\^`\[\]]+'
    r'|bit\.ly/[^\s]+|tinyurl\.com/[^\s]+'
)


def extract_urls(text: str) -> List[str]:
    """Extract all URLs from a text message."""
    found = URL_REGEX.findall(text)
    clean = []
    for url in found:
        if not url.startswith("http"):
            url = "https://" + url
        clean.append(url)
    return list(set(clean))[:10]  # max 10 URLs


async def check_google_safe_browsing(urls: List[str]) -> dict:
    """Check URLs against Google Safe Browsing database."""
    if not GSB_API_KEY or os.getenv("USE_GOOGLE_SAFE_BROWSING", "1") == "0":
        return {"threats": [], "error": "Google Safe Browsing not configured"}

    try:
        payload = {
            "client": {"clientId": "fraud-detector", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": u} for u in urls]
            }
        }
        async with httpx.AsyncClient(timeout=8.0) as client:
            resp = await client.post(f"{GSB_URL}?key={GSB_API_KEY}", json=payload)
            resp.raise_for_status()
            data = resp.json()

        threats = []
        for match in data.get("matches", []):
            threats.append({
                "url": match.get("threat", {}).get("url"),
                "threat_type": match.get("threatType"),
                "platform": match.get("platformType")
            })
        return {"threats": threats, "checked": len(urls), "error": None}

    except Exception as e:
        logger.error(f"Google Safe Browsing error: {e}")
        return {"threats": [], "error": str(e)}


async def check_virustotal(url: str) -> dict:
    """Scan a URL with VirusTotal."""
    if not VT_API_KEY or os.getenv("USE_VIRUSTOTAL", "1") == "0":
        return {"url": url, "positives": 0, "error": "VirusTotal not configured"}

    try:
        headers = {"x-apikey": VT_API_KEY}
        encoded_url = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(f"{VT_URL}/{encoded_url}", headers=headers)

            if resp.status_code == 404:
                # URL not yet known — submit for scan
                submit = await client.post(VT_URL, headers=headers, data={"url": url})
                submit.raise_for_status()
                return {"url": url, "positives": 0, "status": "Submitted for scan", "error": None}

            resp.raise_for_status()
            data = resp.json()

        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        positives = stats.get("malicious", 0) + stats.get("suspicious", 0)

        return {
            "url": url,
            "positives": positives,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "clean": stats.get("harmless", 0),
            "error": None
        }
    except Exception as e:
        logger.error(f"VirusTotal error for {url}: {e}")
        return {"url": url, "positives": 0, "error": str(e)}


async def check_phishtank(url: str) -> dict:
    """Check a URL against PhishTank known phishing database."""
    if os.getenv("USE_PHISHTANK", "1") == "0":
        return {"url": url, "is_phishing": False, "error": "PhishTank disabled"}

    try:
        data = {"url": url, "format": "json"}
        if PHISHTANK_APP_KEY:
            data["app_key"] = PHISHTANK_APP_KEY

        async with httpx.AsyncClient(timeout=8.0) as client:
            resp = await client.post(PHISHTANK_URL, data=data,
                                     headers={"User-Agent": "phishtank/fraud-detector"})
            resp.raise_for_status()
            result = resp.json()

        return {
            "url": url,
            "is_phishing": result.get("results", {}).get("in_database", False),
            "verified": result.get("results", {}).get("verified", False),
            "error": None
        }
    except Exception as e:
        logger.warning(f"PhishTank check error for {url}: {e}")
        return {"url": url, "is_phishing": False, "error": str(e)}


async def analyze_urls_in_text(text: str) -> dict:
    """
    Top-level: extract URLs from text and check all threat sources in parallel.
    Returns a consolidated URL threat report.
    """
    urls = extract_urls(text)

    if not urls:
        return {"urls_found": 0, "threats": [], "virustotal": [], "phishtank": [], "google_safe_browsing": {"threats": []}}

    # Parallel calls across all APIs
    gsb_task = check_google_safe_browsing(urls)
    vt_tasks = [check_virustotal(u) for u in urls[:3]]  # VT: limit 3 per analysis (rate limit)
    pt_tasks = [check_phishtank(u) for u in urls[:3]]

    gsb_result, *vt_results, *pt_results = await asyncio.gather(
        gsb_task, *vt_tasks, *pt_tasks, return_exceptions=True
    )

    # Flatten lists
    vt_results = [r for r in vt_results if isinstance(r, dict)]
    pt_results = [r for r in pt_results if isinstance(r, dict)]

    total_threats = (
        len(gsb_result.get("threats", [])) +
        sum(1 for r in vt_results if r.get("positives", 0) > 0) +
        sum(1 for r in pt_results if r.get("is_phishing"))
    )

    return {
        "urls_found": len(urls),
        "urls": urls,
        "total_threats_detected": total_threats,
        "google_safe_browsing": gsb_result,
        "virustotal": vt_results,
        "phishtank": pt_results
    }
