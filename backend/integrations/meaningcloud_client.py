"""
MeaningCloud Sentiment & Topic Analysis Client
Sign up: https://www.meaningcloud.com/developer/login
Free: 20,000 requests/month
"""

import os
import httpx
import logging

logger = logging.getLogger(__name__)

MC_API_KEY = os.getenv("MEANINGCLOUD_API_KEY", "")
MC_SENTIMENT_URL = "https://api.meaningcloud.com/sentiment-2.1"
MC_TOPICS_URL = "https://api.meaningcloud.com/topics-2.0"

POLARITY_MAP = {
    "P+": "Very Positive",
    "P": "Positive",
    "NEU": "Neutral",
    "N": "Negative",
    "N+": "Very Negative",
    "NONE": "No Sentiment"
}


async def analyze_sentiment(text: str) -> dict:
    """
    Analyze sentiment and irony of the message.
    Returns:
        {
            "polarity": "Very Negative" | "Negative" | "Neutral" | ...,
            "irony": True/False,
            "subjectivity": "subjective" | "objective",
            "topics": [...],
            "source": "meaningcloud",
            "error": None or message
        }
    """
    if not MC_API_KEY or os.getenv("USE_MEANINGCLOUD", "1") == "0":
        return _fallback("MeaningCloud API key not configured or disabled")

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            # Sentiment analysis
            sentiment_resp = await client.post(
                MC_SENTIMENT_URL,
                data={
                    "key": MC_API_KEY,
                    "txt": text[:2000],
                    "lang": "auto",
                    "txt_format": "plain",
                    "model": "general",
                }
            )
            sentiment_resp.raise_for_status()
            s_data = sentiment_resp.json()

        if s_data.get("status", {}).get("code") != "0":
            err = s_data.get("status", {}).get("msg", "API error")
            return _fallback(err)

        polarity_raw = s_data.get("score_tag", "NONE")
        irony = s_data.get("irony", "NONIRONIC") == "IRONIC"
        subjectivity = s_data.get("subjectivity", "NONE").lower()

        return {
            "polarity": POLARITY_MAP.get(polarity_raw, polarity_raw),
            "polarity_raw": polarity_raw,
            "irony": irony,
            "subjectivity": subjectivity,
            "agreement": s_data.get("agreement", ""),
            "confidence": int(s_data.get("confidence", 0)),
            "source": "meaningcloud",
            "error": None
        }

    except Exception as e:
        logger.error(f"MeaningCloud client error: {e}")
        return _fallback(str(e))


def _fallback(reason: str) -> dict:
    return {
        "polarity": "Unknown",
        "polarity_raw": "NONE",
        "irony": False,
        "subjectivity": "unknown",
        "confidence": 0,
        "source": "meaningcloud",
        "error": reason
    }
