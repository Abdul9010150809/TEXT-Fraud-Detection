"""
Hugging Face Inference API Client
Runs BERT-based spam/scam detection models.
Sign up: https://huggingface.co/join
Get token: https://huggingface.co/settings/tokens
"""

import os
import httpx
import logging

logger = logging.getLogger(__name__)

HF_API_KEY = os.getenv("HUGGINGFACE_API_KEY", "")
# Using a spam detection model fine-tuned on SMS spam/scam data
HF_MODEL = "mrm8488/bert-tiny-finetuned-sms-spam-detection"
HF_API_URL = f"https://api-inference.huggingface.co/models/{HF_MODEL}"


async def classify_spam(text: str) -> dict:
    """
    Classify text as SPAM or HAM (not spam) using HuggingFace BERT model.
    Returns:
        {
            "label": "SPAM" or "HAM",
            "score": 0.0-1.0,
            "source": "huggingface",
            "model": <model_name>,
            "error": None or error message
        }
    """
    if not HF_API_KEY or os.getenv("USE_HUGGINGFACE", "1") == "0":
        return _fallback("HuggingFace API key not configured or disabled")

    try:
        headers = {"Authorization": f"Bearer {HF_API_KEY}"}
        payload = {"inputs": text[:512]}  # BERT has 512 token limit

        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(HF_API_URL, headers=headers, json=payload)
            response.raise_for_status()
            data = response.json()

        # HF returns list of label/score pairs sorted by score descending
        if isinstance(data, list) and len(data) > 0:
            results = data[0] if isinstance(data[0], list) else data
            top = max(results, key=lambda x: x.get("score", 0))
            return {
                "label": top.get("label", "UNKNOWN").upper(),
                "score": round(top.get("score", 0.0), 4),
                "source": "huggingface",
                "model": HF_MODEL,
                "error": None
            }

        return _fallback("Unexpected response format from HuggingFace")

    except httpx.HTTPStatusError as e:
        logger.warning(f"HuggingFace API HTTP error: {e.response.status_code}")
        if e.response.status_code == 503:
            # Model is loading - common on free tier
            return {"label": "UNKNOWN", "score": 0.5, "source": "huggingface",
                    "model": HF_MODEL, "error": "Model is loading, retry in 20s"}
        return _fallback(str(e))
    except Exception as e:
        logger.error(f"HuggingFace client error: {e}")
        return _fallback(str(e))


def _fallback(reason: str) -> dict:
    return {
        "label": "UNKNOWN",
        "score": 0.0,
        "source": "huggingface",
        "model": HF_MODEL,
        "error": reason
    }
