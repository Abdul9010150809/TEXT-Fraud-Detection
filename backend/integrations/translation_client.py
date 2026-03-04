"""
LibreTranslate Client - Language Detection & Translation
Fully free, open-source translation API.
Public server: https://libretranslate.com
Self-host: https://github.com/LibreTranslate/LibreTranslate
"""

import os
import httpx
import logging

logger = logging.getLogger(__name__)

LT_URL = os.getenv("LIBRETRANSLATE_URL", "https://libretranslate.com")
LT_API_KEY = os.getenv("LIBRETRANSLATE_API_KEY", "")

# Supported languages by most LibreTranslate instances
SUPPORTED_LANGUAGES = {"en", "hi", "ta", "te", "kn", "ml", "mr",
                        "fr", "de", "es", "zh", "ar", "ru", "pt", "ja", "ko"}


async def detect_and_translate(text: str, target_lang: str = "en") -> dict:
    """
    Detect the language of the text and translate it to English if needed.
    Returns:
        {
            "original_text": str,
            "translated_text": str,
            "source_language": str,
            "was_translated": bool,
            "source": "libretranslate",
            "error": None or message
        }
    """
    if os.getenv("USE_LIBRETRANSLATE", "1") == "0":
        return _passthrough(text, "LibreTranslate disabled")

    try:
        detected_lang = await detect_language(text)

        if detected_lang == target_lang or detected_lang == "unknown":
            return {
                "original_text": text,
                "translated_text": text,
                "source_language": detected_lang,
                "was_translated": False,
                "source": "libretranslate",
                "error": None
            }

        # Translate to English
        translated = await translate(text, source=detected_lang, target=target_lang)
        return {
            "original_text": text,
            "translated_text": translated,
            "source_language": detected_lang,
            "was_translated": True,
            "source": "libretranslate",
            "error": None
        }

    except Exception as e:
        logger.error(f"LibreTranslate error: {e}")
        return _passthrough(text, str(e))


async def detect_language(text: str) -> str:
    """Detect the language of the text using LibreTranslate /detect endpoint."""
    try:
        payload = {"q": text[:500]}
        if LT_API_KEY:
            payload["api_key"] = LT_API_KEY

        async with httpx.AsyncClient(timeout=8.0) as client:
            resp = await client.post(f"{LT_URL}/detect", json=payload)
            resp.raise_for_status()
            results = resp.json()

        if results and isinstance(results, list):
            top = max(results, key=lambda x: x.get("confidence", 0))
            return top.get("language", "unknown")
        return "unknown"

    except Exception as e:
        logger.warning(f"Language detection error: {e}")
        return "unknown"


async def translate(text: str, source: str = "auto", target: str = "en") -> str:
    """Translate text from source to target language."""
    try:
        payload = {"q": text[:2000], "source": source, "target": target, "format": "text"}
        if LT_API_KEY:
            payload["api_key"] = LT_API_KEY

        async with httpx.AsyncClient(timeout=12.0) as client:
            resp = await client.post(f"{LT_URL}/translate", json=payload)
            resp.raise_for_status()
            data = resp.json()

        return data.get("translatedText", text)

    except Exception as e:
        logger.warning(f"Translation error from {source} to {target}: {e}")
        return text  # Return original if translation fails


def _passthrough(text: str, reason: str) -> dict:
    return {
        "original_text": text,
        "translated_text": text,
        "source_language": "unknown",
        "was_translated": False,
        "source": "libretranslate",
        "error": reason
    }
