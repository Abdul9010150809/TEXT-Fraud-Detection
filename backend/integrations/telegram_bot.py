"""
Telegram Bot Integration
Receives user messages from Telegram, runs the full fraud analysis,
and replies with a verdict.

Setup:
1. Open Telegram, search for @BotFather
2. Send /newbot and follow prompts
3. Copy the bot token into your .env as TELEGRAM_BOT_TOKEN
4. Set USE_TELEGRAM_BOT=1 in your .env
5. Start the bot by running: python -m backend.integrations.telegram_bot

The bot works in two modes:
- POLLING (local dev): No server needed, bot polls Telegram every few seconds
- WEBHOOK (production): Requires a public HTTPS URL
"""

import os
import asyncio
import logging
import httpx

logger = logging.getLogger(__name__)

BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_API = f"https://api.telegram.org/bot{BOT_TOKEN}"

RISK_EMOJIS = {
    "Safe": "✅",
    "Suspicious": "⚠️",
    "High": "🔴",
    "Critical": "🚨"
}


async def send_message(chat_id: int, text: str):
    """Send a Telegram message to a chat."""
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            await client.post(f"{TELEGRAM_API}/sendMessage", json={
                "chat_id": chat_id,
                "text": text,
                "parse_mode": "HTML"
            })
    except Exception as e:
        logger.error(f"Failed to send Telegram message: {e}")


async def handle_message(message: dict):
    """Process an incoming Telegram message and reply with fraud analysis."""
    from backend.integrations.api_orchestrator import run_full_analysis

    chat_id = message.get("chat", {}).get("id")
    text = message.get("text", "")
    user = message.get("from", {}).get("first_name", "User")

    if not chat_id or not text:
        return

    if text.startswith("/start"):
        await send_message(chat_id,
            f"👋 Hello <b>{user}</b>! I am the <b>AI Fraud Detector Bot</b>.\n\n"
            "Send me any suspicious message or text and I will analyze it for:\n"
            "• Spam & Scam Detection\n"
            "• Phishing URL Checks\n"
            "• Sentiment Analysis\n"
            "• AI-Generated Text Detection\n\n"
            "Just paste any suspicious text and I'll scan it! 🔍"
        )
        return

    if text.startswith("/"):
        await send_message(chat_id, "ℹ️ Unknown command. Just send me any suspicious text to analyze.")
        return

    # Send loading message
    await send_message(chat_id, "🔍 <b>Analyzing your message...</b>\nRunning 5 AI APIs in parallel...")

    try:
        result = await run_full_analysis(text)

        verdict = result.get("combined_verdict", "Unknown")
        score = result.get("combined_risk_score", 0)
        emoji = RISK_EMOJIS.get(verdict, "❓")

        # Build signals text
        signals_text = ""
        for sig in result.get("api_signals", []):
            flag = "🚩" if sig.get("flagged") else "✅"
            signals_text += f"\n{flag} <b>{sig['api']}</b>: {sig['verdict']} ({sig['detail']})"

        # Translation note
        translation_note = ""
        if result.get("was_translated"):
            translation_note = f"\n🌍 <i>Translated from {result.get('source_language', '?').upper()} to English</i>\n"

        # URL threats
        url_note = ""
        url_data = result.get("url_threats", {})
        if url_data.get("urls_found", 0) > 0:
            threats = url_data.get("total_threats_detected", 0)
            url_note = f"\n🔗 <b>URLs Found:</b> {url_data['urls_found']} | <b>Threats:</b> {threats}"

        response = (
            f"{emoji} <b>FRAUD ANALYSIS RESULT</b> {emoji}\n"
            f"{'─' * 30}\n"
            f"<b>Verdict:</b> {verdict}\n"
            f"<b>Risk Score:</b> {score}/100\n"
            f"{translation_note}"
            f"\n<b>API Intelligence:</b>"
            f"{signals_text}"
            f"{url_note}\n\n"
            f"<i>Powered by HuggingFace · MeaningCloud · IPQualityScore · Google Safe Browsing · VirusTotal</i>"
        )

        await send_message(chat_id, response)

    except Exception as e:
        logger.error(f"Error processing Telegram message: {e}")
        await send_message(chat_id, "❌ An error occurred during analysis. Please try again.")


async def polling_loop():
    """Simple long-polling loop to receive Telegram updates."""
    offset = 0
    logger.info("Telegram bot started (polling mode)...")

    while True:
        try:
            async with httpx.AsyncClient(timeout=35.0) as client:
                response = await client.get(f"{TELEGRAM_API}/getUpdates", params={
                    "offset": offset,
                    "timeout": 30,
                    "allowed_updates": ["message"]
                })
                data = response.json()

            if not data.get("ok"):
                logger.warning(f"Telegram API error: {data}")
                await asyncio.sleep(5)
                continue

            for update in data.get("result", []):
                offset = update["update_id"] + 1
                if "message" in update:
                    asyncio.create_task(handle_message(update["message"]))

        except asyncio.CancelledError:
            logger.info("Telegram bot polling stopped.")
            break
        except Exception as e:
            logger.error(f"Telegram polling error: {e}")
            await asyncio.sleep(3)


async def start_bot():
    """Start the Telegram bot if token and flag are configured."""
    if not BOT_TOKEN:
        logger.warning("TELEGRAM_BOT_TOKEN not set. Telegram bot will not start.")
        return
    if os.getenv("USE_TELEGRAM_BOT", "0") != "1":
        logger.info("Telegram bot disabled (USE_TELEGRAM_BOT=0)")
        return

    logger.info("Starting Telegram bot in polling mode...")
    asyncio.create_task(polling_loop())


if __name__ == "__main__":
    # Run standalone: python -m backend.integrations.telegram_bot
    logging.basicConfig(level=logging.INFO)
    asyncio.run(polling_loop())
