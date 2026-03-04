import asyncio
import logging
import time
import tempfile
import os
from typing import Optional, Dict, Any

from fastapi import APIRouter, Depends, HTTPException, Request, UploadFile, File, BackgroundTasks
from fastapi.responses import JSONResponse

from backend.models import schemas
from backend.integrations.fusion_wrapper import run_fusion
from ai_modules.text_classifier import TextClassifier, RiskLevel

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/ingest", tags=["ingest"])

# Simple in-memory rate limiter (per-IP) - production should use Redis or API gateway
_RATE_LIMIT_STORE: Dict[str, Dict[str, Any]] = {}
_RATE_LIMIT_LOCK = asyncio.Lock()
RATE_LIMIT = 60  # requests
RATE_WINDOW = 60  # seconds


async def rate_limiter(request: Request):
    client = request.client.host if request.client else "anonymous"
    now = time.time()
    async with _RATE_LIMIT_LOCK:
        rec = _RATE_LIMIT_STORE.get(client)
        if not rec or now - rec['start'] > RATE_WINDOW:
            _RATE_LIMIT_STORE[client] = {'count': 1, 'start': now}
            return
        if rec['count'] >= RATE_LIMIT:
            raise HTTPException(status_code=429, detail="Too many requests")
        rec['count'] += 1


def sanitize_text(text: str) -> str:
    if not text:
        return text
    # basic sanitization: strip control characters and excessive whitespace
    cleaned = " ".join(text.strip().split())
    return cleaned


async def trigger_alert(message: str, details: Optional[Dict[str, Any]] = None):
    # Placeholder alerting - in prod push to alerting service or queue
    logger.warning(f"ALERT: {message} | details: {details}")


@router.post("/text", response_model=schemas.IngestResponse)
async def ingest_text(payload: schemas.TextIngestRequest, background: BackgroundTasks, _rl=Depends(rate_limiter)):
    start = time.time()
    try:
        content = sanitize_text(payload.content)
        # Use NLP classifier for text analysis
        # V2: No init args
        classifier = TextClassifier()
        result = classifier.classify(content)
        
        risk_score = result.risk_score
        alert = None
        
        # Determine alert based on is_fraud flag
        if result.is_fraud:
            alert = f"FRAUD DETECTED! Level: {result.risk_level}"
            if result.risk_score > 80:
                 alert += " (High Confidence)"
            background.add_task(trigger_alert, alert, {"user_id": payload.user_id, "risk": result.risk_level})

        processing_time = time.time() - start
        
        return schemas.IngestResponse(
            risk_score=risk_score,
            confidence=result.confidence,
            processing_time=processing_time,
            alert=alert,
            details=result.to_json()
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"Error ingesting text: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post("/url", response_model=schemas.IngestResponse)
async def ingest_url(payload: schemas.UrlIngestRequest, background: BackgroundTasks, _rl=Depends(rate_limiter)):
    start = time.time()
    try:
        # Basic sanitization of URL
        url = payload.url.strip()
        inputs = {"url": url, "metadata": payload.metadata, "user_id": payload.user_id}
        result = await run_fusion(inputs)
        processing_time = result.get('processing_time', time.time() - start)
        score = float(result.get('risk_score', 0.0))
        confidence = float(result.get('confidence', 0.0))
        alert = None
        if score >= 85:
            alert = "FRAUD DETECTED! Pattern matches known scam"
            background.add_task(trigger_alert, alert, {"user_id": payload.user_id, "score": score, "url": url})

        return schemas.IngestResponse(risk_score=score, confidence=confidence, processing_time=processing_time, alert=alert, details=result)

    except Exception as e:
        logger.exception(f"Error ingesting url: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post("/image", response_model=schemas.IngestResponse)
async def ingest_image(file: UploadFile = File(...), background: BackgroundTasks = None, _rl=Depends(rate_limiter)):
    start = time.time()
    tmp_path = None
    try:
        # Temporary file handling
        suffix = os.path.splitext(file.filename)[1] or ".img"
        tmp = tempfile.NamedTemporaryFile(delete=False, suffix=suffix)
        tmp_path = tmp.name
        content = await file.read()
        tmp.write(content)
        tmp.flush()
        tmp.close()

        inputs = {"image": content, "metadata": {"filename": file.filename}}
        result = await run_fusion(inputs)
        processing_time = result.get('processing_time', time.time() - start)
        score = float(result.get('risk_score', 0.0))
        confidence = float(result.get('confidence', 0.0))
        alert = None
        if score >= 85:
            alert = "FRAUD DETECTED! Pattern matches known scam"
            if background:
                background.add_task(trigger_alert, alert, {"filename": file.filename, "score": score})

        return schemas.IngestResponse(risk_score=score, confidence=confidence, processing_time=processing_time, alert=alert, details=result)

    except Exception as e:
        logger.exception(f"Error ingesting image: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")
    finally:
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except Exception:
                logger.debug(f"Failed to remove temp file {tmp_path}")


@router.post("/audio", response_model=schemas.IngestResponse)
async def ingest_audio(file: UploadFile = File(...), background: BackgroundTasks = None, _rl=Depends(rate_limiter)):
    start = time.time()
    tmp_path = None
    try:
        suffix = os.path.splitext(file.filename)[1] or ".wav"
        tmp = tempfile.NamedTemporaryFile(delete=False, suffix=suffix)
        tmp_path = tmp.name
        content = await file.read()
        tmp.write(content)
        tmp.flush()
        tmp.close()

        inputs = {"audio": content, "metadata": {"filename": file.filename}}
        result = await run_fusion(inputs)
        processing_time = result.get('processing_time', time.time() - start)
        score = float(result.get('risk_score', 0.0))
        confidence = float(result.get('confidence', 0.0))
        alert = None
        if score >= 85:
            alert = "FRAUD DETECTED! Pattern matches known scam"
            if background:
                background.add_task(trigger_alert, alert, {"filename": file.filename, "score": score})

        return schemas.IngestResponse(risk_score=score, confidence=confidence, processing_time=processing_time, alert=alert, details=result)

    except Exception as e:
        logger.exception(f"Error ingesting audio: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")
    finally:
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except Exception:
                logger.debug(f"Failed to remove temp file {tmp_path}")


@router.post("/transaction", response_model=schemas.IngestResponse)
async def ingest_transaction(payload: schemas.TransactionIngestRequest, background: BackgroundTasks, _rl=Depends(rate_limiter)):
    start = time.time()
    try:
        inputs = {
            "transaction_id": payload.transaction_id,
            "user_id": payload.user_id,
            "amount": payload.amount,
            "currency": payload.currency,
            "merchant": payload.merchant,
            "metadata": payload.metadata
        }
        result = await run_fusion(inputs)
        processing_time = result.get('processing_time', time.time() - start)
        score = float(result.get('risk_score', 0.0))
        confidence = float(result.get('confidence', 0.0))
        alert = None
        if score >= 85:
            alert = "FRAUD DETECTED! Pattern matches known scam"
            background.add_task(trigger_alert, alert, {"transaction_id": payload.transaction_id, "score": score})

        return schemas.IngestResponse(risk_score=score, confidence=confidence, processing_time=processing_time, alert=alert, details=result)

    except Exception as e:
        logger.exception(f"Error ingesting transaction: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")
