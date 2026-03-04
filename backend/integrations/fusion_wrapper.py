import time
import logging
from typing import Dict, Any

logger = logging.getLogger(__name__)


async def run_fusion(inputs: Dict[str, Any], fusion_strategy: str = "hybrid") -> Dict[str, Any]:
    """Run the fusion engine if available, otherwise use a lightweight fallback.

    Returns a dict with keys: risk_score (0-100), confidence (0-1), processing_time, details
    """
    start = time.time()
    try:
        # import dynamically to avoid startup import errors
        from fusion_engine.fusion_engine import FusionEngine

        engine = FusionEngine({'cache_ttl': 300})
        try:
            await engine.initialize()
        except Exception:
            # initialization might be heavy; ignore if it fails and continue
            logger.debug("FusionEngine initialization skipped/failed, proceeding to process")

        result = await engine.process(inputs, fusion_strategy=fusion_strategy)
        result['processing_time'] = time.time() - start
        return result

    except Exception as e:
        # Fallback simple scoring: heuristics
        logger.warning(f"FusionEngine unavailable or failed: {e}. Using fallback scorer.")
        score = 50.0
        conf = 0.5
        text = inputs.get('text') or inputs.get('content')
        if text:
            # simple heuristics: presence of suspicious keywords
            suspicious = ['win', 'prize', 'urgent', 'transfer', 'verify', 'password']
            hits = sum(1 for k in suspicious if k in text.lower())
            score += min(40, hits * 15)
            conf = min(0.9, 0.5 + hits * 0.1)

        if inputs.get('amount'):
            amt = float(inputs.get('amount', 0))
            if amt > 1000:
                score += 10
                conf = max(conf, 0.6)

        if inputs.get('image'):
            score += 5

        score = min(100.0, max(0.0, score))
        return {
            'risk_score': score,
            'confidence': conf,
            'processing_time': time.time() - start,
            'fusion_type': 'fallback'
        }
