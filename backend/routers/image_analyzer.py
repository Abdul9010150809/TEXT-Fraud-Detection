"""
Image Analysis API Router
Provides endpoint for image OCR + text fraud detection
"""

import asyncio
import base64
import io
import logging
import time
from typing import Dict, Any, Optional, List
from fastapi import APIRouter, Depends, HTTPException, Request, UploadFile, File
from pydantic import BaseModel, Field
from datetime import datetime, UTC

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/image", tags=["image-analysis"])

# Simple in-memory rate limiter (per-IP)
_RATE_LIMIT_STORE: Dict[str, Dict[str, Any]] = {}
_RATE_LIMIT_LOCK = asyncio.Lock()
RATE_LIMIT = 30  # requests (lower for image processing)
RATE_WINDOW = 60  # seconds
MAX_IMAGE_SIZE = 10 * 1024 * 1024  # 10MB


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


class ImageAnalyzeResponse(BaseModel):
    """Response model for image analysis"""
    is_spam: bool
    risk_score: float
    risk_level: str
    message_type: str
    grammar_score: int
    extracted_text: str
    text_found: bool
    scam_type: List[str]
    why_spam: List[str]
    detected_signals: Dict[str, bool]
    text_analysis: Optional[Dict[str, Any]] = None
    recommended_action: List[str]
    confidence: float
    processing_time: float
    ocr_method: str
    timestamp: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())


class ImageAnalyzer:
    """Image OCR and fraud analyzer"""
    
    def __init__(self):
        self.ocr_available = False
        self.ocr_method = "none"
        
        # Try to import OCR libraries
        try:
            import pytesseract
            from PIL import Image
            self.ocr_available = True
            self.ocr_method = "tesseract"
            self.pytesseract = pytesseract
            self.PILImage = Image
            logger.info("Tesseract OCR initialized successfully")
        except ImportError:
            logger.warning("Tesseract OCR not available - will use fallback methods")
    
    async def analyze_image(self, image_bytes: bytes) -> Dict[str, Any]:
        """Analyze image: extract text + fraud detection"""
        start_time = time.time()
        
        # Extract text from image
        extracted_text = await self._extract_text_from_image(image_bytes)
        text_found = len(extracted_text.strip()) > 0
        
        # If no text found
        if not text_found:
            return {
                "is_spam": False,
                "risk_score": 0,
                "risk_level": "Safe",
                "message_type": "No Text Detected",
                "grammar_score": 0,
                "extracted_text": "",
                "text_found": False,
                "scam_type": ["None"],
                "why_spam": ["No text detected in image."],
                "detected_signals": {},
                "text_analysis": None,
                "recommended_action": ["No text found to analyze."],
                "confidence": 0.0,
                "processing_time": time.time() - start_time,
                "ocr_method": self.ocr_method,
            }
        
        # Analyze extracted text using text classifier
        from backend.ai_modules.text_classifier import TextClassifier
        text_classifier = TextClassifier()
        
        analysis_result = text_classifier.classify(extracted_text)
        analysis_data = analysis_result.to_json()
        
        # Get risk metrics
        risk_score = analysis_data.get("risk_score", 0)
        risk_level = analysis_data.get("risk_level", "Safe")
        is_spam = analysis_data.get("is_fraud", False)
        message_type = analysis_data.get("text_category", "General Message")
        grammar_score = int(analysis_data.get("text_error_analysis", {}).get("score", 60))
        
        # Get fraud details
        scam_types = analysis_data.get("fraud_type", ["None"])
        reasons = analysis_data.get("why_fraud", [])
        detected_signals = analysis_data.get("detected_signals", {})
        
        # Add image-specific context
        reasons.insert(0, f"Text extracted from image ({len(extracted_text)} characters)")
        
        # Generate recommendations
        recommendations = list(analysis_data.get("recommended_action", []))
        if is_spam:
            recommendations.insert(0, "This image contains fraudulent/spam text content.")
        
        # Text analysis summary
        text_analysis = {
            "text_category": message_type,
            "grammar_score": grammar_score,
            "author_style": analysis_data.get("author_prediction", "Unknown"),
            "confidence": analysis_data.get("confidence", 0.0),
        }
        
        processing_time = time.time() - start_time
        
        return {
            "is_spam": is_spam,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "message_type": message_type,
            "grammar_score": grammar_score,
            "extracted_text": extracted_text,
            "text_found": text_found,
            "scam_type": scam_types,
            "why_spam": reasons,
            "detected_signals": detected_signals,
            "text_analysis": text_analysis,
            "recommended_action": recommendations,
            "confidence": analysis_data.get("confidence", 0.0),
            "processing_time": processing_time,
            "ocr_method": self.ocr_method,
        }
    
    async def _extract_text_from_image(self, image_bytes: bytes) -> str:
        """Extract text from image using OCR"""
        
        if self.ocr_available:
            try:
                # Use Tesseract OCR
                image = self.PILImage.open(io.BytesIO(image_bytes))
                # Convert to RGB if needed
                if image.mode != 'RGB':
                    image = image.convert('RGB')
                text = self.pytesseract.image_to_string(image)
                return text.strip()
            except Exception as e:
                logger.error(f"Tesseract OCR failed: {e}")
                return await self._fallback_text_extraction(image_bytes)
        else:
            return await self._fallback_text_extraction(image_bytes)
    
    async def _fallback_text_extraction(self, image_bytes: bytes) -> str:
        """Fallback text extraction when OCR is not available"""
        # Try using Google's Gemini Vision API if available
        try:
            import google.generativeai as genai
            import PIL.Image
            import os
            
            api_key = os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")
            if api_key:
                genai.configure(api_key=api_key)
                model = genai.GenerativeModel('gemini-1.5-flash')
                
                image = PIL.Image.open(io.BytesIO(image_bytes))
                response = model.generate_content([
                    "Extract all text from this image. Return only the extracted text, nothing else.",
                    image
                ])
                
                if response and response.text:
                    self.ocr_method = "gemini-vision"
                    return response.text.strip()
        except Exception as e:
            logger.warning(f"Gemini Vision API not available: {e}")
        
        # If all methods fail, return empty string
        logger.warning("No OCR method available - returning empty text")
        self.ocr_method = "none"
        return ""


@router.post("/analyze", response_model=ImageAnalyzeResponse)
async def analyze_image(
    request: Request,
    image: UploadFile = File(..., description="Image file to analyze"),
    _rl: None = Depends(rate_limiter)
) -> ImageAnalyzeResponse:
    """
    Analyze an image: extract text using OCR and detect spam/fraud.
    Supports JPG, PNG, WebP, and other common formats.
    """
    
    try:
        # Validate file size
        image_bytes = await image.read()
        if len(image_bytes) > MAX_IMAGE_SIZE:
            raise HTTPException(
                status_code=413,
                detail=f"Image too large (max {MAX_IMAGE_SIZE // (1024*1024)}MB)"
            )
        
        # Validate file type
        content_type = image.content_type or ""
        if not content_type.startswith("image/"):
            raise HTTPException(
                status_code=400,
                detail="File must be an image"
            )
        
        analyzer = ImageAnalyzer()
        result = await analyzer.analyze_image(image_bytes)
        
        logger.info(
            f"Analyzed image ({image.filename}) - "
            f"text_found={result['text_found']}, spam={result['is_spam']}, "
            f"score={result['risk_score']}"
        )
        
        return ImageAnalyzeResponse(**result)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"Error analyzing image: {e}")
        raise HTTPException(
            status_code=500, 
            detail="Internal server error during image analysis"
        )


@router.get("/health")
async def health_check():
    """Health check endpoint"""
    analyzer = ImageAnalyzer()
    return {
        "status": "healthy",
        "service": "image-analyzer",
        "version": "1.0.0",
        "ocr_available": analyzer.ocr_available,
        "ocr_method": analyzer.ocr_method,
    }


@router.get("/capabilities")
async def get_capabilities():
    """Get OCR capabilities"""
    analyzer = ImageAnalyzer()
    
    capabilities = {
        "tesseract": analyzer.ocr_available and analyzer.ocr_method == "tesseract",
        "gemini_vision": False,  # Would need to test actual availability
    }
    
    return {
        "ocr_available": analyzer.ocr_available,
        "methods": capabilities,
        "max_image_size_mb": MAX_IMAGE_SIZE // (1024 * 1024),
        "supported_formats": ["jpg", "jpeg", "png", "webp", "bmp", "tiff"],
    }
