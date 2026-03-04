from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum
import uuid

class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class DetectionLog(BaseModel):
    id: Optional[str] = Field(default=None, alias="_id")
    user_id: str
    transaction_id: str
    risk_score: float = Field(ge=0.0, le=1.0)
    risk_level: RiskLevel
    features: Dict[str, Any]
    prediction: bool  # True if fraud detected
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    model_version: str
    model_config = {
        'protected_namespaces': ()
    }
    explanation: Optional[str] = None

class UserData(BaseModel):
    id: Optional[str] = Field(default=None, alias="_id")
    user_id: str
    email: str
    phone: Optional[str] = None
    registration_date: datetime
    last_login: Optional[datetime] = None
    risk_profile: Dict[str, Any] = Field(default_factory=dict)
    flags: List[str] = Field(default_factory=list)  # e.g., ["suspicious_activity", "high_risk"]

class RiskScore(BaseModel):
    id: Optional[str] = Field(default=None, alias="_id")
    user_id: str
    score: float = Field(ge=0.0, le=1.0)
    factors: Dict[str, float]  # e.g., {"amount": 0.3, "location": 0.2}
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    model_version: str
    model_config = {
        'protected_namespaces': ()
    }


# Ingestion request/response models
class TextIngestRequest(BaseModel):
    source: str = Field(..., description="Source type: sms, email, social")
    user_id: Optional[str] = None
    content: str = Field(..., min_length=1)
    metadata: Optional[Dict[str, Any]] = Field(default_factory=dict)


class UrlIngestRequest(BaseModel):
    url: str = Field(..., description="URL to analyze")
    user_id: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = Field(default_factory=dict)


class TransactionIngestRequest(BaseModel):
    user_id: str
    transaction_id: str
    amount: float
    currency: str = "USD"
    merchant: Optional[str] = None
    timestamp: Optional[datetime] = None
    metadata: Optional[Dict[str, Any]] = Field(default_factory=dict)


class IngestResponse(BaseModel):
    risk_score: float = Field(..., ge=0.0, le=100.0)
    confidence: float = Field(..., ge=0.0, le=1.0)
    processing_time: float
    alert: Optional[str] = None
    details: Optional[Dict[str, Any]] = None

# Ingestion Request Models
class TextIngestionRequest(BaseModel):
    content: str = Field(..., min_length=1, max_length=10000)
    source_type: str = Field(..., pattern="^(sms|email|social_media)$")
    user_id: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = Field(default_factory=dict)

class URLIngestionRequest(BaseModel):
    url: str = Field(..., pattern=r"^https?://")
    user_id: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = Field(default_factory=dict)

class TransactionIngestionRequest(BaseModel):
    amount: float = Field(gt=0)
    currency: str = Field(min_length=3, max_length=3)
    sender_id: str
    receiver_id: str
    transaction_type: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    metadata: Optional[Dict[str, Any]] = Field(default_factory=dict)

# Response Models
class IngestionResponse(BaseModel):
    request_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    risk_score: float = Field(ge=0, le=100)
    confidence: float = Field(ge=0, le=1)
    processing_time: float
    alert_triggered: bool = False
    alert_message: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)

class ErrorResponse(BaseModel):
    error: str
    detail: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)