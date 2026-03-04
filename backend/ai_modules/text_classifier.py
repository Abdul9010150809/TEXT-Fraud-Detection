import time

class ClassificationResult:
    def __init__(self, data: dict, processing_time: float):
        self.data = data
        self.processing_time = processing_time

    def to_json(self):
        return self.data

class RiskLevel:
    LOW = "Safe"
    MEDIUM = "Suspicious"
    HIGH = "High"
    CRITICAL = "Critical"

class TextClassifier:
    def __init__(self):
        pass

    def classify(self, text: str) -> ClassificationResult:
        start_time = time.time()
        # Simulated heuristic analysis
        text_lower = text.lower()
        is_fraud = False
        risk_score = 10
        risk_level = RiskLevel.LOW
        fraud_type = ["None"]
        why_fraud = ["No issues detected."]
        
        # Basic urgency/financial simulation
        has_urgency = "urgent" in text_lower or "immediate" in text_lower
        has_financial = "lottery" in text_lower or "won" in text_lower
        
        if has_urgency:
            risk_score += 40
        if has_financial:
            risk_score += 40
            
        if risk_score > 70:
            is_fraud = True
            risk_level = RiskLevel.CRITICAL
            fraud_type = ["Scam"]
            why_fraud = ["Matches high risk keywords."]
            
        data = {
            "is_fraud": is_fraud,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "fraud_type": fraud_type,
            "why_fraud": why_fraud,
            "detected_signals": {
                "urgency": has_urgency, 
                "financial_lure": has_financial, 
                "impersonation": False, 
                "credential_theft": False, 
                "suspicious_url": False, 
                "ai_generated_tone": False,
                "spelling_grammar_issues": False,
                "social_engineering": False,
                "crypto_investment_pitch": False,
                "threat_extortion": False,
                "job_scam": False,
                "spam_marketing": False,
                "regional_upi_fraud": False,
                "romance_scam": False,
                "tech_support_refund": False
            },
            "link_intelligence": None,
            "text_error_analysis": {
                "typos": [],
                "grammar_issues": [],
                "score": 85 if not is_fraud else 40
            },
            "author_prediction": "Unknown",
            "recommended_action": ["Always verify sources"],
            "confidence": 0.8
        }
        
        processing_time = time.time() - start_time
        return ClassificationResult(data, processing_time)
