import re
import time
from dataclasses import dataclass
from typing import Dict, List, Tuple
from urllib.parse import urlparse


@dataclass
class ClassificationResult:
    data: Dict
    processing_time: float

    def to_json(self) -> Dict:
        return self.data


class RiskLevel:
    LOW = "Safe"
    MEDIUM = "Suspicious"
    HIGH = "High"
    CRITICAL = "Critical"


class TextClassifier:
    URL_PATTERN = re.compile(r"https?://[^\s]+", re.IGNORECASE)
    WORD_PATTERN = re.compile(r"\b[a-zA-Z']+\b")

    URGENCY_TERMS = {
        "urgent", "immediately", "now", "asap", "deadline", "expire", "final warning",
        "last chance", "blocked", "suspended", "act fast", "within 24 hours"
    }
    FINANCIAL_LURE_TERMS = {
        "lottery", "jackpot", "winner", "won", "cash prize", "reward", "free money",
        "guaranteed returns", "double your money", "instant profit", "investment plan"
    }
    IMPERSONATION_TERMS = {
        "bank", "support team", "customer care", "irs", "tax department", "paypal",
        "amazon", "microsoft", "google", "official notice", "compliance team"
    }
    CREDENTIAL_THEFT_TERMS = {
        "otp", "password", "pin", "cvv", "verify account", "confirm account", "kyc",
        "bank details", "social security", "login details", "verification code"
    }
    SOCIAL_ENGINEERING_TERMS = {
        "trust me", "keep this confidential", "do not tell anyone", "help me urgently",
        "family emergency", "limited time", "exclusive", "you are selected"
    }
    CRYPTO_TERMS = {
        "bitcoin", "usdt", "crypto", "trading bot", "defi", "token presale", "airdrop"
    }
    EXTORTION_TERMS = {
        "blackmail", "pay us", "we recorded", "webcam", "leak your data", "expose you",
        "ransom", "bitcoin payment", "legal action"
    }
    JOB_SCAM_TERMS = {
        "work from home", "part time", "no interview", "daily income", "quick earning",
        "data entry", "registration fee", "processing fee", "task based"
    }
    MARKETING_TERMS = {
        "sale", "discount", "offer", "subscribe", "promo code", "buy now", "shop now",
        "limited stock", "special deal"
    }
    UPI_TERMS = {
        "upi", "paytm", "phonepe", "gpay", "google pay", "bhim", "collect request"
    }
    TECH_SUPPORT_TERMS = {
        "tech support", "refund", "remote access", "anydesk", "teamviewer",
        "system infected", "windows license"
    }
    
    ROMANCE_FRAUD_TERMS = {
        "beautiful", "love you", "miss you", "care about you", "cannot stop thinking",
        "soulmate", "forever with you", "help you financially", "send you money",
        "share your bank", "share your details", "deepest feelings", "true love"
    }
    
    MONEY_TRANSFER_TERMS = {
        "bank details", "account number", "transfer money", "wire transfer", 
        "send funds", "payment details", "banking information", "swift code",
        "iban number", "money transfer"
    }

    SAFE_CONTEXT_TERMS = {
        "meeting", "schedule", "notes", "project", "thanks", "thank you", "regards",
        "please review", "let me know", "team update", "invoice attached"
    }

    SAFE_DOMAINS = {
        "google.com", "github.com", "wikipedia.org", "microsoft.com", "apple.com",
        "amazon.com", "paypal.com", "sbi.co.in", "hdfcbank.com", "icicibank.com"
    }
    HIGH_RISK_TLDS = {"xyz", "top", "click", "work", "tk", "ml", "gq", "cf"}
    SHORTENER_DOMAINS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly"}

    COMMON_SHORT_WORDS = {
        "a", "an", "the", "is", "to", "of", "on", "in", "for", "at", "by", "it",
        "we", "you", "me", "us", "our", "your", "and", "or", "if", "be", "as", "do",
        "can", "will", "this", "that", "from", "with", "not", "are", "was", "were"
    }

    TYPO_HINTS = {
        "plz", "pls", "ur", "u", "immeditly", "recieve", "verfy", "acount", "gud",
        "thx", "msg", "frnd", "confrm", "updte"
    }

    def classify(self, text: str) -> ClassificationResult:
        start_time = time.time()
        text = (text or "").strip()
        text_lower = text.lower()

        signals, score_breakdown, reasons = self._compute_signals(text, text_lower)
        text_category = self._detect_text_category(text_lower, signals)
        link_intelligence = self._analyze_links(text)
        grammar = self._analyze_text_quality(text)
        author_prediction = self._predict_author_style(text, grammar)

        if link_intelligence and (link_intelligence.get("tld_risk") or link_intelligence.get("brand_spoofing")):
            signals["suspicious_url"] = True
            score_breakdown["suspicious_url"] += 20
            reasons.append("Detected high-risk or spoof-like URL characteristics.")

        safe_context_hits = self._count_matches(text_lower, self.SAFE_CONTEXT_TERMS)
        if safe_context_hits >= 2 and score_breakdown["impersonation"] == 0 and score_breakdown["credential_theft"] == 0:
            score_breakdown["safe_context_adjustment"] = -12
            reasons.append("Detected benign conversational or business context.")

        total_score = max(0, min(100, sum(score_breakdown.values())))
        detected_count = sum(1 for value in signals.values() if value)
        if detected_count >= 4:
            total_score = min(100, int(total_score * 1.25))
        elif detected_count == 3:
            total_score = min(100, int(total_score * 1.12))

        category_floor = {
            "Phishing Attempt": 70,
            "Tech Support Scam": 62,
            "Job Scam": 48,
            "UPI/Payment Fraud": 58,
            "Extortion Threat": 72,
            "Crypto Investment Pitch": 55,
            "Romance Scam": 65,
        }
        total_score = max(total_score, category_floor.get(text_category, 0))

        if grammar["score"] < 45 and not signals["spelling_grammar_issues"]:
            signals["spelling_grammar_issues"] = True
            reasons.append("Message quality shows anomalies often seen in scam campaigns.")

        risk_level = self._map_risk_level(total_score)
        is_fraud = risk_level in {RiskLevel.HIGH, RiskLevel.CRITICAL}
        fraud_types = self._derive_fraud_types(text_category, signals, risk_level)
        confidence = self._compute_confidence(total_score, detected_count, text_category)
        recommendations = self._recommend_actions(signals, text_category, risk_level)

        data = {
            "is_fraud": is_fraud,
            "risk_score": total_score,
            "risk_level": risk_level,
            "fraud_type": fraud_types,
            "why_fraud": reasons or ["No high-risk behavior detected in the text."],
            "detected_signals": signals,
            "link_intelligence": link_intelligence,
            "text_error_analysis": grammar,
            "author_prediction": author_prediction,
            "recommended_action": recommendations,
            "confidence": confidence,
            "text_category": text_category,
        }

        processing_time = time.time() - start_time
        return ClassificationResult(data=data, processing_time=processing_time)

    def _compute_signals(self, text: str, text_lower: str) -> Tuple[Dict[str, bool], Dict[str, int], List[str]]:
        signals = {
            "urgency": False,
            "financial_lure": False,
            "impersonation": False,
            "credential_theft": False,
            "suspicious_url": bool(self.URL_PATTERN.search(text)),
            "ai_generated_tone": False,
            "spelling_grammar_issues": False,
            "social_engineering": False,
            "crypto_investment_pitch": False,
            "threat_extortion": False,
            "job_scam": False,
            "spam_marketing": False,
            "regional_upi_fraud": False,
            "tech_support_refund": False,
            "romance_fraud": False,
            "money_transfer_request": False,
        }

        score_breakdown = {
            "urgency": 0,
            "financial_lure": 0,
            "impersonation": 0,
            "credential_theft": 0,
            "suspicious_url": 10 if signals["suspicious_url"] else 0,
            "social_engineering": 0,
            "crypto_investment_pitch": 0,
            "threat_extortion": 0,
            "job_scam": 0,
            "spam_marketing": 0,
            "regional_upi_fraud": 0,
            "tech_support_refund": 0,
            "ai_generated_tone": 0,
            "spelling_grammar_issues": 0,
            "romance_fraud": 0,
            "money_transfer_request": 0,
            "safe_context_adjustment": 0,
        }

        reasons: List[str] = []

        urgency_hits = self._count_matches(text_lower, self.URGENCY_TERMS)
        if urgency_hits:
            signals["urgency"] = True
            score_breakdown["urgency"] = min(22, 10 + urgency_hits * 4)
            reasons.append("Contains urgency/deadline pressure language.")

        financial_hits = self._count_matches(text_lower, self.FINANCIAL_LURE_TERMS)
        if financial_hits:
            signals["financial_lure"] = True
            score_breakdown["financial_lure"] = min(26, 12 + financial_hits * 5)
            reasons.append("Contains unusually attractive financial promises or rewards.")

        impersonation_hits = self._count_matches(text_lower, self.IMPERSONATION_TERMS)
        if impersonation_hits:
            signals["impersonation"] = True
            score_breakdown["impersonation"] = min(28, 12 + impersonation_hits * 4)
            reasons.append("Uses authority or brand-like identity cues that may indicate impersonation.")

        credential_hits = self._count_matches(text_lower, self.CREDENTIAL_THEFT_TERMS)
        if credential_hits:
            signals["credential_theft"] = True
            score_breakdown["credential_theft"] = min(30, 14 + credential_hits * 5)
            reasons.append("Requests credentials, verification codes, or sensitive information.")

        social_hits = self._count_matches(text_lower, self.SOCIAL_ENGINEERING_TERMS)
        if social_hits:
            signals["social_engineering"] = True
            score_breakdown["social_engineering"] = min(18, 8 + social_hits * 3)
            reasons.append("Shows manipulation tactics (fear/greed/trust pressure).")

        crypto_hits = self._count_matches(text_lower, self.CRYPTO_TERMS)
        if crypto_hits:
            signals["crypto_investment_pitch"] = True
            score_breakdown["crypto_investment_pitch"] = min(18, 8 + crypto_hits * 3)
            reasons.append("Contains high-risk crypto investment pitch markers.")

        extortion_hits = self._count_matches(text_lower, self.EXTORTION_TERMS)
        if extortion_hits:
            signals["threat_extortion"] = True
            score_breakdown["threat_extortion"] = min(48, 28 + extortion_hits * 8)
            reasons.append("Contains extortion or blackmail-like threat language.")

        job_hits = self._count_matches(text_lower, self.JOB_SCAM_TERMS)
        if job_hits:
            signals["job_scam"] = True
            score_breakdown["job_scam"] = min(30, 14 + job_hits * 5)
            reasons.append("Contains fake-job style patterns (easy money/fees/task work).")

        marketing_hits = self._count_matches(text_lower, self.MARKETING_TERMS)
        if marketing_hits >= 2:
            signals["spam_marketing"] = True
            score_breakdown["spam_marketing"] = min(14, 6 + marketing_hits * 2)
            reasons.append("Looks like bulk promotional messaging pattern.")

        upi_hits = self._count_matches(text_lower, self.UPI_TERMS)
        if upi_hits:
            signals["regional_upi_fraud"] = True
            score_breakdown["regional_upi_fraud"] = min(20, 10 + upi_hits * 3)
            reasons.append("Includes payment app/UPI phrasing often used in regional fraud attempts.")

        tech_hits = self._count_matches(text_lower, self.TECH_SUPPORT_TERMS)
        if tech_hits:
            signals["tech_support_refund"] = True
            score_breakdown["tech_support_refund"] = min(22, 10 + tech_hits * 4)
            reasons.append("Contains fake tech-support or refund scam indicators.")

        romance_hits = self._count_matches(text_lower, self.ROMANCE_FRAUD_TERMS)
        money_transfer_hits = self._count_matches(text_lower, self.MONEY_TRANSFER_TERMS)
        if romance_hits >= 2:
            signals["romance_fraud"] = True
            score_breakdown["romance_fraud"] = min(35, 15 + romance_hits * 7)
            reasons.append("Contains romance scam or emotional manipulation language.")
        
        if money_transfer_hits:
            signals["money_transfer_request"] = True
            score_breakdown["money_transfer_request"] = min(32, 16 + money_transfer_hits * 5)
            reasons.append("Contains explicit requests for money transfer or banking information.")

        ai_tone_flag = self._detect_ai_tone(text)
        if ai_tone_flag:
            signals["ai_generated_tone"] = True
            score_breakdown["ai_generated_tone"] = 8
            reasons.append("Shows repetitive/formulaic sentence construction.")

        grammar_profile = self._analyze_text_quality(text)
        if grammar_profile["typos"] or grammar_profile["grammar_issues"]:
            signals["spelling_grammar_issues"] = True
            score_breakdown["spelling_grammar_issues"] = min(
                15,
                3 + len(grammar_profile["typos"]) * 2 + len(grammar_profile["grammar_issues"]) * 3,
            )

        if signals["job_scam"] and (signals["financial_lure"] or signals["social_engineering"]):
            score_breakdown["job_scam"] = min(36, score_breakdown["job_scam"] + 8)
        if signals["threat_extortion"] and (signals["urgency"] or signals["credential_theft"]):
            score_breakdown["threat_extortion"] = min(56, score_breakdown["threat_extortion"] + 10)

        return signals, score_breakdown, reasons

    def _analyze_links(self, text: str):
        urls = self.URL_PATTERN.findall(text or "")
        if not urls:
            return None

        first_url = urls[0].rstrip(".,!?:;)")
        parsed = urlparse(first_url)
        domain = (parsed.netloc or "").lower().replace("www.", "")
        tld = domain.split(".")[-1] if "." in domain else ""

        tld_risk = tld in self.HIGH_RISK_TLDS
        is_shortener = domain in self.SHORTENER_DOMAINS
        looks_spoof = any(token in domain for token in ["verify", "secure", "update", "login"]) and domain not in self.SAFE_DOMAINS
        has_https = parsed.scheme == "https"

        if domain in self.SAFE_DOMAINS and has_https and not tld_risk:
            reputation = "Known safe domain profile"
            google_presence = "High"
        elif tld_risk or is_shortener or looks_spoof:
            reputation = "Suspicious link footprint"
            google_presence = "Low"
        else:
            reputation = "Unknown domain profile"
            google_presence = "Medium"

        return {
            "domain_age_days": 0,
            "tld_risk": tld_risk or is_shortener,
            "brand_spoofing": looks_spoof,
            "google_presence": google_presence,
            "reputation_summary": reputation,
        }

    def _analyze_text_quality(self, text: str) -> Dict[str, List[str] | int]:
        words = self.WORD_PATTERN.findall(text.lower())
        typos: List[str] = []
        issues: List[str] = []

        for token in words:
            if token in self.TYPO_HINTS:
                typos.append(token)

        all_caps_words = re.findall(r"\b[A-Z]{4,}\b", text)
        punct_bursts = re.findall(r"[!?]{2,}", text)
        odd_tokens = [w for w in words if len(w) >= 8 and self._looks_gibberish(w)]

        if all_caps_words:
            issues.append("Excessive capitalized emphasis")
        if punct_bursts:
            issues.append("Excessive punctuation bursts")
        if odd_tokens:
            issues.append("Potential gibberish or obfuscated words")
        if len(text.split()) <= 2:
            issues.append("Very short content; limited context")

        typo_count = len(typos)
        word_count = max(1, len(words))
        issue_penalty = 0
        for issue in issues:
            if issue == "Potential gibberish or obfuscated words":
                issue_penalty += 14
            elif issue == "Excessive capitalized emphasis":
                issue_penalty += 8
            elif issue == "Excessive punctuation bursts":
                issue_penalty += 6
            elif issue == "Very short content; limited context":
                issue_penalty += 4

        raw_penalty = typo_count * 6 + issue_penalty
        density_factor = min(1.35, 16 / word_count)
        quality_penalty = min(80, int(raw_penalty * density_factor))
        final_score = max(20, min(100, 100 - quality_penalty))

        return {
            "typos": sorted(set(typos))[:8],
            "grammar_issues": issues,
            "score": final_score,
        }

    def _predict_author_style(self, text: str, grammar: Dict[str, List[str] | int]) -> str:
        sentence_count = max(1, len(re.findall(r"[.!?]", text)))
        avg_sentence_length = max(1, len(text.split())) / sentence_count

        repetitive_templates = [
            "dear customer", "we regret to inform", "kindly do the needful", "act now"
        ]
        repeated_template_hits = self._count_matches(text.lower(), set(repetitive_templates))
        grammar_score = int(grammar.get("score", 70))

        if repeated_template_hits >= 2 and avg_sentence_length > 15:
            return "Likely AI Generated"
        if grammar_score >= 85 and avg_sentence_length >= 10:
            return "Likely Human (Professional)"
        if grammar_score < 55:
            return "Likely Human (Informal/Noisy)"
        return "Unknown"

    def _detect_ai_tone(self, text: str) -> bool:
        lowered = text.lower()
        common_ai_phrases = {
            "i hope this message finds you well",
            "we would like to inform you",
            "please do not hesitate to contact",
            "kindly be advised",
        }
        phrase_hits = self._count_matches(lowered, common_ai_phrases)

        lines = [line.strip() for line in text.splitlines() if line.strip()]
        near_duplicate_lines = len(lines) >= 3 and len(set(lines)) <= max(1, len(lines) - 2)
        return phrase_hits > 0 or near_duplicate_lines

    def _detect_text_category(self, text_lower: str, signals: Dict[str, bool]) -> str:
        if signals["threat_extortion"]:
            return "Extortion Threat"
        if signals["romance_fraud"] or (signals["romance_fraud"] and signals["money_transfer_request"]):
            return "Romance Scam"
        if signals["tech_support_refund"]:
            return "Tech Support Scam"
        if signals["job_scam"]:
            return "Job Scam"
        if signals["crypto_investment_pitch"]:
            return "Crypto Investment Pitch"
        if signals["credential_theft"] and signals["impersonation"]:
            return "Phishing Attempt"
        if signals["regional_upi_fraud"] and signals["credential_theft"]:
            return "UPI/Payment Fraud"
        if signals["spam_marketing"] and not signals["credential_theft"]:
            return "Promotional Spam"
        if self._count_matches(text_lower, self.SAFE_CONTEXT_TERMS) >= 2:
            return "Benign Personal/Business Message"
        return "General Message"

    def _derive_fraud_types(self, text_category: str, signals: Dict[str, bool], risk_level: str) -> List[str]:
        fraud_types: List[str] = []
        if signals["impersonation"]:
            fraud_types.append("Impersonation")
        if signals["credential_theft"]:
            fraud_types.append("Credential Theft")
        if signals["suspicious_url"]:
            fraud_types.append("Suspicious Link")
        if signals["financial_lure"]:
            fraud_types.append("Financial Scam")
        if signals["job_scam"]:
            fraud_types.append("Job Scam")
        if signals["threat_extortion"]:
            fraud_types.append("Extortion")
        if signals["tech_support_refund"]:
            fraud_types.append("Tech Support Scam")
        if signals["romance_fraud"]:
            fraud_types.append("Romance Scam")
        if signals["money_transfer_request"]:
            fraud_types.append("Money Transfer Fraud")

        if not fraud_types:
            if risk_level == RiskLevel.LOW:
                return ["None"]
            return [text_category]
        return sorted(set(fraud_types))

    def _recommend_actions(self, signals: Dict[str, bool], text_category: str, risk_level: str) -> List[str]:
        actions: List[str] = []
        if risk_level in {RiskLevel.HIGH, RiskLevel.CRITICAL}:
            actions.append("Do not click links or share personal/financial information.")
            actions.append("Verify sender identity through an official channel before responding.")

        if signals["credential_theft"]:
            actions.append("Never share OTP, password, PIN, or verification codes.")
        if signals["suspicious_url"]:
            actions.append("Inspect links carefully and prefer typing official domains manually.")
        if signals["tech_support_refund"]:
            actions.append("Avoid remote-access tools unless you initiated support from a trusted source.")
        if signals["regional_upi_fraud"]:
            actions.append("Reject unexpected UPI collect requests and verify transactions in-app.")
        if signals["romance_fraud"]:
            actions.append("Be cautious of false romantic relationships seeking personal/financial information.")
        if signals["money_transfer_request"]:
            actions.append("Never send money or share banking details to unknown contacts.")

        if not actions:
            if text_category == "Benign Personal/Business Message":
                actions.append("Message appears low risk; continue normal caution for unknown links.")
            else:
                actions.append("No strong fraud markers found; verify context if sender is unknown.")

        return actions[:5]

    def _compute_confidence(self, score: int, detected_count: int, text_category: str) -> float:
        base = 0.55
        score_factor = min(0.3, score / 350)
        signal_factor = min(0.12, detected_count * 0.025)
        category_factor = 0.05 if text_category not in {"General Message", "Benign Personal/Business Message"} else 0.0
        return round(min(0.97, base + score_factor + signal_factor + category_factor), 2)

    def _map_risk_level(self, score: int) -> str:
        if score >= 80:
            return RiskLevel.CRITICAL
        if score >= 60:
            return RiskLevel.HIGH
        if score >= 35:
            return RiskLevel.MEDIUM
        return RiskLevel.LOW

    def _count_matches(self, text_lower: str, terms: set) -> int:
        hits = 0
        for term in terms:
            if term in text_lower:
                hits += 1
        return hits

    def _looks_gibberish(self, word: str) -> bool:
        if word in self.COMMON_SHORT_WORDS:
            return False
        vowels = len(re.findall(r"[aeiou]", word))
        consonants = len(re.findall(r"[bcdfghjklmnpqrstvwxyz]", word))
        if vowels == 0 and len(word) >= 7:
            return True
        if consonants >= 6 and vowels <= 1:
            return True
        repeated_run = re.search(r"(.)\1{3,}", word)
        return bool(repeated_run)
