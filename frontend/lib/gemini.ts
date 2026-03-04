import { GoogleGenerativeAI, Part } from "@google/generative-ai";
import { DEMO_DATASET } from "@/data/demo_dataset";

const API_KEY = process.env.NEXT_PUBLIC_GEMINI_API_KEY || "";
const genAI = new GoogleGenerativeAI(API_KEY);

// UPDATED: Injected Real Examples from local 'dataset/spam_texts.csv'
const FEW_SHOT_EXAMPLES = `
REFERENCE FRAUD DATABASE (LOCAL DATASET PATTERNS):
1. [DATASET_BANK_01]: "Dear Customer, Your SBI Bank Account has been blocked by 5:00 PM. Please update your PAN card immediately: http://bit.ly/sbikyc" -> Risk: CRITICAL. Signals: Urgency (5:00 PM), Account Blocked, Short Link.
2. [DATASET_LOTTERY_02]: "Congratulation! Your number has won 25,00,000 in KBC Lottery. Call Rana Pratap Singh 9876543210" -> Risk: HIGH. Signals: Lottery, Large Amount, Personal Name for Authority.
3. [DATASET_JOB_03]: "Part time job! Earn Rs 5000-10000 daily working from home. No investment. Contact WhatsApp: wa.me/9199xxxxxx" -> Risk: HIGH. Signals: Unrealistic Earnings, WhatsApp Redirection, No Investment trap.
4. [DATASET_ELECTRICITY_04]: "Dear User, your electricity power will be disconnected tonight at 9:30 PM because your previous month bill was not updated. Call 890xxxx" -> Risk: CRITICAL. Signals: Utility Disconnection, Tonight Deadline, Personal Number.
5. [DATASET_LOAN_05]: "Pre-approved Personal Loan of Rs 5 Lakhs credited to your wallet. Click to claim: http://loan-bazaar.xyz" -> Risk: MEDIUM/HIGH. Signals: Pre-approved, Wallet Credit, Suspicious Domain.
`;

export interface AnalysisResponse {
    input_id?: string;
    is_fraud: boolean;
    risk_score: number;
    risk_level: "Safe" | "Suspicious" | "High" | "Gray" | "Critical";
    fraud_type: string[];
    why_fraud: string[];
    risky_phrases: string[];
    detected_signals: {
        urgency: boolean;
        financial_lure: boolean;
        impersonation: boolean;
        credential_theft: boolean;
        suspicious_url: boolean;
        ai_generated_tone: boolean;
        spelling_grammar_issues: boolean;
        social_engineering: boolean;
        crypto_investment_pitch: boolean;
        threat_extortion: boolean;
        job_scam: boolean;
        spam_marketing: boolean;
        regional_upi_fraud: boolean;
        romance_scam: boolean;
        tech_support_refund: boolean;
    };
    link_analysis: {
        domain: string;
        shortened: boolean;
        brand_spoofing: boolean;
        google_presence: "High" | "Medium" | "Low" | "Not Found";
    };
    similar_case_match?: {
        id: string;
        similarity_score: number;
        description: string;
    };
    text_error_analysis?: {
        typos: string[];
        grammar_issues: string[];
        score: number;
    };
    bank_verification?: {
        detected_bank: string | null;
        is_official_domain: boolean;
        risk_reason: string | null;
    };
    counterfactual_safe_conditions: string[];
    campaign_detected: boolean;
    recommended_action: string[];
    model_self_check: {
        possible_misclassification_reason: string;
        confidence_calibration: "High" | "Medium" | "Low";
    };
    confidence: number;
    explanation: string;
    signals: string[];
    tone: "Normal" | "Urgent" | "Manipulative" | "AI-Like";
    author_prediction: "AI Generated" | "Human Typed" | "Unknown";
    api_signals?: Array<{ api: string; icon: string; verdict: string; score: number; flagged: boolean; detail: string }>;
}

export async function analyzeContent(text: string, useMock: boolean = false): Promise<AnalysisResponse> {
    if (useMock || !API_KEY) {
        return getMockAnalysis(text);
    }

    try {
        const model = genAI.getGenerativeModel({ model: "gemini-1.5-flash" });

        const prompt = `
      You are an expert AI Fraud Intelligence Analyst focusing ONLY on TEXT scams.
      Analyze the text content for fraud patterns using the Local Reference Database.

      ${FEW_SHOT_EXAMPLES}
      
      INPUT TEXT: "${text || "No text provided."}"
      
      TASK Checklist:
      You MUST analyze the text for these 15 core scam signals:
      1. urgency (Pressure tactics, "act now")
      2. financial_lure (Lotteries, free money)
      3. impersonation (Pretending to be bank/authority)
      4. credential_theft (Asking for OTP/passwords)
      5. suspicious_url (Shady or shortened links)
      6. ai_generated_tone (Overly formal or robotic)
      7. spelling_grammar_issues (Intentional typos to bypass filters)
      8. social_engineering (Guilt trips, "I need help")
      9. crypto_investment_pitch (Guaranteed ROI, BTC)
      10. threat_extortion (Blackmail, data leaks)
      11. job_scam (Fake employment, upfront payment)
      12. spam_marketing (Unsolicited bulk marketing)
      13. regional_upi_fraud (Localized UPI or CashApp fraud)
      14. romance_scam (Fabricated relationships for exploitation)
      15. tech_support_refund (Fake tech support, overpayment refund)

      RETURN VALID JSON:
      {
        "is_fraud": boolean,
        "risk_score": number (0-100),
        "risk_level": "Safe" | "Suspicious" | "High" | "Gray" | "Critical",
        "fraud_type": ["Phishing", "Identity Theft", "Social Engineering", "Extortion", "None"],
        "why_fraud": ["Reason 1"],
        "risky_phrases": ["substring 1"],
        "detected_signals": {
            "urgency": boolean,
            "financial_lure": boolean,
            "impersonation": boolean,
            "credential_theft": boolean,
            "suspicious_url": boolean,
            "ai_generated_tone": boolean,
            "spelling_grammar_issues": boolean,
            "social_engineering": boolean,
            "crypto_investment_pitch": boolean,
            "threat_extortion": boolean,
            "job_scam": boolean,
            "spam_marketing": boolean,
            "regional_upi_fraud": boolean,
            "romance_scam": boolean,
            "tech_support_refund": boolean
        },
        "link_analysis": {
            "domain": "string",
            "shortened": boolean,
            "brand_spoofing": boolean,
            "google_presence": "High" | "Medium" | "Low" | "Not Found"
        },
        "similar_case_match": {
            "id": "PATTERN_ID_OR_NONE",
            "similarity_score": number, 
            "description": "reason"
        },
        "text_error_analysis": {
            "typos": ["list"],
            "grammar_issues": ["list"],
            "score": number
        },
        "bank_verification": {
            "detected_bank": "Name/null",
            "is_official_domain": boolean,
            "risk_reason": "string"
        },
        "counterfactual_safe_conditions": ["If X"],
        "campaign_detected": boolean,
        "recommended_action": ["Action"],
        "model_self_check": {
            "possible_misclassification_reason": "Reason",
            "confidence_calibration": "High"
        },
        "confidence": number,
        "explanation": "Summary",
        "signals": ["List"],
        "tone": "Normal" | "Urgent" | "Manipulative",
        "author_prediction": "AI Generated" | "Human Typed" | "Unknown"
      }
    `;

        const parts: Part[] = [{ text: prompt }];
        const result = await model.generateContent(parts);
        const response = await result.response;
        const textOutput = response.text();
        const cleanedJson = textOutput.replace(/```json/g, '').replace(/```/g, '').trim();

        return JSON.parse(cleanedJson) as AnalysisResponse;

    } catch (error) {
        console.error("Gemini API Error:", error);
        return getMockAnalysis(text);
    }
}

function getMockAnalysis(text: string): AnalysisResponse {
    const lowerText = text.toLowerCase();

    // Check for demo dataset match first
    const demoMatch = DEMO_DATASET.find(d =>
        d.text.toLowerCase().includes(lowerText) ||
        lowerText.includes(d.text.toLowerCase()) ||
        (lowerText.length > 20 && d.text.toLowerCase().substring(0, 30) === lowerText.substring(0, 30))
    );

    // Initialize risk score and signals
    let riskScore = 0;
    const detectedSignals = {
        urgency: false,
        financial_lure: false,
        impersonation: false,
        credential_theft: false,
        suspicious_url: false,
        ai_generated_tone: false,
        spelling_grammar_issues: false,
        social_engineering: false,
        crypto_investment_pitch: false,
        threat_extortion: false,
        job_scam: false,
        spam_marketing: false,
        regional_upi_fraud: false,
        romance_scam: false,
        tech_support_refund: false
    };
    const fraudTypes: string[] = [];
    const whyFraud: string[] = [];
    const riskyPhrases: string[] = [];
    const signals: string[] = [];

    // 1. URGENCY DETECTION (High Weight: +25 points)
    const urgencyKeywords = ['urgent', 'immediate', 'immediately', 'block', 'blocked', 'suspend', 'suspended', 'today', 'tonight', 'now', 'asap', 'expire', 'expires', 'limited time', 'act now', 'deadline'];
    const urgencyMatches = urgencyKeywords.filter(kw => lowerText.includes(kw));
    if (urgencyMatches.length > 0) {
        detectedSignals.urgency = true;
        riskScore += 25;
        whyFraud.push(`Urgency tactics detected: "${urgencyMatches.join('", "')}" - creates panic to bypass critical thinking`);
        riskyPhrases.push(...urgencyMatches);
        signals.push('Urgency Pressure');
    }

    // 2. FINANCIAL/PRIZE KEYWORDS (High Weight: +30 points)
    const financialKeywords = ['prize', 'won', 'winner', 'lottery', 'congratulation', 'reward', 'cash', 'money', 'transfer', 'claim', 'lakh', 'crore', 'million', 'free', 'bonus'];
    const financialMatches = financialKeywords.filter(kw => lowerText.includes(kw));
    if (financialMatches.length > 0) {
        riskScore += Math.min(30, financialMatches.length * 15);
        fraudTypes.push('Financial Scam');
        whyFraud.push(`Financial lure detected: "${financialMatches.join('", "')}" - typical lottery/prize scam pattern`);
        riskyPhrases.push(...financialMatches);
        signals.push('Financial Incentive');
    }

    // 3. BANK/ORGANIZATION IMPERSONATION (Critical: +35 points)
    const bankKeywords = ['sbi', 'hdfc', 'icici', 'axis', 'bank', 'paypal', 'paytm', 'google pay', 'phonepe', 'amazon', 'flipkart', 'rbi'];
    const bankMatches = bankKeywords.filter(kw => lowerText.includes(kw));
    if (bankMatches.length > 0) {
        detectedSignals.impersonation = true;
        riskScore += 35;
        fraudTypes.push('Impersonation');
        whyFraud.push(`Impersonating trusted organization: "${bankMatches.join('", "')}" - high-risk phishing indicator`);
        signals.push('Brand Impersonation');
    }

    // 4. OTP/VERIFICATION REQUEST (Critical: +30 points)
    const otpKeywords = ['otp', 'one time password', 'verification code', 'verify', 'confirm', 'validate', 'authenticate', 'kyc', 'update details', 'update pan'];
    const otpMatches = otpKeywords.filter(kw => lowerText.includes(kw));
    if (otpMatches.length > 0) {
        detectedSignals.credential_theft = true;
        riskScore += 30;
        fraudTypes.push('Credential Theft');
        whyFraud.push(`Requesting sensitive information: "${otpMatches.join('", "')}" - credential harvesting attempt`);
        riskyPhrases.push(...otpMatches);
        signals.push('OTP/Credential Request');
    }

    // 5. SUSPICIOUS LINKS (High Weight: +25 points)
    const urlPattern = /(https?:\/\/[^\s]+)|(bit\.ly|tinyurl|short\.link|goo\.gl)/gi;
    const urls = text.match(urlPattern);
    if (urls) {
        detectedSignals.suspicious_url = true;
        const hasShortener = /bit\.ly|tinyurl|short\.link|goo\.gl/i.test(text);
        const hasSuspiciousDomain = /\.xyz|\.tk|\.ml|\.ga|\.cf|-secure|-verify|-update|-login/i.test(text);

        if (hasShortener) {
            riskScore += 20;
            whyFraud.push('URL shortener detected - hides true destination');
            signals.push('Shortened URL');
        }
        if (hasSuspiciousDomain) {
            riskScore += 25;
            whyFraud.push('Suspicious domain pattern detected - likely spoofing');
            signals.push('Suspicious Domain');
        }
    }

    // 6. AI-GENERATED TONE DETECTION (+15 points)
    const aiPhrases = ['dear valued', 'kindly request', 'cooperation', 'uninterrupted access', 'we regret', 'inconvenience caused'];
    const aiMatches = aiPhrases.filter(phrase => lowerText.includes(phrase));
    if (aiMatches.length >= 2) {
        detectedSignals.ai_generated_tone = true;
        riskScore += 15;
        fraudTypes.push('AI Generated');
        whyFraud.push('Overly formal/generic phrasing typical of AI-generated phishing templates');
        signals.push('AI-Like Tone');
    }

    // 7. SOCIAL ENGINEERING (+20 points)
    const socialEngineering = ['bro', 'friend', 'help', 'stuck', 'emergency', 'battery dead', 'phone lost'];
    const socialMatches = socialEngineering.filter(kw => lowerText.includes(kw));
    if (socialMatches.length >= 2) {
        riskScore += 20;
        fraudTypes.push('Social Engineering');
        whyFraud.push('Personal connection exploitation - leveraging trust to bypass security');
        signals.push('Social Engineering');
    }

    // 8. DATA LEAK/EXTORTION
    const extortionKeywords = ['hack', 'recorded', 'webcam', 'password', 'leak', 'expose', 'bitcoin', 'payment'];
    const extortionMatches = extortionKeywords.filter(kw => lowerText.includes(kw));
    if (extortionMatches.length >= 3) {
        detectedSignals.threat_extortion = true;
        riskScore += 90;
        fraudTypes.push('Extortion');
        whyFraud.push('Extortion markers detected - usually associated with fake sextortion emails/texts');
        signals.push('Threat/Extortion');
    }

    // 9. BANK VERIFICATION
    let bankVerification = undefined;
    if (bankMatches.length > 0) {
        const detectedBank = bankMatches[0].toUpperCase();
        const hasOfficialDomain = /\.in|\.com/.test(lowerText) && !/-secure|-verify|-update/.test(lowerText);
        bankVerification = {
            detected_bank: detectedBank,
            is_official_domain: hasOfficialDomain,
            risk_reason: hasOfficialDomain ? null : "Domain appears to be spoofed or unofficial"
        };
    }

    // 10. SAFE INDICATORS (Reduce risk score)
    const safeIndicators = ['thank you', 'regards', 'official', 'customer service', 'help desk'];
    const safeMatches = safeIndicators.filter(kw => lowerText.includes(kw));
    if (safeMatches.length > 0 && riskScore < 50) {
        riskScore = Math.max(0, riskScore - 15);
    }

    // Very casual/normal conversation
    const casualPhrases = ['can you', 'could you', 'please send', 'notes', 'homework', 'meeting'];
    const casualMatches = casualPhrases.filter(kw => lowerText.includes(kw));
    if (casualMatches.length >= 2 && riskScore < 30) {
        riskScore = Math.max(0, riskScore - 20);
    }

    // If demo match found, use its risk level but with calculated score
    if (demoMatch) {
        const demoRiskMap: Record<string, number> = {
            'CRITICAL': 90,
            'HIGH': 75,
            'MEDIUM': 50,
            'LOW': 10
        };
        riskScore = demoRiskMap[demoMatch.riskLevel] || riskScore;

        return {
            is_fraud: demoMatch.riskLevel !== 'LOW',
            risk_score: riskScore,
            risk_level: demoMatch.riskLevel as "Safe" | "Suspicious" | "High" | "Critical",
            fraud_type: [demoMatch.fraudType],
            why_fraud: [demoMatch.explanation],
            risky_phrases: riskyPhrases.length > 0 ? riskyPhrases : ["account blocked"],
            detected_signals: detectedSignals,
            link_analysis: { domain: urls ? urls[0].replace(/https?:\/\//, '').split('/')[0] : "mock.com", shortened: /bit\.ly|tinyurl/i.test(text), brand_spoofing: detectedSignals.impersonation, google_presence: "Medium" },
            similar_case_match: { id: demoMatch.id, similarity_score: 95, description: demoMatch.explanation },
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
            text_error_analysis: (demoMatch as any).textErrorAnalysis || { typos: [], grammar_issues: [], score: 85 },
            bank_verification: bankVerification,
            counterfactual_safe_conditions: ["If sender used official domain", "If no urgency language was used"],
            campaign_detected: false,
            recommended_action: riskScore > 70 ? ["Do not click any links", "Report as spam", "Verify through official channels"] : ["Verify sender identity"],
            model_self_check: { possible_misclassification_reason: "Demo dataset match", confidence_calibration: "High" },
            confidence: 90,
            explanation: demoMatch.explanation,
            signals: signals.length > 0 ? signals : ["Demo Match"],
            tone: detectedSignals.urgency ? "Urgent" : detectedSignals.ai_generated_tone ? "AI-Like" : "Normal",
            author_prediction: detectedSignals.ai_generated_tone ? "AI Generated" : "Unknown"
        };
    }

    // Calculate final risk level based on score
    let riskLevel: "Safe" | "Suspicious" | "High" | "Critical" = "Safe";
    let isFraud = false;

    if (riskScore >= 80) {
        riskLevel = "Critical";
        isFraud = true;
    } else if (riskScore >= 60) {
        riskLevel = "High";
        isFraud = true;
    } else if (riskScore >= 30) {
        riskLevel = "Suspicious";
        isFraud = true;
    } else {
        riskLevel = "Safe";
        isFraud = false;
    }

    // Ensure we have at least some fraud type
    if (fraudTypes.length === 0 && isFraud) {
        fraudTypes.push('Possible Scam');
    }
    if (fraudTypes.length === 0 && !isFraud) {
        fraudTypes.push('None');
    }

    // Build explanation
    let explanation = "";
    if (isFraud) {
        explanation = `Risk Score: ${riskScore}/100. ${whyFraud.join('. ')}.`;
    } else {
        explanation = "Content appears safe. No significant fraud indicators detected.";
    }

    return {
        is_fraud: isFraud,
        risk_score: riskScore,
        risk_level: riskLevel,
        fraud_type: fraudTypes,
        why_fraud: whyFraud.length > 0 ? whyFraud : ["No significant fraud indicators"],
        risky_phrases: riskyPhrases,
        detected_signals: detectedSignals,
        link_analysis: {
            domain: urls ? urls[0].replace(/https?:\/\//, '').split('/')[0] : "",
            shortened: /bit\.ly|tinyurl|short\.link/i.test(text),
            brand_spoofing: detectedSignals.impersonation,
            google_presence: riskScore > 60 ? "Low" : "Medium"
        },
        similar_case_match: undefined,
        text_error_analysis: { typos: [], grammar_issues: [], score: 85 },
        bank_verification: bankVerification,
        counterfactual_safe_conditions: isFraud ? ["Remove urgency language", "Use official communication channels", "Verify sender identity"] : [],
        campaign_detected: false,
        recommended_action: riskScore > 70 ? ["Do not respond", "Do not click links", "Report as spam", "Verify through official channels"] : riskScore > 30 ? ["Verify sender identity", "Check for official domain"] : ["Appears safe"],
        model_self_check: {
            possible_misclassification_reason: riskScore < 30 ? "May miss sophisticated attacks" : "Heuristic-based detection",
            confidence_calibration: riskScore > 60 || riskScore < 20 ? "High" : "Medium"
        },
        confidence: riskScore > 60 ? 85 : riskScore > 30 ? 70 : 60,
        explanation: explanation,
        signals: signals.length > 0 ? signals : ["Content Analysis Complete"],
        tone: detectedSignals.urgency ? "Urgent" : detectedSignals.ai_generated_tone ? "AI-Like" : "Normal",
        author_prediction: detectedSignals.ai_generated_tone ? "AI Generated" : "Unknown"
    };
}
