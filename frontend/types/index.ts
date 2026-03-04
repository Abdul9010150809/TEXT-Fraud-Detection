export type RiskLevel = 'SAFE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export type FraudSignal = {
    id: string;
    category: 'CONTENT' | 'URL' | 'BEHAVIOR' | 'TECHNICAL';
    name: string;
    detected: boolean;
    score: number; // 0-100 impact
    description: string;
};

export type FraudTypeConfidence = {
    type: string; // Phishing, Scam, Malware, etc.
    confidence: number; // 0-100
};

export type TimelineStep = {
    id: string;
    name: string;
    status: 'PENDING' | 'PROCESSING' | 'COMPLETED' | 'FLAGGED';
    timestamp: string;
    details?: string;
};

export type FraudResult = {
    id: string;
    analyzedContent: string;
    inputType: 'TEXT' | 'URL' | 'MIXED';
    timestamp: string;

    // Core Metrics
    riskScore: number; // 0-100
    riskLevel: RiskLevel;
    verdict: 'FRAUD' | 'SAFE' | 'SUSPICIOUS';
    confidenceScore: number; // 0-100

    // Detailed Analysis
    fraudTypes: FraudTypeConfidence[];
    signals: FraudSignal[];

    // Explanations
    explanation: {
        whyFraud: string[];
        whyNotFraud: string[];
    };

    // Advanced Features
    linkIntelligence?: {
        url: string;
        domain: string;
        domainAge: string; // e.g., "2 days"
        hasSsl: boolean;
        redirectCount: number;
        isMasked: boolean;
        reputation: 'CLEAN' | 'SUSPICIOUS' | 'MALICIOUS';
    };

    googlePresence: {
        found: boolean;
        snippet?: string;
        source?: string;
    };

    recommendedActions: string[];

    // For Comparison/Timeline
    timeline: TimelineStep[];
};
