import { FraudResult } from '@/types';

const MOCK_DELAY = 1500; // Simulate network latency

export const MOCK_SCENARIOS: Record<string, FraudResult> = {
    SAFE: {
        id: 'res-safe-001',
        analyzedContent: "Hi John, your order #12345 has been shipped via UPS. Track it here: https://ups.com/track/12345",
        inputType: 'TEXT',
        timestamp: new Date().toISOString(),
        riskScore: 5,
        riskLevel: 'SAFE',
        verdict: 'SAFE',
        confidenceScore: 98,
        fraudTypes: [],
        signals: [
            { id: 'sig-1', category: 'URL', name: 'Legitimate Domain', detected: true, score: 0, description: 'Domain belongs to a known entity (UPS).' },
            { id: 'sig-2', category: 'CONTENT', name: 'Transactional context', detected: true, score: 0, description: 'Message matches standard shipping notification patterns.' }
        ],
        explanation: {
            whyFraud: [],
            whyNotFraud: ['Domain ups.com is highly reputable', 'SSL certificate is valid from DigiCert', 'No urgency or pressure tactics detected']
        },
        linkIntelligence: {
            url: 'https://ups.com/track/12345',
            domain: 'ups.com',
            domainAge: '> 20 years',
            hasSsl: true,
            redirectCount: 0,
            isMasked: false,
            reputation: 'CLEAN'
        },
        googlePresence: {
            found: true,
            snippet: 'UPS - United Parcel Service',
            source: 'Knowledge Graph'
        },
        recommendedActions: ['No action needed', 'Safe to click'],
        timeline: [
            { id: 't1', name: 'Text Analysis', status: 'COMPLETED', timestamp: new Date().toISOString() },
            { id: 't2', name: 'Link Expansion', status: 'COMPLETED', timestamp: new Date().toISOString() },
            { id: 't3', name: 'Threat Intelligence', status: 'COMPLETED', timestamp: new Date().toISOString() },
            { id: 't4', name: 'Final Verdict', status: 'COMPLETED', timestamp: new Date().toISOString() }
        ]
    },
    PHISHING: {
        id: 'res-phish-001',
        analyzedContent: "URGENT: Your Wells Fargo account has been locked due to suspicious activity. Verify immediately: http://wells-fargo-security-check.com/login",
        inputType: 'TEXT',
        timestamp: new Date().toISOString(),
        riskScore: 92,
        riskLevel: 'CRITICAL',
        verdict: 'FRAUD',
        confidenceScore: 95,
        fraudTypes: [
            { type: 'Phishing', confidence: 95 },
            { type: 'Brand Impersonation', confidence: 88 }
        ],
        signals: [
            { id: 'sig-3', category: 'URL', name: 'Typosquatting Detected', detected: true, score: 90, description: 'Domain mimics wellsfargo.com but is registered yesterday.' },
            { id: 'sig-4', category: 'BEHAVIOR', name: 'Urgency/Fear', detected: true, score: 75, description: 'Uses panic language ("URGENT", "Locked").' },
            { id: 'sig-5', category: 'TECHNICAL', name: 'HTTP only', detected: true, score: 60, description: 'Site does not use SSL (HTTPS).' }
        ],
        explanation: {
            whyFraud: ['Domain is unrelated to official Wells Fargo entity', 'High-pressure urgency tactics used', 'New domain registration (< 24 hours)'],
            whyNotFraud: []
        },
        linkIntelligence: {
            url: 'http://wells-fargo-security-check.com/login',
            domain: 'wells-fargo-security-check.com',
            domainAge: '1 day',
            hasSsl: false,
            redirectCount: 1,
            isMasked: false,
            reputation: 'MALICIOUS'
        },
        googlePresence: {
            found: false
        },
        recommendedActions: ['Do NOT click the link', 'Report to bank via official app', 'Block sender'],
        timeline: [
            { id: 't1', name: 'Text Analysis', status: 'COMPLETED', timestamp: new Date().toISOString() },
            { id: 't2', name: 'Link Expansion', status: 'FLAGGED', details: 'Suspicious Redirect', timestamp: new Date().toISOString() },
            { id: 't3', name: 'Threat Intelligence', status: 'FLAGGED', details: 'Blacklisted Domain', timestamp: new Date().toISOString() },
            { id: 't4', name: 'Final Verdict', status: 'COMPLETED', timestamp: new Date().toISOString() }
        ]
    },
    SCAM: {
        id: 'res-scam-001',
        analyzedContent: "Congrats! You've won a $1000 Walmart gift card. Click here to claim your prize provided you pay $5 shipping: bit.ly/claims-prize-now",
        inputType: 'TEXT',
        timestamp: new Date().toISOString(),
        riskScore: 85,
        riskLevel: 'HIGH',
        verdict: 'FRAUD',
        confidenceScore: 88,
        fraudTypes: [
            { type: 'Advance Fee Fraud', confidence: 90 },
            { type: 'Prize Scam', confidence: 85 }
        ],
        signals: [
            { id: 'sig-6', category: 'CONTENT', name: 'Too Good To Be True', detected: true, score: 80, description: 'Promises large reward for small payment.' },
            { id: 'sig-7', category: 'URL', name: 'URL Shortener', detected: true, score: 50, description: 'Uses bit.ly to hide destination.' },
            { id: 'sig-8', category: 'BEHAVIOR', name: 'Monetary Demand', detected: true, score: 70, description: 'Asks for upfront payment.' }
        ],
        explanation: {
            whyFraud: ['Classic "Advance Fee" scam pattern', 'Hidden destination URL via shortener', 'Unsolicited prize notification'],
            whyNotFraud: []
        },
        linkIntelligence: {
            url: 'bit.ly/claims-prize-now',
            domain: 'scam-site-hosting.net',
            domainAge: '5 days',
            hasSsl: true,
            redirectCount: 2,
            isMasked: true,
            reputation: 'SUSPICIOUS'
        },
        googlePresence: {
            found: false
        },
        recommendedActions: ['Ignore the message', 'Do not provide payment info'],
        timeline: [
            { id: 't1', name: 'Text Analysis', status: 'COMPLETED', timestamp: new Date().toISOString() },
            { id: 't2', name: 'Link Expansion', status: 'COMPLETED', details: 'Unshortened', timestamp: new Date().toISOString() },
            { id: 't3', name: 'Threat Intelligence', status: 'FLAGGED', timestamp: new Date().toISOString() },
            { id: 't4', name: 'Final Verdict', status: 'COMPLETED', timestamp: new Date().toISOString() }
        ]
    }
};

export const analyzeContent = async (text: string): Promise<FraudResult> => {
    return new Promise((resolve) => {
        setTimeout(() => {
            // Simple keyword matching for demo purposes
            const lower = text.toLowerCase();
            if (lower.includes('ups') || lower.includes('shipped') || lower.includes('safe')) {
                resolve({ ...MOCK_SCENARIOS.SAFE, analyzedContent: text, timestamp: new Date().toISOString() });
            } else if (lower.includes('winner') || lower.includes('prize') || lower.includes('walmart')) {
                resolve({ ...MOCK_SCENARIOS.SCAM, analyzedContent: text, timestamp: new Date().toISOString() });
            } else {
                // Default to Phishing for other cases or empty
                resolve({ ...MOCK_SCENARIOS.PHISHING, analyzedContent: text, timestamp: new Date().toISOString() });
            }
        }, MOCK_DELAY);
    });
};
