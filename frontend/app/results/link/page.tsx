"use client"

import React, { useEffect, useState } from 'react';
import { useFraudStore } from '@/store/useFraudStore';
import { GoogleLinkCheck } from '@/components/analyze/GoogleLinkCheck';
import { Globe, Shield, Clock, AlertTriangle } from 'lucide-react';

export default function LinkIntelligencePage() {
    const { inputText, result } = useFraudStore();
    const [url, setUrl] = useState<string>('');

    useEffect(() => {
        const match = inputText.match(/(https?:\/\/[^\s]+)/g);
        if (match) setUrl(match[0]);
    }, [inputText]);

    if (!url) {
        return (
            <div className="flex flex-col items-center justify-center min-h-[50vh] text-center space-y-4">
                <Globe className="w-16 h-16 text-muted-foreground opacity-20" />
                <h2 className="text-xl font-bold">No Link Detected</h2>
                <p className="text-muted-foreground">Go back to Analyze and enter a message containing a URL.</p>
            </div>
        );
    }

    // Use store data if available, otherwise heuristics
    const analysisData = result?.link_analysis;

    const isSuspicious = analysisData
        ? (analysisData.google_presence === 'Low' || analysisData.google_presence === 'Not Found' || analysisData.brand_spoofing)
        : (url.includes('bit.ly') || url.includes('xyz') || url.includes('update'));

    const domain = analysisData?.domain || new URL(url).hostname;
    const googlePresence = analysisData?.google_presence || 'Not Found';
    const shortened = analysisData?.shortened || url.length < 25;

    return (
        <div className="max-w-3xl mx-auto space-y-8 animate-in fade-in duration-500">
            <div className="space-y-2">
                <h1 className="text-3xl font-bold font-display">Link Intelligence</h1>
                <p className="text-muted-foreground">Deep analysis of the detected URL: <span className="font-mono text-primary bg-muted px-2 py-0.5 rounded">{domain}</span></p>
            </div>

            <GoogleLinkCheck url={url} />

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div className="p-4 rounded-xl border border-border bg-card flex flex-col items-center text-center gap-2">
                    <Clock className={`w-8 h-8 ${shortened ? 'text-warning' : 'text-blue-500'}`} />
                    <span className="text-sm font-muted-foreground">URL Structure</span>
                    <span className="font-bold text-lg">{shortened ? "Shortened (Risky)" : "Standard"}</span>
                </div>
                <div className="p-4 rounded-xl border border-border bg-card flex flex-col items-center text-center gap-2">
                    <Shield className={`w-8 h-8 ${googlePresence === 'High' ? 'text-green-500' : 'text-red-500'}`} />
                    <span className="text-sm font-muted-foreground">Google Presence</span>
                    <span className="font-bold text-lg">{googlePresence}</span>
                </div>
                <div className="p-4 rounded-xl border border-border bg-card flex flex-col items-center text-center gap-2">
                    <AlertTriangle className={`w-8 h-8 ${isSuspicious ? 'text-warning' : 'text-muted-foreground'}`} />
                    <span className="text-sm font-muted-foreground">Spoofing Risk</span>
                    <span className="font-bold text-lg">{isSuspicious ? "High" : "None"}</span>
                </div>
            </div>

            <div className="bg-muted/30 p-6 rounded-xl border border-border">
                <h3 className="font-bold mb-2">Analysis Summary</h3>
                <p className="text-sm leading-relaxed">
                    The domain <b>{domain}</b> {isSuspicious ?
                        "has indicators of being unsafe. The Google Presence is low, or the URL structure attempts to mask the destination." :
                        "appears to be a legitimate entity with a recognized presence on Google. No immediate spoofing signals detected."}
                </p>
            </div>
        </div>
    );
}
