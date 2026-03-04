'use client';

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Check, X, ArrowRight } from "lucide-react";

export default function ComparePage() {
    return (
        <div className="space-y-8 animate-slide-up">
            <div className="text-center">
                <h1 className="text-3xl font-bold">Analysis Comparison</h1>
                <p className="text-muted-foreground">side-by-side analysis of a fraudulent vs legitimate message structure</p>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                {/* SAFE VERSION */}
                <Card className="border-safe-200 bg-safe-50/30">
                    <CardHeader>
                        <CardTitle className="flex justify-between items-center text-safe-700">
                            Legitimate Notification
                            <span className="px-3 py-1 bg-safe-100 text-safe-700 text-xs rounded-full border border-safe-200">SAFE (Risk: 5/100)</span>
                        </CardTitle>
                    </CardHeader>
                    <CardContent className="space-y-4">
                        <div className="bg-white p-4 rounded border text-sm font-mono text-gray-700">
                            Hi John, your order <span className="text-safe-600 font-bold">#12345</span> has been shipped via <span className="text-safe-600 font-bold">UPS</span>. Track it here: <span className="bg-safe-100 px-1 rounded">https://ups.com/track/12345</span>
                        </div>

                        <div className="space-y-2">
                            <h4 className="font-semibold text-sm uppercase text-safe-600">Key Trust Signals</h4>
                            <ul className="space-y-1">
                                <li className="flex items-center gap-2 text-sm"><Check className="w-4 h-4 text-safe-500" /> Domain matches entity (ups.com)</li>
                                <li className="flex items-center gap-2 text-sm"><Check className="w-4 h-4 text-safe-500" /> Valid SSL Certificate (DigiCert)</li>
                                <li className="flex items-center gap-2 text-sm"><Check className="w-4 h-4 text-safe-500" /> No urgency or pressure tactics</li>
                                <li className="flex items-center gap-2 text-sm"><Check className="w-4 h-4 text-safe-500" /> Standard transactional format</li>
                            </ul>
                        </div>
                    </CardContent>
                </Card>

                {/* FRAUD VERSION */}
                <Card className="border-fraud-200 bg-fraud-50/30">
                    <CardHeader>
                        <CardTitle className="flex justify-between items-center text-fraud-700">
                            Phishing Attempt
                            <span className="px-3 py-1 bg-fraud-100 text-fraud-700 text-xs rounded-full border border-fraud-200">CRITICAL (Risk: 92/100)</span>
                        </CardTitle>
                    </CardHeader>
                    <CardContent className="space-y-4">
                        <div className="bg-white p-4 rounded border text-sm font-mono text-gray-700">
                            <span className="text-fraud-600 font-bold bg-fraud-100">URGENT:</span> Your <span className="text-fraud-600 font-bold">Account</span> has been <span className="text-fraud-600 font-bold">LOCKED</span>. Verify now: <span className="bg-fraud-100 px-1 rounded ring-2 ring-fraud-200">http://ups-delivery-check.com/login</span>
                        </div>

                        <div className="space-y-2">
                            <h4 className="font-semibold text-sm uppercase text-fraud-600">Detected Threats</h4>
                            <ul className="space-y-1">
                                <li className="flex items-center gap-2 text-sm"><X className="w-4 h-4 text-fraud-500" /> Typosquatting (ups-delivery-check.com)</li>
                                <li className="flex items-center gap-2 text-sm"><X className="w-4 h-4 text-fraud-500" /> High Urgency/Fear language</li>
                                <li className="flex items-center gap-2 text-sm"><X className="w-4 h-4 text-fraud-500" /> Domain registered &lt; 24h ago</li>
                                <li className="flex items-center gap-2 text-sm"><X className="w-4 h-4 text-fraud-500" /> Insecure Protocol (HTTP)</li>
                            </ul>
                        </div>
                    </CardContent>
                </Card>
            </div>

            <div className="flex justify-center pt-8">
                <div className="bg-secondary/50 p-6 rounded-xl flex items-center gap-4 max-w-2xl">
                    <div className="text-3xl font-bold text-primary">98.5%</div>
                    <div className="text-sm text-muted-foreground">
                        <strong className="text-foreground block text-lg">Similarity Match in Structure</strong>
                        Despite looking similar, our AI detects subtle behavioral and technical differences that traditional filters miss.
                    </div>
                </div>
            </div>
        </div>
    );
}
