"use client"

import { RiskMeter } from '@/components/results/RiskMeter';
import { ArrowLeftRight, CheckCircle, AlertTriangle } from 'lucide-react';

export default function ComparePage() {
    return (
        <div className="max-w-6xl mx-auto space-y-8 animate-in fade-in duration-500">

            <div className="text-center space-y-2 mb-8">
                <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-muted text-muted-foreground text-xs font-semibold uppercase tracking-wider mb-2">
                    <ArrowLeftRight className="w-4 h-4" />
                    Live Comparison
                </div>
                <h1 className="text-3xl font-bold font-display">Fraud vs. Normal Patterns</h1>
                <p className="text-muted-foreground max-w-2xl mx-auto">
                    See how our AI distinguishes between legitimate urgency and manipulative scam tactics using the exact same context (e.g., Bank Alert).
                </p>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-8 relative">

                {/* VS Badge */}
                <div className="hidden md:flex absolute left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2 w-12 h-12 bg-background border border-border rounded-full items-center justify-center font-black z-10 shadow-lg">
                    VS
                </div>

                {/* Normal Column */}
                <div className="bg-card border border-border rounded-2xl p-6 shadow-sm flex flex-col gap-6 relative overflow-hidden">
                    <div className="absolute top-0 left-0 w-full h-1 bg-safe" />

                    <div className="flex items-center justify-between">
                        <span className="text-sm font-bold uppercase text-safe flex items-center gap-2">
                            <CheckCircle className="w-4 h-4" /> Normal Message
                        </span>
                        <span className="text-xs text-muted-foreground">Context: Bank Alert</span>
                    </div>

                    <div className="p-4 bg-muted/40 rounded-xl border border-border font-mono text-sm leading-relaxed">
                        "Dear Customer, Rs 5,000 debited from acc **9012 on 29-01-26. Info: ATM WDL. If not done by you, call 1800-123-4567 - SBI"
                    </div>

                    <div className="flex-1 border-t border-border pt-6">
                        <h4 className="font-semibold mb-3 text-sm">AI Analysis</h4>
                        <ul className="space-y-2 text-sm text-muted-foreground">
                            <li className="flex items-start gap-2">
                                <span className="text-safe">✔</span>
                                Official Sender ID format verified.
                            </li>
                            <li className="flex items-start gap-2">
                                <span className="text-safe">✔</span>
                                No suspicious link (direct phone number).
                            </li>
                            <li className="flex items-start gap-2">
                                <span className="text-safe">✔</span>
                                Factual tone, no "immediate panic" induction.
                            </li>
                        </ul>
                    </div>

                    <div className="flex justify-center p-4">
                        <RiskMeter score={5} level="LOW" />
                    </div>
                </div>

                {/* Fraud Column */}
                <div className="bg-card border border-border rounded-2xl p-6 shadow-sm flex flex-col gap-6 relative overflow-hidden">
                    <div className="absolute top-0 left-0 w-full h-1 bg-danger" />

                    <div className="flex items-center justify-between">
                        <span className="text-sm font-bold uppercase text-danger flex items-center gap-2">
                            <AlertTriangle className="w-4 h-4" /> Fraud Message
                        </span>
                        <span className="text-xs text-muted-foreground">Context: Bank Scam</span>
                    </div>

                    <div className="p-4 bg-red-50 dark:bg-red-900/10 rounded-xl border border-red-100 dark:border-red-900/30 font-mono text-sm leading-relaxed text-red-900 dark:text-red-100">
                        "Urgent: Your SBI acc will be BLOCKED today due to KYC issue. Click immediately to update: http://sbi-secure-update.xyz"
                    </div>

                    <div className="flex-1 border-t border-border pt-6">
                        <h4 className="font-semibold mb-3 text-sm">AI Analysis</h4>
                        <ul className="space-y-2 text-sm text-muted-foreground">
                            <li className="flex items-start gap-2">
                                <span className="text-danger">✖</span>
                                <b>Urgency Trap:</b> "BLOCKED today", "immediately".
                            </li>
                            <li className="flex items-start gap-2">
                                <span className="text-danger">✖</span>
                                <b>Suspicious Link:</b> "sbi-secure-update.xyz" (Unofficial TLD).
                            </li>
                            <li className="flex items-start gap-2">
                                <span className="text-danger">✖</span>
                                <b>Panic Induction:</b> Threatens service loss.
                            </li>
                        </ul>
                    </div>

                    <div className="flex justify-center p-4">
                        <RiskMeter score={98} level="CRITICAL" />
                    </div>
                </div>

            </div>
        </div>
    );
}
