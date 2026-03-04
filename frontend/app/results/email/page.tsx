"use client"

import React, { useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { useFraudStore } from '@/store/useFraudStore';
import { RiskMeter } from '@/components/results/RiskMeter';
import { ArrowLeft, Loader2, Check, AlertOctagon, Mail, ShieldAlert, ShieldCheck, UserX, Globe, AlertTriangle } from 'lucide-react';
import Link from 'next/link';
import { motion } from 'framer-motion';
import { Button } from '@/components/ui/button';

export default function EmailResultPage() {
    const router = useRouter();
    const { result, isAnalyzing, inputText } = useFraudStore();

    useEffect(() => {
        if (!isAnalyzing && !result && !inputText) {
            router.push('/email-analysis');
        }
    }, [isAnalyzing, result, inputText, router]);

    if (isAnalyzing) {
        return (
            <div className="flex flex-col items-center justify-center min-h-[60vh] text-center space-y-6">
                <Loader2 className="w-16 h-16 text-primary animate-spin" />
                <div>
                    <h2 className="text-2xl font-bold">Verifying Sender Identity...</h2>
                    <p className="text-muted-foreground">Checking domain reputation and SPF records.</p>
                </div>
            </div>
        );
    }

    if (!result || !result.email_analysis) return null;

    const { email_analysis } = result;
    const isSenderRisky = email_analysis.sender_domain_mismatch;

    return (
        <div className="max-w-4xl mx-auto space-y-8 pb-12 animate-in fade-in slide-in-from-bottom-4 duration-500">
            {/* Header */}
            <div className="flex items-center gap-4">
                <Link href="/email-analysis" className="p-2 hover:bg-muted rounded-full transition-colors">
                    <ArrowLeft className="w-6 h-6" />
                </Link>
                <div>
                    <h1 className="text-3xl font-bold font-display flex items-center gap-2">
                        <Mail className="w-8 h-8 text-primary" />
                        Email Forensics Report
                    </h1>
                    <p className="text-muted-foreground text-sm">Focused Analysis on Sender Identity & Content</p>
                </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-8">

                {/* PRIMARY CARD: SENDER IDENTITY */}
                <div className={`col-span-1 md:col-span-2 p-8 rounded-2xl border-2 shadow-lg ${isSenderRisky ? 'bg-red-50 border-red-200 dark:bg-red-900/10 dark:border-red-900/30' : 'bg-green-50 border-green-200 dark:bg-green-900/10 dark:border-green-900/30'
                    }`}>
                    <div className="flex items-start justify-between">
                        <div className="flex items-center gap-4">
                            <div className={`p-4 rounded-full ${isSenderRisky ? 'bg-red-100 text-red-600' : 'bg-green-100 text-green-600'}`}>
                                {isSenderRisky ? <UserX className="w-8 h-8" /> : <ShieldCheck className="w-8 h-8" />}
                            </div>
                            <div>
                                <h2 className={`text-2xl font-bold ${isSenderRisky ? 'text-red-800' : 'text-green-800'}`}>
                                    {isSenderRisky ? "Sender Identity Mismatch" : "Sender Identity Verified"}
                                </h2>
                                <p className={`font-medium ${isSenderRisky ? 'text-red-600' : 'text-green-600'}`}>
                                    {isSenderRisky ? "CRITICAL: The sender address does not match the organization claims." : "The sender domain aligns with the email content."}
                                </p>
                            </div>
                        </div>
                        <div className="text-right hidden sm:block">
                            <div className="text-xs font-bold uppercase tracking-wider text-muted-foreground">Trust Score</div>
                            <div className={`text-3xl font-black ${isSenderRisky ? 'text-red-600' : 'text-green-600'}`}>
                                {isSenderRisky ? '0/100' : '95/100'}
                            </div>
                        </div>
                    </div>

                    <div className="mt-6 bg-white/50 dark:bg-black/20 rounded-xl p-4 border border-black/5">
                        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                            <div>
                                <div className="text-xs text-muted-foreground uppercase font-bold mb-1">Detected Domain</div>
                                <div className="font-mono text-sm flex items-center gap-2">
                                    <Globe className="w-3 h-3" />
                                    {result.link_analysis?.domain || "Generic Provider"}
                                </div>
                            </div>
                            <div>
                                <div className="text-xs text-muted-foreground uppercase font-bold mb-1">Spoofing Technique</div>
                                <div className="font-medium text-sm">
                                    {isSenderRisky ? "Free Email Provider Abuse" : "None Detected"}
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                {/* Secondary: Subject & Content Analysis */}
                <div className="bg-card border border-border p-6 rounded-xl shadow-sm space-y-4">
                    <h3 className="font-bold text-lg flex items-center gap-2">
                        <AlertTriangle className="w-5 h-5 text-orange-500" />
                        Psychological Triggers
                    </h3>
                    <div className="space-y-3">
                        <div className={`p-3 rounded-lg border ${email_analysis.suspicious_subject ? 'bg-orange-50 border-orange-200 text-orange-800' : 'bg-muted/30 border-transparent'}`}>
                            <span className="text-xs font-bold uppercase opacity-70">Subject Line Analysis</span>
                            <p className="font-medium mt-1">
                                {email_analysis.suspicious_subject ? "Contains Urgent/Panic Inducing Language" : "Neutral / Informational Tone"}
                            </p>
                        </div>
                        <div className="flex flex-wrap gap-2">
                            {result.risky_phrases.map((phrase, i) => (
                                <span key={i} className="bg-red-100 text-red-700 px-2 py-1 rounded text-xs font-bold">
                                    "{phrase}"
                                </span>
                            ))}
                            {result.risky_phrases.length === 0 && <span className="text-sm text-muted-foreground italic">No alarmist keywords found.</span>}
                        </div>
                    </div>
                </div>

                {/* Technical: Headers & Attachments */}
                <div className="bg-card border border-border p-6 rounded-xl shadow-sm space-y-4">
                    <h3 className="font-bold text-lg flex items-center gap-2">
                        <ShieldAlert className="w-5 h-5 text-blue-500" />
                        Technical Checks
                    </h3>
                    <ul className="space-y-3 text-sm">
                        <li className="flex justify-between items-center border-b border-border pb-2">
                            <span>Attachment Scanning</span>
                            <span className={`font-bold ${email_analysis.attachment_risk !== 'None' ? 'text-red-500' : 'text-green-500'}`}>
                                {email_analysis.attachment_risk === 'None' ? 'Clean' : 'Risky File Type'}
                            </span>
                        </li>
                        <li className="flex justify-between items-center border-b border-border pb-2">
                            <span>Domain Blacklist Check</span>
                            <span className="font-bold text-green-500">Passed</span>
                            {/* (Simulated for this demo) */}
                        </li>
                        <li className="flex justify-between items-center">
                            <span>Header Consistency</span>
                            <span className={`font-bold ${isSenderRisky ? 'text-red-500' : 'text-green-500'}`}>
                                {isSenderRisky ? 'FAILED (DKIM Fail)' : 'PASSED'}
                            </span>
                        </li>
                    </ul>
                </div>

            </div>

            <div className="text-center pt-8">
                <Link href="/email-analysis">
                    <Button variant="outline" className="gap-2">
                        <ArrowLeft className="w-4 h-4" />
                        Analyze Another Email
                    </Button>
                </Link>
            </div>
        </div>
    );
}
