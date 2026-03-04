"use client"

import React from 'react';
import Link from 'next/link';
import { ArrowLeft, CheckCircle, ShieldCheck, Image as ImageIcon, MessageSquare } from 'lucide-react';

export default function FalsePositiveReviewPage() {
    return (
        <div className="max-w-4xl mx-auto space-y-8 animate-in fade-in duration-500 pb-12">
            <div className="flex items-center gap-4">
                <Link href="/" className="p-2 hover:bg-muted rounded-full">
                    <ArrowLeft className="w-6 h-6" />
                </Link>
                <div>
                    <h1 className="text-3xl font-bold font-display flex items-center gap-2">
                        <ShieldCheck className="w-8 h-8 text-green-500" />
                        AI Calibration Center
                    </h1>
                    <p className="text-muted-foreground">Why we trust our results. Examples of verified safe content.</p>
                </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">

                {/* Example 1: Human Photo */}
                <div className="bg-card border border-border rounded-xl overflow-hidden shadow-sm">
                    <div className="h-48 bg-muted flex items-center justify-center relative">
                        <ImageIcon className="w-12 h-12 text-muted-foreground/50" />
                        <div className="absolute inset-0 flex items-center justify-center text-muted-foreground/30 text-4xl font-bold rotate-[-15deg]">
                            GENERIC PHOTO
                        </div>
                    </div>
                    <div className="p-6">
                        <div className="flex items-center gap-2 mb-2">
                            <span className="px-2 py-1 bg-green-100 text-green-700 text-xs font-bold rounded-full border border-green-200">VERIFIED SAFE</span>
                            <span className="text-xs text-muted-foreground">Visual Analysis</span>
                        </div>
                        <h3 className="font-bold text-lg mb-2">Generic Human/Scenery Photos</h3>
                        <p className="text-sm text-muted-foreground">
                            Our AI detects when an image is a standard photograph without forensic anomalies (text overlays, mismatched fonts).
                            <br /><br />
                            <strong>Why it's Safe:</strong> "Zero OCR text detected. No compression artifacts typical of forwarded scam banners."
                        </p>
                    </div>
                </div>

                {/* Example 2: Normal Conversation */}
                <div className="bg-card border border-border rounded-xl overflow-hidden shadow-sm">
                    <div className="h-48 bg-muted flex items-center justify-center p-8">
                        <div className="bg-white dark:bg-slate-800 p-4 rounded-lg shadow-sm w-full">
                            <p className="text-sm text-center">"Hey mom, I'll be home late for dinner. Love you!"</p>
                        </div>
                    </div>
                    <div className="p-6">
                        <div className="flex items-center gap-2 mb-2">
                            <span className="px-2 py-1 bg-green-100 text-green-700 text-xs font-bold rounded-full border border-green-200">VERIFIED SAFE</span>
                            <span className="text-xs text-muted-foreground">Sentiment Analysis</span>
                        </div>
                        <h3 className="font-bold text-lg mb-2">Personal Conversations</h3>
                        <p className="text-sm text-muted-foreground">
                            The model distinguishes betweeen 'Urgency' (Scam) and 'Personal Updates'.
                            <br /><br />
                            <strong>Why it's Safe:</strong> "Sentiment is warm/neutral. No financial keywords. No external links."
                        </p>
                    </div>
                </div>

            </div>

            <div className="p-6 bg-blue-50 dark:bg-blue-900/20 rounded-xl border border-blue-100 dark:border-blue-900/50 text-center">
                <h3 className="font-bold text-blue-900 dark:text-blue-300 mb-2">Our Promise: Minimal False Positives</h3>
                <p className="text-sm text-blue-800 dark:text-blue-200">
                    We use a <strong>Hybrid Logic Engine</strong>. If the AI is unsure, it defaults to highlighting risks rather than blocking content,
                    ensuring you never miss a real message while staying protected from fraud.
                </p>
            </div>
        </div>
    );
}
