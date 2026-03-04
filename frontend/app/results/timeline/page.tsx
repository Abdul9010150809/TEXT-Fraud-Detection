"use client"

import { CheckCircle, ArrowDown, Brain, Link as LinkIcon, ShieldAlert, FileText, Search } from 'lucide-react';
import { useFraudStore } from '@/store/useFraudStore';
import Link from 'next/link';

export default function TimelinePage() {
    const { result } = useFraudStore();

    if (!result) {
        return (
            <div className="flex flex-col items-center justify-center min-h-[50vh] text-center space-y-4">
                <h2 className="text-xl font-bold">No Analysis Data</h2>
                <Link href="/analyze" className="text-primary hover:underline">Start a new analysis to see the timeline.</Link>
            </div>
        );
    }

    const steps = [
        {
            title: "Input Processing",
            icon: <FileText className="w-5 h-5 text-blue-500" />,
            desc: "Text content and metadata extracted.",
            status: "Complete"
        },
        {
            title: "Link Discovery",
            icon: <LinkIcon className="w-5 h-5 text-purple-500" />,
            desc: "URLs identified and checked against blocklists.",
            status: "Complete"
        },
        {
            title: "Pattern Recognition",
            icon: <Search className="w-5 h-5 text-orange-500" />,
            desc: "Tone analysis (Urgency, Manipulation) performed.",
            status: "Complete"
        },
        {
            title: "Gemini Reasoning",
            icon: <Brain className="w-5 h-5 text-green-500" />,
            desc: "LLM contextual understanding and classification.",
            status: "Complete"
        },
        {
            title: "Risk Calculation",
            icon: <ShieldAlert className="w-5 h-5 text-red-500" />,
            desc: `Final verdict: ${result.risk_level} Risk.`,
            status: "Finalized"
        }
    ];

    return (
        <div className="max-w-2xl mx-auto space-y-8 animate-in fade-in duration-500">
            <div className="text-center mb-8">
                <h1 className="text-3xl font-bold font-display">Detection Timeline</h1>
                <p className="text-muted-foreground">Trace the AI's decision-making process step-by-step.</p>
            </div>

            <div className="relative">
                {/* Connector Line */}
                <div className="absolute left-6 top-4 bottom-4 w-0.5 bg-border" />

                <div className="space-y-8">
                    {steps.map((step, idx) => (
                        <div key={idx} className="relative flex gap-6 items-start group">
                            {/* Step Icon Bubble */}
                            <div className="relative z-10 w-12 h-12 rounded-full border border-border bg-background flex items-center justify-center shadow-sm group-hover:scale-110 transition-transform">
                                {step.icon}
                                <div className="absolute -bottom-1 -right-1 bg-green-500 text-white rounded-full p-0.5 border-2 border-background">
                                    <CheckCircle className="w-3 h-3" />
                                </div>
                            </div>

                            {/* Step Content */}
                            <div className="flex-1 bg-card border border-border p-4 rounded-xl shadow-sm hover:shadow-md transition-shadow">
                                <div className="flex justify-between items-start mb-1">
                                    <h3 className="font-bold">{step.title}</h3>
                                    <span className="text-xs font-mono px-2 py-0.5 bg-muted rounded">{step.status}</span>
                                </div>
                                <p className="text-sm text-muted-foreground">{step.desc}</p>
                            </div>
                        </div>
                    ))}
                </div>
            </div>
        </div>
    );
}
