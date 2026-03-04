"use client"

import { AlertTriangle, CheckCircle, Brain } from 'lucide-react';

interface RiskExplainerProps {
    explanation: string;
    signals: string[];
    fraudType: string;
    level: string;
}

export function RiskExplainer({ explanation, signals, fraudType, level }: RiskExplainerProps) {
    return (
        <div className="space-y-6">
            <div className="p-4 rounded-xl bg-muted/30 border border-border">
                <h3 className="text-lg font-semibold flex items-center gap-2 mb-2">
                    <Brain className="w-5 h-5 text-primary" />
                    AI Analysis
                </h3>
                <p className="text-base text-foreground leading-relaxed">
                    {explanation}
                </p>
            </div>

            <div>
                <h4 className="text-sm font-semibold uppercase text-muted-foreground mb-3">Key Signals Detected</h4>
                <div className="space-y-2">
                    {signals.map((signal, idx) => (
                        <div key={idx} className="flex items-start gap-3 p-3 rounded-lg bg-background border border-border shadow-sm">
                            {level === 'LOW' ? (
                                <CheckCircle className="w-5 h-5 text-safe shrink-0 mt-0.5" />
                            ) : (
                                <AlertTriangle className="w-5 h-5 text-warning shrink-0 mt-0.5" />
                            )}
                            <span className="text-sm font-medium">{signal}</span>
                        </div>
                    ))}
                </div>
            </div>

            <div className="pt-4 border-t border-border">
                <h4 className="text-sm font-semibold uppercase text-muted-foreground mb-2">Detected Category</h4>
                <span className={`inline-flex items-center px-3 py-1 rounded-full text-sm font-bold border ${level === 'LOW' ? 'bg-green-100 border-green-200 text-green-800' :
                        'bg-red-100 border-red-200 text-red-800'
                    }`}>
                    {fraudType}
                </span>
            </div>
        </div>
    );
}
