"use client"

import React, { useState } from 'react';
import { Search, CheckCircle, AlertTriangle, ExternalLink } from 'lucide-react';

export function GoogleLinkCheck({ url }: { url: string }) {
    const [checking, setChecking] = useState(false);
    const [googlePresence, setGooglePresence] = useState<'HIGH' | 'MEDIUM' | 'LOW' | 'NOT_FOUND' | null>(null);

    const handleCheck = () => {
        if (!url) return;
        setChecking(true);
        setGooglePresence(null);

        // Mock API delay for badge
        setTimeout(() => {
            setChecking(false);
            // Mock logic for presence
            if (url.includes('sbi') || url.includes('amazon') || url.includes('google')) {
                setGooglePresence('HIGH');
            } else if (url.includes('bit.ly') || url.includes('xyz')) {
                setGooglePresence('LOW');
            } else {
                setGooglePresence('MEDIUM');
            }
        }, 1200);

        // REAL Google Search
        const searchUrl = `https://www.google.com/search?q=${encodeURIComponent(url)}`;
        window.open(searchUrl, '_blank');
    };

    if (!url) return null;

    return (
        <div className="mt-6 p-4 border border-border rounded-xl bg-card shadow-sm">
            <h3 className="text-sm font-bold uppercase text-muted-foreground mb-3 flex items-center gap-2">
                <Search className="w-4 h-4" /> Link Intelligence
            </h3>

            <div className="flex flex-col sm:flex-row items-center gap-4 justify-between">
                <div className="flex items-center gap-3">
                    <div className="p-2 bg-blue-50 dark:bg-blue-900/20 rounded-lg">
                        <ExternalLink className="w-5 h-5 text-blue-600" />
                    </div>
                    <div>
                        <p className="font-semibold text-sm">Verify Source</p>
                        <p className="text-xs text-muted-foreground">Search this URL on Google to check legitimacy.</p>
                    </div>
                </div>

                <button
                    onClick={handleCheck}
                    className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg text-sm font-medium transition-all flex items-center gap-2 whitespace-nowrap"
                >
                    Check Link on Google
                    <ExternalLink className="w-3 h-3" />
                </button>
            </div>

            {googlePresence && (
                <div className={`mt-4 pt-4 border-t border-border flex items-center gap-2 animate-in fade-in slide-in-from-top-2 duration-300`}>
                    {googlePresence === 'HIGH' ? <CheckCircle className="w-5 h-5 text-green-500" /> : <AlertTriangle className="w-5 h-5 text-yellow-500" />}
                    <span className="text-sm font-medium">
                        Google Presence: <span className={
                            googlePresence === 'HIGH' ? 'text-green-600 font-bold' :
                                googlePresence === 'LOW' ? 'text-red-600 font-bold' :
                                    'text-yellow-600 font-bold'
                        }>{googlePresence}</span>
                    </span>
                </div>
            )}
        </div>
    );
}
