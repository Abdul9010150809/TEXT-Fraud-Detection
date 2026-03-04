"use client"

import React, { useState } from 'react';
import { useRouter } from 'next/navigation';
import { useFraudStore } from '@/store/useFraudStore';
import { analyzeContent } from '@/lib/gemini';
import { ScanLine, Shield } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Textarea } from '@/components/ui/textarea';
import { Card } from '@/components/ui/card';
import { motion, AnimatePresence } from 'framer-motion';

export default function AnalyzePage() {
    const router = useRouter();
    const {
        inputText, setInputText,
        setIsAnalyzing, setResult,
        demoMode
    } = useFraudStore();

    const [isLoading, setIsLoading] = useState(false);

    const handleAnalyze = async () => {
        if (!inputText) return;

        setIsLoading(true);
        setIsAnalyzing(true);
        setResult(null);

        try {
            const data = await analyzeContent(inputText, demoMode);
            // Artificial delay for the "Scan" effect to be visible
            setTimeout(() => {
                setResult(data);
                router.push('/results');
                setIsLoading(false);
                setIsAnalyzing(false);
            }, 2000);
        } catch (e) {
            console.error(e);
            setIsLoading(false);
            setIsAnalyzing(false);
        }
    };

    return (
        <div className="max-w-4xl mx-auto space-y-8 animate-in fade-in slide-in-from-bottom-4 duration-500 relative">

            <div className="text-center space-y-2">
                <div className="inline-flex items-center justify-center p-3 bg-primary/10 rounded-full mb-4">
                    <Shield className="w-8 h-8 text-primary" />
                </div>
                <h1 className="text-4xl font-bold font-display tracking-tight">Fraud Analysis Engine</h1>
                <p className="text-muted-foreground text-lg">Paste text or upload a screenshot to detect fraud instantly.</p>
            </div>

            <div className="grid gap-6 relative">

                {/* Scanner Overlay */}
                <AnimatePresence>
                    {isLoading && (
                        <motion.div
                            initial={{ opacity: 0 }}
                            animate={{ opacity: 1 }}
                            exit={{ opacity: 0 }}
                            className="absolute inset-0 z-50 bg-background/80 backdrop-blur-sm rounded-xl flex flex-col items-center justify-center border-2 border-primary/50 overflow-hidden"
                        >
                            <motion.div
                                className="w-full h-1 bg-primary shadow-[0_0_20px_rgba(37,99,235,0.8)] absolute"
                                animate={{ top: ["0%", "100%", "0%"] }}
                                transition={{ duration: 2, repeat: Infinity, ease: "linear" }}
                            />
                            <div className="relative z-10 bg-background p-6 rounded-2xl border border-primary text-center shadow-2xl">
                                <ScanLine className="w-12 h-12 text-primary mx-auto mb-4 animate-pulse" />
                                <h3 className="text-xl font-bold">Scanning Content...</h3>
                                <p className="text-muted-foreground text-sm mt-1">Analyzing Patterns • Verifying Links • Checking Forensics</p>
                            </div>
                        </motion.div>
                    )}
                </AnimatePresence>

                {/* Text Input */}
                <Card className="p-4 border-2 focus-within:border-primary/50 transition-colors bg-card/50">
                    <Textarea
                        placeholder="Paste suspicious message or link here..."
                        className="min-h-[150px] text-lg resize-none border-none focus-visible:ring-0 p-0 shadow-none bg-transparent"
                        value={inputText}
                        onChange={(e) => setInputText(e.target.value)}
                    />
                </Card>

                <Button
                    size="lg"
                    className="w-full text-lg h-14 bg-gradient-to-r from-primary to-blue-600 hover:opacity-90 transition-opacity shadow-lg"
                    onClick={handleAnalyze}
                    disabled={!inputText || isLoading}
                >
                    {isLoading ? "Processing..." : "Analyze Suspicious Item"}
                </Button>

            </div>
        </div>
    );
}
