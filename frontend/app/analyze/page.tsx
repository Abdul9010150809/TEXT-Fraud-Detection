"use client"

import React, { useState, useCallback } from 'react';
import { useRouter } from 'next/navigation';
import { useFraudStore } from '@/store/useFraudStore';
import { analyzeContent } from '@/lib/gemini';
import { useDropzone } from 'react-dropzone';
import { Upload, X, Loader2, Image as ImageIcon, ScanLine, Shield } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Textarea } from '@/components/ui/textarea';
import { Card } from '@/components/ui/card';
import { motion, AnimatePresence } from 'framer-motion';

export default function AnalyzePage() {
    const router = useRouter();
    const {
        inputText, setInputText,
        image, setImage,
        setIsAnalyzing, setResult,
        demoMode, isAnalyzing: globalIsAnalyzing
    } = useFraudStore();

    const [isLoading, setIsLoading] = useState(false);

    const onDrop = useCallback((acceptedFiles: File[]) => {
        const file = acceptedFiles[0];
        const reader = new FileReader();
        reader.onload = () => {
            setImage(reader.result as string);
        };
        reader.readAsDataURL(file);
    }, [setImage]);

    const { getRootProps, getInputProps, isDragActive } = useDropzone({
        onDrop,
        accept: { 'image/*': [] },
        maxFiles: 1
    });

    const handleAnalyze = async () => {
        if (!inputText && !image) return;

        setIsLoading(true);
        setIsAnalyzing(true);
        setResult(null);

        try {
            const data = await analyzeContent(inputText, image || undefined, demoMode);
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
                        placeholder="Paste suspicious message, email, or link here..."
                        className="min-h-[150px] text-lg resize-none border-none focus-visible:ring-0 p-0 shadow-none bg-transparent"
                        value={inputText}
                        onChange={(e) => setInputText(e.target.value)}
                    />
                </Card>

                {/* Image Upload Area */}
                <div {...getRootProps()} className={`
                    border-2 border-dashed rounded-xl p-8 text-center cursor-pointer transition-all relative overflow-hidden
                    ${isDragActive ? 'border-primary bg-primary/5' : 'border-muted hover:border-primary/50 hover:bg-muted/50'}
                    ${image ? 'bg-muted/30' : ''}
                `}>
                    <input {...getInputProps()} />
                    {image ? (
                        <div className="relative inline-block">
                            <img src={image} alt="Upload preview" className="h-48 rounded-lg shadow-md object-contain" />
                            <button
                                onClick={(e) => { e.stopPropagation(); setImage(null); }}
                                className="absolute -top-3 -right-3 bg-destructive text-white p-1 rounded-full shadow-sm hover:bg-destructive/90"
                            >
                                <X className="w-4 h-4" />
                            </button>
                        </div>
                    ) : (
                        <div className="flex flex-col items-center gap-2 text-muted-foreground">
                            <div className="p-4 bg-muted rounded-full">
                                <Upload className="w-6 h-6" />
                            </div>
                            <p className="font-medium">Drop screenshot here or click to upload</p>
                            <p className="text-xs opacity-70">Supports JPG, PNG (Max 5MB)</p>
                        </div>
                    )}
                </div>

                {/* Actions */}
                <Button
                    size="lg"
                    className="w-full text-lg h-14 bg-gradient-to-r from-primary to-blue-600 hover:opacity-90 transition-opacity shadow-lg"
                    onClick={handleAnalyze}
                    disabled={(!inputText && !image) || isLoading}
                >
                    {isLoading ? "Processing..." : "Analyze Suspicious Item"}
                </Button>

            </div>
        </div>
    );
}
