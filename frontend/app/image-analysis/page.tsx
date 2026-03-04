"use client"

import React, { useState, useCallback } from 'react';
import { useRouter } from 'next/navigation';
import { useFraudStore } from '@/store/useFraudStore';
import { analyzeContent } from '@/lib/gemini';
import { useDropzone } from 'react-dropzone';
import { Image as ImageIcon, Scan, Loader2, ArrowLeft, Upload, X, Eye } from 'lucide-react';
import { Button } from '@/components/ui/button';
import Link from 'next/link';

export default function ImageAnalysisPage() {
    const router = useRouter();
    const { image, setImage, setIsAnalyzing, setResult, setInputText } = useFraudStore();
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
        if (!image) return;

        setIsLoading(true);
        setIsAnalyzing(true);
        setInputText(""); // Clear text, focus on image

        try {
            const data = await analyzeContent("", image); // Empty text forces Image-First analysis
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
        <div className="max-w-3xl mx-auto space-y-6 animate-in fade-in duration-500 pb-12">
            <div className="flex items-center gap-4 mb-6">
                <Link href="/" className="p-2 hover:bg-muted rounded-full">
                    <ArrowLeft className="w-6 h-6" />
                </Link>
                <div>
                    <h1 className="text-3xl font-bold font-display flex items-center gap-2">
                        <ImageIcon className="w-8 h-8 text-primary" />
                        Visual Forensics Lab
                    </h1>
                    <p className="text-muted-foreground">Detect manipulated screenshots, fake logos, and edited receipts.</p>
                </div>
            </div>

            <div {...getRootProps()} className={`
                min-h-[400px] border-2 border-dashed rounded-xl flex flex-col items-center justify-center text-center cursor-pointer transition-all relative overflow-hidden bg-card
                ${isDragActive ? 'border-primary bg-primary/5' : 'border-muted hover:border-primary/50'}
            `}>
                <input {...getInputProps()} />

                {image ? (
                    <div className="relative w-full h-full p-4 flex items-center justify-center group">
                        <img src={image} alt="Forensics Target" className="max-h-[350px] object-contain rounded-lg shadow-lg" />
                        <button
                            onClick={(e) => { e.stopPropagation(); setImage(null); }}
                            className="absolute top-4 right-4 bg-destructive text-white p-2 rounded-full shadow-md hover:bg-destructive/90 transition-opacity"
                        >
                            <X className="w-5 h-5" />
                        </button>
                    </div>
                ) : (
                    <div className="space-y-4 p-8">
                        <div className="w-20 h-20 bg-muted rounded-full flex items-center justify-center mx-auto">
                            <Upload className="w-10 h-10 text-muted-foreground" />
                        </div>
                        <div>
                            <h3 className="text-xl font-bold">Drop Screenshot Evidence</h3>
                            <p className="text-muted-foreground mt-2">Supports WhatsApp Chats, Payment Receipts, KYC Documents</p>
                        </div>
                    </div>
                )}
            </div>

            <div className="flex flex-col sm:flex-row gap-4">
                <Button
                    size="lg"
                    className="flex-1 h-14 text-lg gap-2"
                    onClick={handleAnalyze}
                    disabled={!image || isLoading}
                >
                    {isLoading ? <Loader2 className="w-5 h-5 animate-spin" /> : <Scan className="w-5 h-5" />}
                    {isLoading ? "Running Forensics..." : "Run Visual Analysis"}
                </Button>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mt-8">
                <div className="p-4 rounded-lg bg-red-50 dark:bg-red-900/10 border border-red-100 dark:border-red-900/30">
                    <div className="font-bold text-red-800 dark:text-red-300 text-sm mb-1">Pixel Manipulation</div>
                    <div className="text-xs opacity-80">Detects traces of Photoshop or editing tools.</div>
                </div>
                <div className="p-4 rounded-lg bg-orange-50 dark:bg-orange-900/10 border border-orange-100 dark:border-orange-900/30">
                    <div className="font-bold text-orange-800 dark:text-orange-300 text-sm mb-1">Font Mismatches</div>
                    <div className="text-xs opacity-80">Identifies unnatural text insertion in existing docs.</div>
                </div>
                <div className="p-4 rounded-lg bg-blue-50 dark:bg-blue-900/10 border border-blue-100 dark:border-blue-900/30">
                    <div className="font-bold text-blue-800 dark:text-blue-300 text-sm mb-1">Fake Branding</div>
                    <div className="text-xs opacity-80">Compares logos against official brand assets.</div>
                </div>
            </div>
        </div>
    );
}
