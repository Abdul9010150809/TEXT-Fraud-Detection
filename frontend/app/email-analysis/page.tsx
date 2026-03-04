"use client"

import React, { useState } from 'react';
import { useRouter } from 'next/navigation';
import { useFraudStore } from '@/store/useFraudStore';
import { analyzeContent } from '@/lib/gemini';
import { Mail, Paperclip, Send, Loader2, ArrowLeft, Shield } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '../../components/ui/input';
import { Textarea } from '@/components/ui/textarea';
import Link from 'next/link';

export default function EmailAnalysisPage() {
    const router = useRouter();
    const { setIsAnalyzing, setResult, setInputText } = useFraudStore();
    const [isLoading, setIsLoading] = useState(false);

    // Email specific state
    const [sender, setSender] = useState('');
    const [subject, setSubject] = useState('');
    const [body, setBody] = useState('');

    const handleAnalyze = async () => {
        if (!body && !sender) return;

        setIsLoading(true);
        setIsAnalyzing(true);

        // Construct a composite "Email" string for the AI to analyze as a structured prompt
        const compositeText = `
        [EMAIL_HEADER_ANALYSIS_REQUEST]
        SENDER: ${sender}
        SUBJECT: ${subject}
        BODY:
        ${body}
        `;

        setInputText(compositeText); // Store for result display

        try {
            const data = await analyzeContent(compositeText);
            setTimeout(() => {
                setResult(data);
                router.push('/results/email');
                setIsLoading(false);
                setIsAnalyzing(false);
            }, 1000);
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
                        <Mail className="w-8 h-8 text-primary" />
                        Email Scam Verifier
                    </h1>
                    <p className="text-muted-foreground">Analyze headers, sender spoofing, and phishing intent.</p>
                </div>
            </div>

            <div className="bg-card border border-border rounded-xl p-6 shadow-sm space-y-4">
                <div className="space-y-2">
                    <label className="text-sm font-bold text-muted-foreground">Sender Address</label>
                    <div className="relative">
                        <Mail className="w-4 h-4 absolute left-3 top-3 text-muted-foreground" />
                        <Input
                            placeholder="e.g. support@paypal-service-alert.com"
                            className="pl-9"
                            value={sender}
                            onChange={(e: React.ChangeEvent<HTMLInputElement>) => setSender(e.target.value)}
                        />
                    </div>
                </div>

                <div className="space-y-2">
                    <label className="text-sm font-bold text-muted-foreground">Subject Line</label>
                    <div className="relative">
                        <Input
                            placeholder="e.g. URGENT: Account Suspended"
                            className="font-medium"
                            value={subject}
                            onChange={(e: React.ChangeEvent<HTMLInputElement>) => setSubject(e.target.value)}
                        />
                    </div>
                </div>

                <div className="space-y-2">
                    <label className="text-sm font-bold text-muted-foreground">Email Body</label>
                    <Textarea
                        placeholder="Paste the full email content here..."
                        className="min-h-[200px] resize-y"
                        value={body}
                        onChange={(e: React.ChangeEvent<HTMLTextAreaElement>) => setBody(e.target.value)}
                    />
                </div>

                <div className="pt-4 flex justify-end">
                    <Button
                        size="lg"
                        className="w-full md:w-auto gap-2"
                        onClick={handleAnalyze}
                        disabled={isLoading || (!sender && !body)}
                    >
                        {isLoading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Send className="w-4 h-4" />}
                        {isLoading ? "Verifying Headers..." : "Analyze Email"}
                    </Button>
                </div>
            </div>

            <div className="p-4 bg-muted/40 rounded-lg text-sm text-muted-foreground flex gap-3">
                <Shield className="w-10 h-10 text-green-600 flex-shrink-0" />
                <p>
                    <strong>Privacy Note:</strong> Emails are processed anonymously.
                    We check the sender domain against official records (SPF/DKIM logic simulation) and analyze the body for linguistic phishing patterns.
                </p>
            </div>
        </div>
    );
}
