"use client"

import React, { useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { useFraudStore } from '@/store/useFraudStore';
import { RiskMeter } from '@/components/results/RiskMeter';
import { TextHighlighter } from '@/components/results/TextHighlighter';
import { ArrowLeft, Loader2, Check, AlertOctagon, Info, Image as ImageIcon, Sparkles, Scan, Eye, Database, FileText, AlignLeft, ShieldCheck, XCircle, Landmark as LandmarkIcon, SpellCheck, Mail, Paperclip, AlertTriangle, Smartphone, Search } from 'lucide-react';
import Link from 'next/link';
import { motion } from 'framer-motion';

export default function ResultsPage() {
    const router = useRouter();
    const { result, isAnalyzing, inputText, image } = useFraudStore();

    useEffect(() => {
        if (!isAnalyzing && !result && !inputText && !image) {
            router.push('/analyze');
        }
    }, [isAnalyzing, result, inputText, image, router]);

    if (isAnalyzing) {
        return (
            <div className="flex flex-col items-center justify-center min-h-[60vh] text-center space-y-6">
                <Loader2 className="w-16 h-16 text-primary animate-spin" />
                <div>
                    <h2 className="text-2xl font-bold">Analyzing Content...</h2>
                    <p className="text-muted-foreground">Consulting Gemini 1.5 Flash (Multi-Modal) & verifying patterns.</p>
                </div>
            </div>
        );
    }

    if (!result) return null;

    // Stagger animation variants
    const container = {
        hidden: { opacity: 0 },
        show: {
            opacity: 1,
            transition: {
                staggerChildren: 0.1
            }
        }
    };

    const item = {
        hidden: { opacity: 0, y: 20 },
        show: { opacity: 1, y: 0 }
    };

    const isSafeImage = result.image_analysis?.is_safe_content;

    // Google Search Comparison Function
    const handleGoogleSearch = () => {
        // Extract key phrases from the text for better search results
        const searchText = inputText || '';
        const truncatedText = searchText.substring(0, 200); // Limit to 200 chars for URL
        const searchQuery = `is this fraud scam: ${truncatedText}`;
        const encodedQuery = encodeURIComponent(searchQuery);
        const googleSearchUrl = `https://www.google.com/search?q=${encodedQuery}`;
        window.open(googleSearchUrl, '_blank');
    };

    return (
        <motion.div
            variants={container}
            initial="hidden"
            animate="show"
            className="max-w-6xl mx-auto space-y-8 pb-12"
        >

            {/* Header */}
            <div className="flex items-center justify-between gap-4">
                <div className="flex items-center gap-4">
                    <Link href="/analyze" className="p-2 hover:bg-muted rounded-full transition-colors">
                        <ArrowLeft className="w-6 h-6" />
                    </Link>
                    <div>
                        <h1 className="text-3xl font-bold font-display">Analysis Verdict</h1>
                        <p className="text-muted-foreground text-sm">AI-Powered Assessment complete</p>
                    </div>
                </div>

                {/* Google Search Comparison Button */}
                {inputText && (
                    <button
                        onClick={handleGoogleSearch}
                        className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg font-medium text-sm transition-colors shadow-sm"
                        title="Search Google to verify if this is a known scam"
                    >
                        <Search className="w-4 h-4" />
                        <span className="hidden sm:inline">Compare with Google</span>
                        <span className="sm:hidden">Google</span>
                    </button>
                )}
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">

                {/* Left Column: Score & Summary */}
                <div className="lg:col-span-1 space-y-6">
                    <motion.div variants={item} className="flex flex-col items-center bg-card border border-border p-8 rounded-2xl shadow-sm text-center relative overflow-hidden">
                        <RiskMeter score={result.risk_score} level={result.risk_level as any} />
                        <h2 className={`text-2xl font-bold mt-6 ${(result.risk_level as string) === 'Critical' || (result.risk_level as string) === 'High' || (result.risk_level as string) === 'CRITICAL' || (result.risk_level as string) === 'HIGH' ? 'text-danger' :
                            (result.risk_level as string) === 'Suspicious' || (result.risk_level as string) === 'Gray' ? 'text-warning' :
                                'text-safe'
                            }`}>
                            {result.risk_level} Risk
                        </h2>

                        {/* Tone Badges */}
                        <div className="mt-4 flex flex-wrap gap-2 justify-center">
                            <span className={`px-3 py-1 rounded-full text-xs font-bold uppercase border ${result.tone === 'Urgent' ? 'bg-red-100 text-red-700 border-red-200' :
                                result.tone === 'Manipulative' ? 'bg-orange-100 text-orange-700 border-orange-200' :
                                    result.tone === 'AI-Like' ? 'bg-blue-100 text-blue-700 border-blue-200' :
                                        'bg-green-100 text-green-700 border-green-200'
                                }`}>
                                Tone: {result.tone}
                            </span>
                            {result.fraud_type.map((ft, i) => (
                                <span key={i} className="px-3 py-1 rounded-full bg-muted text-xs font-bold uppercase">{ft}</span>
                            ))}
                        </div>
                    </motion.div>

                    {/* Bank Verification Card */}
                    {result.bank_verification && result.bank_verification.detected_bank && (
                        <motion.div variants={item} className={`p-4 rounded-xl border-l-4 shadow-sm ${result.bank_verification.is_official_domain ? 'bg-green-50 border-green-500' : 'bg-red-50 border-red-500'
                            }`}>
                            <div className="flex items-center gap-3 mb-2">
                                {result.bank_verification.is_official_domain ? <ShieldCheck className="w-6 h-6 text-green-600" /> : <XCircle className="w-6 h-6 text-red-600" />}
                                <div>
                                    <h4 className={`font-bold text-sm ${result.bank_verification.is_official_domain ? 'text-green-800' : 'text-red-800'}`}>
                                        {result.bank_verification.is_official_domain ? "Official Bank Link" : "Fake Bank Link Detected"}
                                    </h4>
                                    <p className="text-xs opacity-75">{result.bank_verification.detected_bank}</p>
                                </div>
                            </div>
                            {!result.bank_verification.is_official_domain && (
                                <p className="text-xs text-red-700 font-medium">⚠️ {result.bank_verification.risk_reason}</p>
                            )}
                        </motion.div>
                    )}

                    <motion.div variants={item} className="bg-muted/30 p-4 rounded-xl border border-border space-y-3">
                        <h3 className="text-xs font-bold uppercase text-muted-foreground mb-2 flex items-center gap-2">
                            <Info className="w-4 h-4" /> Analyzed Content
                        </h3>

                        {/* Highlighted Text */}
                        {inputText && (
                            <div className="bg-background/50 p-3 rounded-lg border border-border/50">
                                <TextHighlighter text={inputText} riskyPhrases={result.risky_phrases} />
                            </div>
                        )}

                        {/* Image Preview & Safety Tag */}
                        {image && (
                            <div className="relative group">
                                <img src={image} alt="Analyzed" className="w-full rounded-lg border border-border object-cover max-h-48" />
                                {isSafeImage ? (
                                    <div className="absolute top-2 right-2 bg-green-500 text-white text-[10px] px-2 py-0.5 rounded-full flex items-center gap-1">
                                        <ShieldCheck className="w-3 h-3" />
                                        Verified Safe Image
                                    </div>
                                ) : (
                                    <div className="absolute top-2 right-2 bg-black/70 text-white text-[10px] px-2 py-0.5 rounded-full flex items-center gap-1">
                                        <Sparkles className="w-3 h-3 text-yellow-400" />
                                        Image Analyzed
                                    </div>
                                )}
                            </div>
                        )}

                        {/* Link Analysis Summary */}
                        {result.link_analysis && result.link_analysis.domain && (
                            <div className="mt-3 pt-3 border-t border-border">
                                <div className="flex justify-between items-start mb-2">
                                    <h4 className="font-bold text-sm">Link Intelligence</h4>
                                    <Link href="/results/link" className="text-xs text-primary hover:underline flex items-center gap-1">View Details <ArrowLeft className="w-3 h-3 rotate-180" /></Link>
                                </div>
                                <ul className="text-xs space-y-1">
                                    <li>Domain: <span className="font-mono bg-muted px-1 rounded">{result.link_analysis.domain}</span></li>
                                    <li>Google: <span className={
                                        result.link_analysis.google_presence === 'High' ? 'text-safe font-bold' : 'text-danger font-bold'
                                    }>{result.link_analysis.google_presence}</span></li>
                                </ul>
                            </div>
                        )}
                    </motion.div>
                </div>

                {/* Right Column: Reasoning & Fusion */}
                <div className="lg:col-span-2 space-y-6">

                    {/* Database Match Card */}
                    {result.similar_case_match && result.similar_case_match.similarity_score > 50 && (
                        <motion.div variants={item} className="bg-slate-900 text-white p-6 rounded-2xl shadow-lg border border-slate-700 relative overflow-hidden">
                            <div className="absolute top-0 right-0 p-4 opacity-10">
                                <Database className="w-24 h-24" />
                            </div>
                            <div className="flex items-start gap-4">
                                <div className="p-3 bg-blue-500/20 rounded-lg">
                                    <Database className="w-8 h-8 text-blue-400" />
                                </div>
                                <div>
                                    <div className="flex items-center gap-3 mb-1">
                                        <h3 className="text-lg font-bold">Fraud Database Match</h3>
                                        <span className="bg-blue-500 text-xs font-bold px-2 py-0.5 rounded-full">{result.similar_case_match.similarity_score}% MATCH</span>
                                    </div>
                                    <p className="text-slate-300 text-sm mb-2">This content matches a known fraud pattern in our database.</p>
                                    <div className="bg-slate-800/50 p-3 rounded-lg border border-slate-700">
                                        <div className="flex items-center gap-2 mb-1">
                                            <FileText className="w-3 h-3 text-slate-400" />
                                            <span className="text-xs font-mono text-blue-300">{result.similar_case_match.id}</span>
                                        </div>
                                        <p className="text-sm italic opacity-90">"{result.similar_case_match.description}"</p>
                                    </div>
                                </div>
                            </div>
                        </motion.div>
                    )}

                    {/* Email Intelligence Card (NEW) */}
                    {result.email_analysis && result.email_analysis.is_email && (
                        <motion.div variants={item} className="bg-card border-l-4 border-blue-500 p-6 rounded-2xl shadow-sm">
                            <h3 className="text-lg font-bold mb-4 flex items-center gap-2 text-blue-800 dark:text-blue-300">
                                <Mail className="w-5 h-5" />
                                Email Intelligence Check
                            </h3>
                            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                                <div className={`p-3 rounded-lg ${result.email_analysis.sender_domain_mismatch ? 'bg-red-50 text-red-800' : 'bg-green-50 text-green-800'}`}>
                                    <div className="font-bold text-sm">Sender Verification</div>
                                    <div className="text-xs mt-1">{result.email_analysis.sender_domain_mismatch ? "Mismatched Sender (Spoofing Detected)" : "Sender Domain Aligns"}</div>
                                </div>
                                <div className={`p-3 rounded-lg ${result.email_analysis.suspicious_subject ? 'bg-orange-50 text-orange-800' : 'bg-muted text-muted-foreground'}`}>
                                    <div className="font-bold text-sm">Subject Line</div>
                                    <div className="text-xs mt-1">{result.email_analysis.suspicious_subject ? "Urgency/Scam Pattern Detected" : "Normal Subject Line"}</div>
                                </div>
                            </div>
                            {result.email_analysis.attachment_risk !== "None" && (
                                <div className="mt-4 p-3 bg-red-50 border border-red-200 rounded-lg flex items-center gap-3">
                                    <Paperclip className="w-5 h-5 text-red-600" />
                                    <div>
                                        <div className="font-bold text-sm text-red-800">High Risk Attachment Detected</div>
                                        <div className="text-xs text-red-700">Avoid opening .exe, .scr, or .zip files from unknown sources.</div>
                                    </div>
                                </div>
                            )}
                            <div className="mt-4 text-xs font-mono text-muted-foreground bg-muted p-2 rounded">
                                HDR: {result.email_analysis.headers_analysis}
                            </div>
                        </motion.div>
                    )}

                    {/* Text Quality & Forensics Card */}
                    {result.text_error_analysis && (
                        <motion.div variants={item} className="bg-card border border-border p-6 rounded-2xl shadow-sm">
                            <h3 className="text-lg font-bold mb-4 flex items-center gap-2">
                                <SpellCheck className="w-5 h-5 text-primary" />
                                Text Forensics & Quality
                            </h3>
                            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                                <div className="p-3 bg-muted/30 rounded-lg">
                                    <div className="text-sm text-muted-foreground mb-1">Grammar Score</div>
                                    <div className={`text-2xl font-bold ${result.text_error_analysis.score > 80 ? 'text-safe' : 'text-danger'
                                        }`}>{result.text_error_analysis.score}/100</div>
                                    <div className="text-xs mt-1">Lower scores often indicate scam origins.</div>
                                </div>
                                <div className="p-3 bg-muted/30 rounded-lg">
                                    <div className="text-sm text-muted-foreground mb-1">Detected Typos</div>
                                    <div className="text-sm font-mono text-danger">
                                        {result.text_error_analysis.typos && result.text_error_analysis.typos.length > 0 ?
                                            result.text_error_analysis.typos.join(", ") : "None Detected"}
                                    </div>
                                </div>
                            </div>
                        </motion.div>
                    )}

                    {/* AI Reasoning */}
                    <motion.div variants={item} className="bg-card border border-border p-6 rounded-2xl shadow-sm">
                        <h3 className="text-lg font-bold mb-4 flex items-center gap-2">
                            <AlertOctagon className="w-5 h-5 text-primary" />
                            Why this decision?
                        </h3>
                        <p className="text-foreground leading-relaxed mb-6">
                            {result.explanation}
                        </p>

                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                            <div className="p-4 rounded-xl bg-green-50 dark:bg-green-900/10 border border-green-100 dark:border-green-900/30">
                                <h4 className="font-bold text-green-800 dark:text-green-300 text-sm mb-2 flex items-center gap-2">
                                    <Check className="w-4 h-4" /> What would make it SAFE?
                                </h4>
                                <ul className="text-xs space-y-1 text-green-700 dark:text-green-400">
                                    {result.counterfactual_safe_conditions?.length > 0 ? result.counterfactual_safe_conditions.map((item, i) => (
                                        <li key={i}>• {item}</li>
                                    )) : <li>No suggestions available.</li>}
                                </ul>
                            </div>
                            <div className="p-4 rounded-xl bg-red-50 dark:bg-red-900/10 border border-red-100 dark:border-red-900/30">
                                <h4 className="font-bold text-red-800 dark:text-red-300 text-sm mb-2 flex items-center gap-2">
                                    <AlertOctagon className="w-4 h-4" /> Why it is Risky
                                </h4>
                                <ul className="text-xs space-y-1 text-red-700 dark:text-red-400">
                                    {result.why_fraud?.length > 0 ? result.why_fraud.map((s, i) => (
                                        <li key={i}>• {s}</li>
                                    )) : <li>No specific risks listed.</li>}
                                </ul>
                            </div>
                        </div>

                        <div className="mt-6 pt-4 border-t border-border">
                            <p className="text-xs text-muted-foreground flex items-center gap-2">
                                <span className="font-bold">AI Consistency Check:</span>
                                {result.model_self_check?.confidence_calibration === 'High'
                                    ? <span className="text-safe flex items-center gap-1"><Check className="w-3 h-3" /> High Confidence</span>
                                    : <span className="text-warning flex items-center gap-1"><AlertOctagon className="w-3 h-3" /> {result.model_self_check?.confidence_calibration} Confidence</span>
                                }
                                <span className="text-muted-foreground/50">•</span>
                                <span>{result.model_self_check?.possible_misclassification_reason}</span>
                            </p>
                        </div>
                    </motion.div>


                    {/* Signal Detection Matrix (Advanced) */}
                    <motion.div variants={item} className="bg-card border border-border p-6 rounded-2xl shadow-sm">
                        <h3 className="text-lg font-bold mb-4 flex items-center justify-between">
                            <span>Signal Detection Matrix</span>
                            <span className="text-xs font-normal text-muted-foreground bg-muted px-2 py-1 rounded">Multi-Modal Fusion</span>
                        </h3>
                        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                            {result.detected_signals && Object.entries(result.detected_signals).map(([key, value]) => {
                                const signalConfig: Record<string, { icon: React.ReactNode, label: string, desc: string }> = {
                                    urgency: { icon: <AlertTriangle className="w-4 h-4 text-orange-500" />, label: "Urgency Tactics", desc: "Pressure to act fast" },
                                    impersonation: { icon: <ShieldCheck className="w-4 h-4 text-blue-500" />, label: "Impersonation", desc: "Pretending to be authority" },
                                    otp_request: { icon: <Smartphone className="w-4 h-4 text-purple-500" />, label: "OTP Request", desc: "Asking for sensitive codes" },
                                    suspicious_url: { icon: <Paperclip className="w-4 h-4 text-red-500" />, label: "Suspicious Link", desc: "Embeds risky URLs" },
                                    ai_generated_tone: { icon: <Sparkles className="w-4 h-4 text-indigo-500" />, label: "AI-Generated", desc: "Synthetic text patterns" },
                                    image_text_mismatch: { icon: <AlignLeft className="w-4 h-4 text-yellow-500" />, label: "Image/Text Mismatch", desc: "Inconsistent content" },
                                    fake_branding: { icon: <Scan className="w-4 h-4 text-pink-500" />, label: "Fake Branding", desc: "Unofficial logos detected" },
                                    visual_artifacts: { icon: <Eye className="w-4 h-4 text-cyan-500" />, label: "Visual Artifacts", desc: "Edited/Manipulated pixels" }
                                };

                                const config = signalConfig[key] || { icon: <Info className="w-4 h-4" />, label: key.replace(/_/g, ' '), desc: "Signal detected" };

                                return (
                                    <div key={key} className={`flex items-start gap-3 p-3 rounded-xl border transition-all ${value
                                        ? 'bg-red-50/50 border-red-200 dark:bg-red-900/10 dark:border-red-900/30'
                                        : 'bg-muted/20 border-border opacity-60 hover:opacity-100'
                                        }`}>
                                        <div className={`mt-0.5 p-1.5 rounded-full ${value ? 'bg-white shadow-sm dark:bg-slate-800' : 'bg-transparent'}`}>
                                            {config.icon}
                                        </div>
                                        <div className="flex-1">
                                            <div className="flex justify-between items-center mb-0.5">
                                                <h4 className={`text-sm font-bold ${value ? 'text-red-900 dark:text-red-300' : 'text-foreground'}`}>
                                                    {config.label}
                                                </h4>
                                                {value && (
                                                    <span className="text-[10px] font-bold px-1.5 py-0.5 bg-red-100 text-red-600 rounded uppercase tracking-wide">
                                                        Detected
                                                    </span>
                                                )}
                                            </div>
                                            <p className="text-xs text-muted-foreground leading-tight">
                                                {config.desc}
                                            </p>
                                        </div>
                                    </div>
                                );
                            })}
                        </div>
                    </motion.div>

                </div>
            </div>
        </motion.div>
    );
}
