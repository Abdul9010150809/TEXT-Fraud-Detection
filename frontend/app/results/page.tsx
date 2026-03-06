"use client";

import React, { useEffect } from "react";
import { useRouter } from "next/navigation";
import { useFraudStore } from "@/store/useFraudStore";
import { RiskMeter } from "@/components/results/RiskMeter";
import { TextHighlighter } from "@/components/results/TextHighlighter";
import {
  ArrowLeft,
  Loader2,
  Check,
  AlertOctagon,
  Info,
  Sparkles,
  Scan,
  Eye,
  Database,
  FileText,
  AlignLeft,
  ShieldCheck,
  XCircle,
  SpellCheck,
  Mail,
  Paperclip,
  AlertTriangle,
  Smartphone,
  Search,
  Bot,
  User,
} from "lucide-react";
import Link from "next/link";
import { motion } from "framer-motion";
import { saveComparePayload } from "@/lib/googleVerification";

export default function ResultsPage() {
  const router = useRouter();
  const { result, isAnalyzing, inputText } = useFraudStore();

  useEffect(() => {
    if (!isAnalyzing && !result && !inputText) {
      router.push("/analyze");
    }
  }, [isAnalyzing, result, inputText, router]);

  if (isAnalyzing) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[60vh] text-center space-y-6">
        <Loader2 className="w-16 h-16 text-primary animate-spin" />
        <div>
          <h2 className="text-2xl font-bold">Analyzing Content...</h2>
          <p className="text-muted-foreground">
            Consulting Gemini 1.5 Flash (Multi-Modal) & verifying patterns.
          </p>
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
        staggerChildren: 0.1,
      },
    },
  };

  const item = {
    hidden: { opacity: 0, y: 20 },
    show: { opacity: 1, y: 0 },
  };

  const handleGoogleCompare = () => {
    if (!inputText || !result) return;

    saveComparePayload({
      mode: "text",
      input: inputText,
      fraudguard: {
        isFraud: result.is_fraud,
        riskScore: result.risk_score,
        riskLevel: String(result.risk_level),
        messageType: result.message_type,
      },
      timestamp: Date.now(),
    });

    router.push("/analyze/compare?mode=text");
  };

  return (
    <motion.div
      variants={container}
      initial="hidden"
      animate="show"
      className="max-w-6xl mx-auto space-y-8 pb-12"
    >
      {/* Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 mb-8">
        <div className="flex items-center gap-4 w-full">
          <Link
            href="/analyze"
            className="p-2 hover:bg-muted/60 dark:hover:bg-muted/40 rounded-xl transition-colors border border-border/40 hover:border-primary/30"
          >
            <ArrowLeft className="w-6 h-6" />
          </Link>
          <div className="flex-1">
            <h1 className="text-4xl sm:text-5xl font-display font-bold gradient-text">
              Analysis Complete
            </h1>
            <p className="text-muted-foreground text-sm sm:text-base mt-1">
              Detailed AI-powered fraud assessment
            </p>
          </div>
        </div>

        {/* Google Search Comparison Button */}
        {inputText && (
          <button
            onClick={handleGoogleCompare}
            className="flex items-center gap-2 px-6 py-3 bg-gradient-to-r from-blue-600 to-blue-700 hover:from-blue-700 hover:to-blue-800 text-white rounded-xl font-semibold text-sm transition-all duration-300 shadow-md hover:shadow-lg whitespace-nowrap"
            title="Verify this content with Google and compare verdicts"
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
          <motion.div
            variants={item}
            className="card-hover bg-gradient-to-br from-card via-card to-card/50 border-2 border-primary/30 p-8 rounded-2xl text-center relative overflow-hidden group"
          >
            {/* Background Glow */}
            <div className="absolute inset-0 opacity-0 group-hover:opacity-100 transition-opacity duration-500 bg-gradient-to-br from-primary/5 to-secondary/5 pointer-events-none"></div>

            <div className="relative z-10">
              <RiskMeter
                score={result.risk_score}
                level={
                  result.risk_level as
                    | "Safe"
                    | "Suspicious"
                    | "High"
                    | "Critical"
                }
              />
              <h2
                className={`text-2xl font-display font-bold mt-6 ${
                  (result.risk_level as string) === "Critical" ||
                  (result.risk_level as string) === "High" ||
                  (result.risk_level as string) === "CRITICAL" ||
                  (result.risk_level as string) === "HIGH"
                    ? "text-danger"
                    : (result.risk_level as string) === "Suspicious" ||
                        (result.risk_level as string) === "Gray"
                      ? "text-warning"
                      : "text-safe"
                }`}
              >
                {result.risk_level} Risk
              </h2>

              {/* Message Type Badge - Prominent Display */}
              <div className="mt-6 mb-4">
                <span
                  className={`inline-flex items-center gap-2 px-6 py-3 rounded-full text-base font-bold uppercase border-2 transition-all shadow-md ${
                    result.message_type === "Friendly Message"
                      ? "bg-green-500/20 text-green-700 dark:text-green-400 border-green-500/50"
                      : result.message_type === "Safe Link"
                        ? "bg-blue-500/20 text-blue-700 dark:text-blue-400 border-blue-500/50"
                        : result.message_type === "Suspicious Link"
                          ? "bg-orange-600/20 text-orange-700 dark:text-orange-400 border-orange-600/50"
                          : result.message_type === "Spam/Marketing"
                            ? "bg-yellow-500/20 text-yellow-700 dark:text-yellow-400 border-yellow-500/50"
                            : result.message_type === "Suspicious"
                              ? "bg-orange-500/20 text-orange-700 dark:text-orange-400 border-orange-500/50"
                              : result.message_type === "Job Scam"
                                ? "bg-red-500/20 text-red-700 dark:text-red-400 border-red-500/50"
                                : result.message_type === "Phishing"
                                  ? "bg-red-600/20 text-red-700 dark:text-red-400 border-red-600/50"
                                  : result.message_type === "Financial Fraud"
                                    ? "bg-purple-600/20 text-purple-700 dark:text-purple-400 border-purple-600/50"
                                    : result.message_type ===
                                        "Blackmail/Extortion"
                                      ? "bg-red-700/20 text-red-800 dark:text-red-400 border-red-700/50"
                                      : result.message_type ===
                                          "Tech Support Scam"
                                        ? "bg-blue-600/20 text-blue-700 dark:text-blue-400 border-blue-600/50"
                                        : result.message_type === "UPI Fraud"
                                          ? "bg-red-800/20 text-red-900 dark:text-red-400 border-red-800/50"
                                          : result.message_type ===
                                              "Impersonation"
                                            ? "bg-indigo-600/20 text-indigo-700 dark:text-indigo-400 border-indigo-600/50"
                                            : "bg-slate-500/20 text-slate-700 dark:text-slate-400 border-slate-500/50"
                  }`}
                >
                  <Mail className="w-5 h-5" />
                  {result.message_type}
                </span>
              </div>

              {/* Tone Badges */}
              <div className="mt-6 flex flex-wrap gap-2 justify-center">
                <span
                  className={`px-4 py-2 rounded-full text-xs font-bold uppercase border transition-all ${
                    result.tone === "Urgent"
                      ? "bg-danger/10 text-danger border-danger/30"
                      : result.tone === "Manipulative"
                        ? "bg-warning/10 text-warning border-warning/30"
                        : result.tone === "AI-Like"
                          ? "bg-primary/10 text-primary border-primary/30"
                          : "bg-safe/10 text-safe border-safe/30"
                  }`}
                >
                  Tone: {result.tone}
                </span>
                {result.author_prediction && (
                  <span
                    className={`px-4 py-2 rounded-full text-xs font-bold uppercase border transition-all flex items-center gap-1 ${
                      result.author_prediction === "AI Generated"
                        ? "bg-purple-500/10 text-purple-600 border-purple-500/30 dark:text-purple-400"
                        : result.author_prediction === "Human Typed"
                          ? "bg-blue-500/10 text-blue-600 border-blue-500/30 dark:text-blue-400"
                          : "bg-slate-500/10 text-slate-600 border-slate-500/30 dark:text-slate-400"
                    }`}
                  >
                    {result.author_prediction === "AI Generated" ? (
                      <Bot className="w-3 h-3" />
                    ) : (
                      <User className="w-3 h-3" />
                    )}
                    {result.author_prediction}
                  </span>
                )}
                {result.fraud_type.map((ft, i) => (
                  <span
                    key={i}
                    className="px-4 py-2 rounded-full bg-muted/60 text-foreground text-xs font-bold uppercase border border-border/50 transition-all hover:border-primary/40"
                  >
                    {ft}
                  </span>
                ))}
              </div>
            </div>
          </motion.div>

          {/* Bank Verification Card */}
          {result.bank_verification &&
            result.bank_verification.detected_bank && (
              <motion.div
                variants={item}
                className={`p-6 rounded-2xl border-l-4 shadow-md transition-all ${
                  result.bank_verification.is_official_domain
                    ? "bg-gradient-to-br from-safe/10 to-safe/5 border-safe/60"
                    : "bg-gradient-to-br from-danger/10 to-danger/5 border-danger/60"
                }`}
              >
                <div className="flex items-center gap-3 mb-2">
                  {result.bank_verification.is_official_domain ? (
                    <ShieldCheck className="w-6 h-6 text-safe flex-shrink-0" />
                  ) : (
                    <XCircle className="w-6 h-6 text-danger flex-shrink-0" />
                  )}
                  <div className="flex-1">
                    <h4
                      className={`font-bold text-sm ${result.bank_verification.is_official_domain ? "text-safe" : "text-danger"}`}
                    >
                      {result.bank_verification.is_official_domain
                        ? "✓ Official Bank Link"
                        : "⚠️ Fake Bank Link Detected"}
                    </h4>
                    <p className="text-xs opacity-75 mt-1">
                      {result.bank_verification.detected_bank}
                    </p>
                  </div>
                </div>
                {!result.bank_verification.is_official_domain && (
                  <p className="text-xs font-medium mt-2 opacity-80">
                    Risk: {result.bank_verification.risk_reason}
                  </p>
                )}
              </motion.div>
            )}

          <motion.div
            variants={item}
            className="bg-muted/30 p-4 rounded-xl border border-border space-y-3"
          >
            <h3 className="text-xs font-bold uppercase text-muted-foreground mb-2 flex items-center gap-2">
              <Info className="w-4 h-4" /> Analyzed Content
            </h3>

            {/* Highlighted Text */}
            {inputText && (
              <div className="bg-background/50 p-3 rounded-lg border border-border/50">
                <TextHighlighter
                  text={inputText}
                  riskyPhrases={result.risky_phrases}
                />
              </div>
            )}

            {/* Link Analysis Summary */}
            {result.link_analysis && result.link_analysis.domain && (
              <div className="mt-3 pt-3 border-t border-border">
                <div className="flex justify-between items-start mb-2">
                  <h4 className="font-bold text-sm">Link Intelligence</h4>
                  <Link
                    href="/results/link"
                    className="text-xs text-primary hover:underline flex items-center gap-1"
                  >
                    View Details <ArrowLeft className="w-3 h-3 rotate-180" />
                  </Link>
                </div>
                <ul className="text-xs space-y-1">
                  <li>
                    Domain:{" "}
                    <span className="font-mono bg-muted px-1 rounded">
                      {result.link_analysis.domain}
                    </span>
                  </li>
                  <li>
                    Google:{" "}
                    <span
                      className={
                        result.link_analysis.google_presence === "High"
                          ? "text-safe font-bold"
                          : "text-danger font-bold"
                      }
                    >
                      {result.link_analysis.google_presence}
                    </span>
                  </li>
                </ul>
              </div>
            )}
          </motion.div>
        </div>

        {/* Right Column: Reasoning & Fusion */}
        <div className="lg:col-span-2 space-y-6">
          {/* Database Match Card */}
          {result.similar_case_match &&
            result.similar_case_match.similarity_score > 50 && (
              <motion.div
                variants={item}
                className="bg-slate-900 text-white p-6 rounded-2xl shadow-lg border border-slate-700 relative overflow-hidden"
              >
                <div className="absolute top-0 right-0 p-4 opacity-10">
                  <Database className="w-24 h-24" />
                </div>
                <div className="flex items-start gap-4">
                  <div className="p-3 bg-blue-500/20 rounded-lg">
                    <Database className="w-8 h-8 text-blue-400" />
                  </div>
                  <div>
                    <div className="flex items-center gap-3 mb-1">
                      <h3 className="text-lg font-bold">
                        Fraud Database Match
                      </h3>
                      <span className="bg-blue-500 text-xs font-bold px-2 py-0.5 rounded-full">
                        {result.similar_case_match.similarity_score}% MATCH
                      </span>
                    </div>
                    <p className="text-slate-300 text-sm mb-2">
                      This content matches a known fraud pattern in our
                      database.
                    </p>
                    <div className="bg-slate-800/50 p-3 rounded-lg border border-slate-700">
                      <div className="flex items-center gap-2 mb-1">
                        <FileText className="w-3 h-3 text-slate-400" />
                        <span className="text-xs font-mono text-blue-300">
                          {result.similar_case_match.id}
                        </span>
                      </div>
                      <p className="text-sm italic opacity-90">
                        &quot;{result.similar_case_match.description}&quot;
                      </p>
                    </div>
                  </div>
                </div>
              </motion.div>
            )}

          {/* Text Quality & Forensics Card */}
          {result.text_error_analysis && (
            <motion.div
              variants={item}
              className="bg-card border border-border p-6 rounded-2xl shadow-sm"
            >
              <h3 className="text-lg font-bold mb-4 flex items-center gap-2">
                <SpellCheck className="w-5 h-5 text-primary" />
                Text Forensics & Quality
              </h3>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="p-3 bg-muted/30 rounded-lg">
                  <div className="text-sm text-muted-foreground mb-1">
                    Grammar Score
                  </div>
                  <div
                    className={`text-2xl font-bold ${
                      result.text_error_analysis.score > 80
                        ? "text-safe"
                        : "text-danger"
                    }`}
                  >
                    {result.text_error_analysis.score}/100
                  </div>
                  <div className="text-xs mt-1">
                    Lower scores often indicate scam origins.
                  </div>
                </div>
                <div className="p-3 bg-muted/30 rounded-lg">
                  <div className="text-sm text-muted-foreground mb-1">
                    Detected Typos
                  </div>
                  <div className="text-sm font-mono text-danger">
                    {result.text_error_analysis.typos &&
                    result.text_error_analysis.typos.length > 0
                      ? result.text_error_analysis.typos.join(", ")
                      : "None Detected"}
                  </div>
                </div>
              </div>
            </motion.div>
          )}

          {/* AI Reasoning */}
          <motion.div
            variants={item}
            className="bg-card border border-border p-6 rounded-2xl shadow-sm"
          >
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
                  {result.counterfactual_safe_conditions?.length > 0 ? (
                    result.counterfactual_safe_conditions.map((item, i) => (
                      <li key={i}>• {item}</li>
                    ))
                  ) : (
                    <li>No suggestions available.</li>
                  )}
                </ul>
              </div>
              <div className="p-4 rounded-xl bg-red-50 dark:bg-red-900/10 border border-red-100 dark:border-red-900/30">
                <h4 className="font-bold text-red-800 dark:text-red-300 text-sm mb-2 flex items-center gap-2">
                  <AlertOctagon className="w-4 h-4" /> Why it is Risky
                </h4>
                <ul className="text-xs space-y-1 text-red-700 dark:text-red-400">
                  {result.why_fraud?.length > 0 ? (
                    result.why_fraud.map((s, i) => <li key={i}>• {s}</li>)
                  ) : (
                    <li>No specific risks listed.</li>
                  )}
                </ul>
              </div>
            </div>

            <div className="mt-6 pt-4 border-t border-border">
              <p className="text-xs text-muted-foreground flex items-center gap-2">
                <span className="font-bold">AI Consistency Check:</span>
                {result.model_self_check?.confidence_calibration === "High" ? (
                  <span className="text-safe flex items-center gap-1">
                    <Check className="w-3 h-3" /> High Confidence
                  </span>
                ) : (
                  <span className="text-warning flex items-center gap-1">
                    <AlertOctagon className="w-3 h-3" />{" "}
                    {result.model_self_check?.confidence_calibration} Confidence
                  </span>
                )}
                <span className="text-muted-foreground/50">•</span>
                <span>
                  {result.model_self_check?.possible_misclassification_reason}
                </span>
              </p>
            </div>
          </motion.div>

          {/* Signal Detection Matrix (Advanced) */}
          <motion.div
            variants={item}
            className="bg-card border border-border p-6 rounded-2xl shadow-sm"
          >
            <h3 className="text-lg font-bold mb-4 flex items-center justify-between">
              <span>Signal Detection Matrix</span>
              <span className="text-xs font-normal text-muted-foreground bg-muted px-2 py-1 rounded">
                Multi-Modal Fusion
              </span>
            </h3>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              {result.detected_signals &&
                Object.entries(result.detected_signals).map(([key, value]) => {
                  const signalConfig: Record<
                    string,
                    { icon: React.ReactNode; label: string; desc: string }
                  > = {
                    urgency: {
                      icon: (
                        <AlertTriangle className="w-4 h-4 text-orange-500" />
                      ),
                      label: "Urgency/Pressure",
                      desc: "Forces immediate action",
                    },
                    financial_lure: {
                      icon: <Sparkles className="w-4 h-4 text-yellow-500" />,
                      label: "Financial Lure",
                      desc: "Promises of money or prizes",
                    },
                    impersonation: {
                      icon: <ShieldCheck className="w-4 h-4 text-blue-500" />,
                      label: "Impersonation",
                      desc: "Pretends to be authority",
                    },
                    credential_theft: {
                      icon: <Smartphone className="w-4 h-4 text-purple-500" />,
                      label: "Credential Theft",
                      desc: "Asks for OTP/Passwords",
                    },
                    suspicious_url: {
                      icon: <Paperclip className="w-4 h-4 text-red-500" />,
                      label: "Suspicious Link",
                      desc: "Contains shady/shortened URLs",
                    },
                    ai_generated_tone: {
                      icon: <Scan className="w-4 h-4 text-indigo-500" />,
                      label: "AI Scripted",
                      desc: "Uses robotic templates",
                    },
                    spelling_grammar_issues: {
                      icon: <SpellCheck className="w-4 h-4 text-orange-500" />,
                      label: "Spelling Errors",
                      desc: "Contains intentional typos",
                    },
                    social_engineering: {
                      icon: <Eye className="w-4 h-4 text-cyan-500" />,
                      label: "Social Engineering",
                      desc: "Emotional manipulation",
                    },
                    crypto_investment_pitch: {
                      icon: <Database className="w-4 h-4 text-green-500" />,
                      label: "Crypto Pitch",
                      desc: "Guaranteed ROI/BTC mentions",
                    },
                    threat_extortion: {
                      icon: <AlertOctagon className="w-4 h-4 text-red-600" />,
                      label: "Extortion Threat",
                      desc: "Blackmail or data leak threats",
                    },
                    job_scam: {
                      icon: <AlignLeft className="w-4 h-4 text-sky-500" />,
                      label: "Fake Job Offer",
                      desc: "Employment lures & upfront fees",
                    },
                    spam_marketing: {
                      icon: <Mail className="w-4 h-4 text-slate-500" />,
                      label: "Spam Marketing",
                      desc: "Unsolicited promotional bulk",
                    },
                    regional_upi_fraud: {
                      icon: <Sparkles className="w-4 h-4 text-emerald-500" />,
                      label: "UPI/CashApp Fraud",
                      desc: "Localized payment requests",
                    },
                    tech_support_refund: {
                      icon: <Scan className="w-4 h-4 text-teal-500" />,
                      label: "Tech Support/Refund",
                      desc: "Fake overpayment refunds",
                    },
                  };

                  const config = signalConfig[key] || {
                    icon: <Info className="w-4 h-4" />,
                    label: key.replace(/_/g, " "),
                    desc: "Signal detected",
                  };

                  return (
                    <motion.div
                      variants={item}
                      key={key}
                      className={`flex items-start gap-3 p-3 rounded-xl border transition-all ${
                        value
                          ? "bg-red-50/50 border-red-200 dark:bg-red-900/10 dark:border-red-900/30"
                          : "bg-muted/20 border-border opacity-60 hover:opacity-100"
                      }`}
                    >
                      <div
                        className={`mt-0.5 p-1.5 rounded-full ${value ? "bg-white shadow-sm dark:bg-slate-800" : "bg-transparent"}`}
                      >
                        {config.icon}
                      </div>
                      <div className="flex-1">
                        <div className="flex justify-between items-center mb-0.5">
                          <h4
                            className={`text-sm font-bold ${value ? "text-red-900 dark:text-red-300" : "text-foreground"}`}
                          >
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
                    </motion.div>
                  );
                })}
            </div>
          </motion.div>

          {/* ===== API Intelligence Panel ===== */}
          {result.api_signals && result.api_signals.length > 0 && (
            <motion.div
              variants={item}
              className="bg-slate-900 text-white p-6 rounded-2xl shadow-lg border border-slate-700"
            >
              <h3 className="text-lg font-bold mb-4 flex items-center gap-2">
                <Sparkles className="w-5 h-5 text-yellow-400" />
                Real-World API Intelligence
                <span className="ml-auto text-xs bg-yellow-400 text-slate-900 px-2 py-0.5 rounded-full font-bold">
                  LIVE APIs
                </span>
              </h3>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                {result.api_signals.map(
                  (
                    sig: {
                      api: string;
                      icon: string;
                      verdict: string;
                      score: number;
                      flagged: boolean;
                      detail: string;
                    },
                    i: number,
                  ) => (
                    <div
                      key={i}
                      className={`flex items-start gap-3 p-3 rounded-xl border ${sig.flagged ? "bg-red-900/20 border-red-700/40" : "bg-green-900/20 border-green-700/40"}`}
                    >
                      <span className="text-xl">{sig.icon}</span>
                      <div className="min-w-0">
                        <div className="flex items-center gap-2 flex-wrap">
                          <span className="text-xs font-bold text-slate-300">
                            {sig.api}
                          </span>
                          <span
                            className={`text-[10px] font-bold px-2 py-0.5 rounded-full uppercase ${sig.flagged ? "bg-red-500 text-white" : "bg-green-600 text-white"}`}
                          >
                            {sig.verdict}
                          </span>
                        </div>
                        <p className="text-xs text-slate-400 mt-0.5 truncate">
                          {sig.detail}
                        </p>
                      </div>
                      <span
                        className={`ml-auto text-xs font-bold shrink-0 ${sig.flagged ? "text-red-400" : "text-green-400"}`}
                      >
                        {sig.score}%
                      </span>
                    </div>
                  ),
                )}
              </div>
            </motion.div>
          )}
        </div>
      </div>

      {/* Action Buttons Footer */}
      <div className="border-t border-border/40 pt-8 mt-12">
        <div className="flex flex-col sm:flex-row gap-4 justify-center items-center">
          <Link href="/analyze">
            <button className="px-8 py-3 rounded-xl border-2 border-primary hover:bg-primary/10 text-primary font-semibold transition-all duration-300">
              ← Analyze Another
            </button>
          </Link>
          <Link href="/demo">
            <button className="px-8 py-3 rounded-xl border-2 border-border hover:border-primary/50 text-foreground font-semibold transition-all duration-300">
              Try Demo Examples
            </button>
          </Link>
          <Link href="/">
            <button className="px-8 py-3 rounded-xl border-2 border-border hover:border-primary/50 text-foreground font-semibold transition-all duration-300">
              Back to Home
            </button>
          </Link>
        </div>
      </div>
    </motion.div>
  );
}
