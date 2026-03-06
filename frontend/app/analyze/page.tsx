"use client";

import React, { useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useFraudStore } from "@/store/useFraudStore";
import { analyzeContent } from "@/lib/gemini";
import { ScanLine, Shield, Zap, Copy, CheckCircle } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { Card } from "@/components/ui/card";
import { motion, AnimatePresence } from "framer-motion";

const FRAUD_EXAMPLES = [
  {
    title: "UPI Payment Scam",
    description: "Fake UPI payment request",
    text: "Hi! Your UPI account has suspicious activity. Click here urgently to verify: bit.ly/upi-verify. Don't share this with anyone! Your money is at risk! Reply ASAP.",
  },
  {
    title: "Bank Account Compromise",
    description: "Account lockout threat",
    text: "ALERT: Your HDFC Bank Account will be CLOSED immediately due to suspicious transactions! Update your details now: secure-hdfc-verify.com/login. Your account has been flagged. Act now!",
  },
  {
    title: "Amazon/PayPal Refund",
    description: "Fake refund offer scam",
    text: "Congratulations! You've been selected for a Rs.5000 Amazon refund. Click below to claim your refund before it expires in 24 hours: amazon-refund-claim.tk. Limited slots available!",
  },
  {
    title: "Mobile Recharge Fraud",
    description: "Subscription trap message",
    text: "Your mobile plan expires today! Recharge now and get 50% OFF on next recharge. Click: mobile-recharge-offer.xyz. Valid only for 2 hours! Don't miss this amazing deal!",
  },
  {
    title: "Job Offer Scam",
    description: "Employment fraud",
    text: "You've been selected for a HIGH PAYING JOB! Work from home, earn Rs.50,000/month with no experience needed. Register now: quickjob-money.com. Urgent hiring! Limited positions left!",
  },
  {
    title: "Tax Refund Phishing",
    description: "Government impersonation",
    text: "Income Tax Dept: Your tax refund amount is Rs.23,456. To receive it immediately, verify your Aadhaar: itd-refund-verify.gov.fake. Process will take only 5 minutes. Don't wait!",
  },
];

const SAFE_EXAMPLES = [
  {
    title: "Team Update",
    text: "Hi team, the client review is moved to 3 PM tomorrow. Please bring your sprint notes and blockers list.",
  },
  {
    title: "Order Confirmation",
    text: "Your order #12984 has been confirmed and will be delivered by Monday. Track status from your account dashboard.",
  },
];

export default function AnalyzePage() {
  const router = useRouter();
  const { inputText, setInputText, setIsAnalyzing, setResult, demoMode } =
    useFraudStore();

  const [isLoading, setIsLoading] = useState(false);
  const [copiedId, setCopiedId] = useState<number | null>(null);

  const handleAnalyze = async () => {
    if (!inputText) return;

    setIsLoading(true);
    setIsAnalyzing(true);
    setResult(null);

    try {
      const data = await analyzeContent(inputText, demoMode);
      setTimeout(() => {
        setResult(data);
        router.push("/results");
        setIsLoading(false);
        setIsAnalyzing(false);
      }, 2000);
    } catch (e) {
      console.error(e);
      setIsLoading(false);
      setIsAnalyzing(false);
      alert("Error analyzing content. Please try again.");
    }
  };

  const handleAnalyzeAndGoogleCompare = () => {
    if (!inputText || inputText.length < 10) {
      alert("Please enter at least 10 characters to search on Google");
      return;
    }

    // Create Google search query
    const searchQuery = `is this fraud or scam: ${inputText.substring(0, 200)}`;
    const googleUrl = `https://www.google.com/search?q=${encodeURIComponent(searchQuery)}`;

    // Open Google in new tab
    window.open(googleUrl, "_blank");
  };

  const handleExampleClick = (text: string) => {
    setInputText(text);
  };

  const handleCopyExample = (text: string, id: number) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  return (
    <div className="relative min-h-screen flex flex-col">
      {/* Background Elements */}
      <div className="absolute inset-0 -z-10 overflow-hidden">
        <div className="absolute top-1/4 left-1/4 w-96 h-96 bg-gradient-to-br from-blue-500/20 to-purple-500/10 rounded-full blur-3xl animate-float"></div>
        <div
          className="absolute bottom-1/4 right-1/4 w-96 h-96 bg-gradient-to-br from-purple-500/20 to-pink-500/10 rounded-full blur-3xl animate-float"
          style={{ animationDelay: "2s" }}
        ></div>
      </div>

      {/* Header Section - Clean & Simple */}
      <div className="text-center space-y-6 mb-12 pt-8">
        {/* Simple Logo */}
        <div className="inline-flex items-center justify-center mb-4">
          <div className="relative">
            {/* Hexagon Logo */}
            <div
              className="w-20 h-20 bg-gradient-to-br from-blue-600 to-purple-600 flex items-center justify-center"
              style={{
                clipPath:
                  "polygon(50% 0%, 100% 25%, 100% 75%, 50% 100%, 0% 75%, 0% 25%)",
              }}
            >
              <Shield className="w-10 h-10 text-white" strokeWidth={2} />
            </div>
          </div>
        </div>
        <h1 className="text-4xl sm:text-5xl font-display font-bold tracking-tight gradient-text">
          Fraud Analysis
        </h1>
        <p className="text-lg text-muted-foreground max-w-2xl mx-auto">
          Paste text or share a link to instantly detect fraud with{" "}
          <span className="text-blue-600 dark:text-blue-400 font-semibold">
            AI-powered analysis
          </span>
          .
        </p>
        <div>
          <Link
            href="/analyze/compare?mode=text"
            className="text-sm text-blue-600 dark:text-blue-400 font-medium hover:underline"
          >
            Compare Text Result with Google/Other APIs
          </Link>
        </div>
      </div>

      {/* Main Content */}
      <div className="max-w-5xl mx-auto w-full space-y-8 flex-1 animate-in fade-in slide-in-from-bottom-8 duration-700 px-4">
        {/* Scanner Overlay - Simplified */}
        <AnimatePresence>
          {isLoading && (
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="fixed inset-0 z-50 bg-background/90 backdrop-blur-sm flex items-center justify-center"
            >
              {/* Content Container */}
              <div className="bg-card border-2 border-blue-500/30 p-8 rounded-lg text-center max-w-md">
                <motion.div
                  animate={{ rotate: 360 }}
                  transition={{ duration: 2, repeat: Infinity, ease: "linear" }}
                  className="flex justify-center mb-4"
                >
                  <Shield className="w-12 h-12 text-blue-600" />
                </motion.div>
                <h3 className="text-xl font-bold mb-3">Analyzing Content...</h3>
                <div className="space-y-2 text-sm text-muted-foreground">
                  <div className="flex items-center justify-center gap-2">
                    <Zap className="w-4 h-4" />
                    <span>Detecting Patterns</span>
                  </div>
                  <div className="flex items-center justify-center gap-2">
                    <Shield className="w-4 h-4" />
                    <span>Verifying Authenticity</span>
                  </div>
                  <div className="flex items-center justify-center gap-2">
                    <ScanLine className="w-4 h-4" />
                    <span>Running Forensics</span>
                  </div>
                </div>
              </div>
            </motion.div>
          )}
        </AnimatePresence>

        {/* Input Section */}
        <div className="space-y-6">
          {/* Text Input Card */}
          <div className="relative border-2 border-border focus-within:border-blue-500 transition-colors duration-200 bg-card rounded-lg overflow-hidden">
            <Textarea
              placeholder="Paste suspicious text, link, or message here to analyze..."
              className="min-h-[220px] text-base resize-none border-none focus-visible:ring-0 p-6 shadow-none bg-transparent"
              value={inputText}
              onChange={(e) => setInputText(e.target.value)}
            />
          </div>

          {/* Character Count & Status */}
          <div className="flex items-center justify-between text-sm text-muted-foreground px-2">
            <span>{inputText.length} characters</span>
            {inputText.length > 0 && inputText.length < 10 && (
              <span className="text-orange-500 text-xs">
                Enter at least 10 characters
              </span>
            )}
          </div>

          <div className="bg-card border border-border rounded-lg p-4">
            <p className="text-sm font-semibold mb-3">
              Demo Examples (Safe + Scam)
            </p>
            <div className="flex flex-col sm:flex-row gap-3">
              <button
                onClick={() => setInputText(SAFE_EXAMPLES[0].text)}
                className="flex-1 px-4 py-2 rounded-md border border-green-300 dark:border-green-700 bg-green-50 dark:bg-green-900/20 text-green-700 dark:text-green-300 text-sm font-medium hover:opacity-90"
              >
                Load Safe Demo
              </button>
              <button
                onClick={() => setInputText(FRAUD_EXAMPLES[0].text)}
                className="flex-1 px-4 py-2 rounded-md border border-red-300 dark:border-red-700 bg-red-50 dark:bg-red-900/20 text-red-700 dark:text-red-300 text-sm font-medium hover:opacity-90"
              >
                Load Scam Demo
              </button>
            </div>
          </div>

          <div className="flex flex-col sm:flex-row gap-3">
            <Button
              size="lg"
              className="gradient-button flex-1 text-base h-12 rounded-lg font-semibold hover:opacity-90 transition-opacity duration-200 disabled:opacity-50 disabled:cursor-not-allowed"
              onClick={handleAnalyze}
              disabled={!inputText || inputText.length < 10 || isLoading}
            >
              <Zap className="w-5 h-5 mr-2" />
              {isLoading ? "Analyzing..." : "Analyze Now"}
            </Button>
            <Link
              href="#"
              onClick={(e) => {
                e.preventDefault();
                void handleAnalyzeAndGoogleCompare();
              }}
              className="h-12 px-6 rounded-lg border-2 border-blue-500 text-blue-600 dark:text-blue-400 font-semibold inline-flex items-center justify-center hover:bg-blue-50 dark:hover:bg-blue-900/20"
            >
              Compare with Google
            </Link>
          </div>

          {/* Info Box */}
          <div className="bg-card border border-border rounded-lg p-4 text-sm text-muted-foreground space-y-2">
            <p className="font-semibold text-foreground">
              💡 Tips for Best Results:
            </p>
            <ul className="space-y-1 text-xs">
              <li>
                • Include the full message or link for comprehensive analysis
              </li>
              <li>• Copy-paste suspicious content exactly as received</li>
              <li>
                • Include URLs, sender details, and any unusual formatting
              </li>
              <li>• Analysis takes 2-3 seconds with AI-powered insights</li>
            </ul>
          </div>
        </div>

        {/* Fraud Examples Section */}
        <div className="mt-16 pt-12 border-t border-border/40">
          <div className="text-center mb-8">
            <h2 className="text-2xl sm:text-3xl font-display font-bold mb-2">
              Common Fraud Examples
            </h2>
            <p className="text-sm text-muted-foreground">
              Try these real-world fraud examples to see FraudGuard in action
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {FRAUD_EXAMPLES.map((example, idx) => (
              <motion.div
                key={idx}
                initial={{ opacity: 0, y: 20 }}
                whileInView={{ opacity: 1, y: 0 }}
                transition={{ delay: idx * 0.05, duration: 0.3 }}
                viewport={{ once: true }}
                className="group"
              >
                <div className="relative bg-card border-2 border-border rounded-lg p-4 h-full transition-all duration-200 flex flex-col hover:border-red-500/40 hover:-translate-y-0.5">
                  {/* Subtle shadow that doesn't affect layout */}
                  <div className="absolute inset-0 rounded-lg opacity-0 group-hover:opacity-100 transition-opacity duration-200 pointer-events-none shadow-lg shadow-red-500/10 -z-10"></div>

                  {/* Fraud Badge */}
                  <div className="absolute top-3 right-3 px-2 py-0.5 rounded-md bg-red-500/10 border border-red-500/30 text-red-500 text-xs font-bold">
                    FRAUD
                  </div>

                  {/* Header */}
                  <div className="mb-3 pr-16">
                    <h3 className="font-semibold text-sm text-foreground">
                      {example.title}
                    </h3>
                    <p className="text-xs text-muted-foreground mt-1">
                      {example.description}
                    </p>
                  </div>

                  {/* Preview Text - Fixed height to prevent layout shift */}
                  <p className="text-xs leading-relaxed text-muted-foreground mb-4 flex-1 line-clamp-4">
                    "{example.text}"
                  </p>

                  {/* Action Buttons */}
                  <div className="flex gap-2">
                    <button
                      onClick={() => handleExampleClick(example.text)}
                      className="flex-1 px-3 py-2 rounded-md bg-blue-600/10 hover:bg-blue-600/20 border border-blue-500/30 text-blue-600 dark:text-blue-400 text-xs font-semibold transition-colors duration-200"
                    >
                      Use Example
                    </button>
                    <button
                      onClick={() => handleCopyExample(example.text, idx)}
                      className="px-3 py-2 rounded-md border border-border hover:border-blue-500/40 hover:bg-blue-500/5 text-muted-foreground hover:text-foreground text-xs transition-all duration-200"
                    >
                      {copiedId === idx ? (
                        <CheckCircle className="w-4 h-4 text-green-500" />
                      ) : (
                        <Copy className="w-4 h-4" />
                      )}
                    </button>
                  </div>
                </div>
              </motion.div>
            ))}
          </div>

          <p className="text-xs text-muted-foreground text-center mt-8">
            Note: These are examples of common fraud patterns. Analysis results
            are for educational purposes.
          </p>
        </div>
      </div>
    </div>
  );
}
