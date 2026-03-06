"use client";

import Link from "next/link";
import { useState } from "react";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Link2,
  Shield,
  AlertTriangle,
  CheckCircle,
  Loader2,
} from "lucide-react";

interface LinkAnalysisResult {
  is_spam: boolean;
  risk_score: number;
  risk_level: string;
  message_type: string;
  grammar_score: number;
  url: string;
  domain: string;
  scam_type: string[];
  why_spam: string[];
  detected_signals: Record<string, boolean>;
  domain_analysis: {
    domain: string;
    tld: string;
    scheme: string;
    is_shortener: boolean;
    is_safe_domain: boolean;
  };
  recommended_action: string[];
  confidence: number;
}

const LINK_DEMOS = {
  safe: "https://github.com/microsoft/vscode",
  scam: "https://verify-secure-update.top/login-now",
};

export default function LinkAnalyzePage() {
  const [url, setUrl] = useState("");
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [result, setResult] = useState<LinkAnalysisResult | null>(null);
  const [error, setError] = useState("");

  const getBackendBaseUrls = (): string[] => {
    const fromEnv = process.env.NEXT_PUBLIC_BACKEND_URL?.trim();
    const fromWindow =
      typeof window !== "undefined"
        ? `${window.location.protocol}//${window.location.hostname}:8080`
        : undefined;

    const candidates = [
      fromEnv,
      fromWindow,
      "http://127.0.0.1:8080",
      "http://localhost:8080",
    ].filter((value): value is string => Boolean(value));

    return [...new Set(candidates)];
  };

  const analyzeLink = async () => {
    if (!url.trim()) {
      setError("Please enter a URL");
      return;
    }

    setIsAnalyzing(true);
    setError("");
    setResult(null);

    try {
      let lastError: unknown = null;
      let response: Response | null = null;

      for (const baseUrl of getBackendBaseUrls()) {
        try {
          response = await fetch(`${baseUrl}/api/v1/link/analyze`, {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
            },
            body: JSON.stringify({ url: url.trim() }),
          });
          if (response.ok) {
            break;
          }
          lastError = new Error(`Backend returned status ${response.status}`);
        } catch (err) {
          lastError = err;
          response = null;
        }
      }

      if (!response || !response.ok) {
        throw lastError ?? new Error("Analysis failed");
      }

      const data = await response.json();
      setResult(data);
    } catch (err) {
      setError(
        "Failed to connect to backend link analyzer. Ensure backend is running on port 8080.",
      );
      console.error(err);
    } finally {
      setIsAnalyzing(false);
    }
  };

  const getRiskColor = (level: string) => {
    switch (level) {
      case "Critical":
        return "text-red-600 dark:text-red-400";
      case "High":
        return "text-orange-600 dark:text-orange-400";
      case "Suspicious":
        return "text-yellow-600 dark:text-yellow-400";
      default:
        return "text-green-600 dark:text-green-400";
    }
  };

  const getRiskIcon = (level: string) => {
    switch (level) {
      case "Critical":
      case "High":
        return <AlertTriangle className="w-6 h-6" />;
      default:
        return <CheckCircle className="w-6 h-6" />;
    }
  };

  const handleGoogleCompare = () => {
    if (!result) {
      setError("Run link analysis first, then verify with Google.");
      return;
    }

    // Create Google search query for the URL
    const searchQuery = `is ${result.url || url} fraud or scam website`;
    const googleUrl = `https://www.google.com/search?q=${encodeURIComponent(searchQuery)}`;

    // Open Google in new tab
    window.open(googleUrl, "_blank");
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 via-white to-purple-50 dark:from-slate-950 dark:via-slate-900 dark:to-slate-950">
      <div className="container mx-auto px-4 py-12">
        {/* Header */}
        <div className="text-center mb-12">
          <div className="flex items-center justify-center gap-3 mb-4">
            <Link2 className="w-12 h-12 text-blue-600" />
            <h1 className="text-4xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-blue-600 to-purple-600">
              Link Analyzer
            </h1>
          </div>
          <p className="text-muted-foreground text-lg">
            Analyze URLs for spam, phishing, and fraud indicators
          </p>
          <div className="mt-4">
            <Link
              href="/analyze/compare?mode=link"
              className="text-sm text-blue-600 dark:text-blue-400 font-medium hover:underline"
            >
              Compare Link Result with Google/Other APIs
            </Link>
          </div>
        </div>

        {/* Input Section */}
        <Card className="max-w-4xl mx-auto p-8 mb-8 border-2">
          <div className="space-y-4">
            <div className="rounded-lg border border-border p-4 bg-muted/20">
              <p className="text-sm font-semibold mb-3">
                Demo Examples (Safe + Scam)
              </p>
              <div className="flex flex-col sm:flex-row gap-3">
                <button
                  onClick={() => setUrl(LINK_DEMOS.safe)}
                  className="flex-1 px-4 py-2 rounded-md border border-green-300 dark:border-green-700 bg-green-50 dark:bg-green-900/20 text-green-700 dark:text-green-300 text-sm font-medium hover:opacity-90"
                >
                  Load Safe Demo URL
                </button>
                <button
                  onClick={() => setUrl(LINK_DEMOS.scam)}
                  className="flex-1 px-4 py-2 rounded-md border border-red-300 dark:border-red-700 bg-red-50 dark:bg-red-900/20 text-red-700 dark:text-red-300 text-sm font-medium hover:opacity-90"
                >
                  Load Scam Demo URL
                </button>
              </div>
            </div>

            <label className="text-sm font-medium">Enter URL to Analyze</label>
            <div className="flex gap-3">
              <Input
                type="text"
                placeholder="https://example.com or bit.ly/shortened"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                onKeyPress={(e) => e.key === "Enter" && analyzeLink()}
                className="flex-1 text-lg"
              />
              <Button
                onClick={analyzeLink}
                disabled={isAnalyzing}
                className="px-8 bg-gradient-to-r from-blue-600 to-purple-600 hover:from-blue-700 hover:to-purple-700"
              >
                {isAnalyzing ? (
                  <>
                    <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                    Analyzing...
                  </>
                ) : (
                  <>
                    <Shield className="w-4 h-4 mr-2" />
                    Analyze
                  </>
                )}
              </Button>
              <Link
                href="#"
                onClick={(e) => {
                  e.preventDefault();
                  handleGoogleCompare();
                }}
                className="px-6 rounded-lg border-2 border-blue-500 text-blue-600 dark:text-blue-400 font-semibold inline-flex items-center justify-center hover:bg-blue-50 dark:hover:bg-blue-900/20"
              >
                Compare with Google
              </Link>
            </div>
            {error && (
              <p className="text-red-600 dark:text-red-400 text-sm">{error}</p>
            )}
          </div>
        </Card>

        {/* Results */}
        {result && (
          <div className="max-w-4xl mx-auto space-y-6">
            {/* Risk Score Card */}
            <Card className="p-8 border-2">
              <div className="flex items-center justify-between mb-6">
                <div className="flex items-center gap-4">
                  <div className={getRiskColor(result.risk_level)}>
                    {getRiskIcon(result.risk_level)}
                  </div>
                  <div>
                    <h2 className="text-2xl font-bold">Risk Assessment</h2>
                    <p className="text-muted-foreground">{result.domain}</p>
                  </div>
                </div>
                <div className="text-right">
                  <div
                    className={`text-4xl font-bold ${getRiskColor(result.risk_level)}`}
                  >
                    {result.risk_score}/100
                  </div>
                  <div
                    className={`text-lg font-semibold ${getRiskColor(result.risk_level)}`}
                  >
                    {result.risk_level}
                  </div>
                </div>
              </div>

              {/* Risk Bar */}
              <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-3 mb-6">
                <div
                  className={`h-3 rounded-full transition-all ${
                    result.risk_level === "Critical"
                      ? "bg-red-600"
                      : result.risk_level === "High"
                        ? "bg-orange-500"
                        : result.risk_level === "Suspicious"
                          ? "bg-yellow-500"
                          : "bg-green-500"
                  }`}
                  style={{ width: `${result.risk_score}%` }}
                ></div>
              </div>

              {/* Scam Types */}
              <div className="mb-6">
                <h3 className="text-lg font-semibold mb-3">
                  Detected Scam Types
                </h3>
                <div className="flex flex-wrap gap-2">
                  {result.scam_type.map((type, idx) => (
                    <span
                      key={idx}
                      className="px-3 py-1 bg-blue-100 dark:bg-blue-900 text-blue-800 dark:text-blue-200 rounded-full text-sm"
                    >
                      {type}
                    </span>
                  ))}
                </div>
              </div>

              <div className="grid grid-cols-2 gap-4 mb-6">
                <div>
                  <p className="text-sm text-muted-foreground">Message Type</p>
                  <p className="font-semibold">{result.message_type}</p>
                </div>
                <div>
                  <p className="text-sm text-muted-foreground">
                    URL Grammar Score
                  </p>
                  <p className="font-semibold">{result.grammar_score}/100</p>
                </div>
              </div>

              {/* Why Spam */}
              <div>
                <h3 className="text-lg font-semibold mb-3">Analysis Details</h3>
                <ul className="space-y-2">
                  {result.why_spam.map((reason, idx) => (
                    <li key={idx} className="flex items-start gap-2">
                      <span className="text-blue-600 dark:text-blue-400 mt-1">
                        •
                      </span>
                      <span>{reason}</span>
                    </li>
                  ))}
                </ul>
              </div>
            </Card>

            {/* Domain Analysis */}
            <Card className="p-8 border-2">
              <h3 className="text-xl font-bold mb-4">Domain Information</h3>
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <p className="text-sm text-muted-foreground">Domain</p>
                  <p className="font-mono font-semibold">
                    {result.domain_analysis.domain}
                  </p>
                </div>
                <div>
                  <p className="text-sm text-muted-foreground">TLD</p>
                  <p className="font-mono font-semibold">
                    .{result.domain_analysis.tld}
                  </p>
                </div>
                <div>
                  <p className="text-sm text-muted-foreground">Protocol</p>
                  <p className="font-mono font-semibold">
                    {result.domain_analysis.scheme}
                  </p>
                </div>
                <div>
                  <p className="text-sm text-muted-foreground">URL Shortener</p>
                  <p className="font-semibold">
                    {result.domain_analysis.is_shortener ? "Yes ⚠️" : "No ✓"}
                  </p>
                </div>
                <div>
                  <p className="text-sm text-muted-foreground">Safe Domain</p>
                  <p className="font-semibold">
                    {result.domain_analysis.is_safe_domain ? "Yes ✓" : "No ⚠️"}
                  </p>
                </div>
                <div>
                  <p className="text-sm text-muted-foreground">Confidence</p>
                  <p className="font-semibold">
                    {(result.confidence * 100).toFixed(0)}%
                  </p>
                </div>
              </div>
            </Card>

            {/* Signal Detection Matrix */}
            <Card className="p-8 border-2">
              <h3 className="text-xl font-bold mb-4">
                Signal Detection Matrix
              </h3>
              <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
                {Object.entries(result.detected_signals).map(
                  ([signal, detected]) => (
                    <div
                      key={signal}
                      className={`p-3 rounded-lg border ${
                        detected
                          ? "bg-red-50 dark:bg-red-900/20 border-red-300 dark:border-red-700"
                          : "bg-gray-50 dark:bg-gray-800 border-gray-200 dark:border-gray-700"
                      }`}
                    >
                      <p className="text-sm font-medium capitalize">
                        {signal.replace(/_/g, " ")}
                      </p>
                      <p
                        className={`text-xs ${detected ? "text-red-600 dark:text-red-400" : "text-gray-500"}`}
                      >
                        {detected ? "Detected" : "Not Detected"}
                      </p>
                    </div>
                  ),
                )}
              </div>
            </Card>

            {/* Recommendations */}
            <Card className="p-8 border-2 bg-gradient-to-br from-blue-50 to-purple-50 dark:from-blue-950/20 dark:to-purple-950/20">
              <h3 className="text-xl font-bold mb-4">Recommended Actions</h3>
              <ul className="space-y-3">
                {result.recommended_action.map((action, idx) => (
                  <li key={idx} className="flex items-start gap-3">
                    <Shield className="w-5 h-5 text-blue-600 mt-0.5 flex-shrink-0" />
                    <span className="font-medium">{action}</span>
                  </li>
                ))}
              </ul>
            </Card>
          </div>
        )}
      </div>
    </div>
  );
}
