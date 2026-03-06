"use client";

import { useEffect, useMemo, useState } from "react";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import {
  CompareMode,
  ComparePayload,
  GoogleVerificationResult,
  readComparePayload,
  verifyWithGoogle,
} from "@/lib/googleVerification";
import { CheckCircle, AlertTriangle, Loader2, Shield } from "lucide-react";

interface GoogleVerificationPanelProps {
  mode: CompareMode;
}

function verdictColor(verdict: string): string {
  if (verdict === "FRAUD") return "text-red-600 dark:text-red-400";
  if (verdict === "SUSPICIOUS") return "text-yellow-600 dark:text-yellow-400";
  return "text-green-600 dark:text-green-400";
}

export default function GoogleVerificationPanel({
  mode,
}: GoogleVerificationPanelProps) {
  const [payload, setPayload] = useState<ComparePayload | null>(null);
  const [googleResult, setGoogleResult] =
    useState<GoogleVerificationResult | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    const stored = readComparePayload();
    if (stored && stored.mode === mode) {
      setPayload(stored);
    } else {
      setPayload(null);
      setGoogleResult(null);
    }
  }, [mode]);

  const fraudguardVerdict = useMemo(() => {
    if (!payload) return "UNKNOWN";
    return payload.fraudguard.isFraud
      ? payload.fraudguard.riskScore >= 70
        ? "FRAUD"
        : "SUSPICIOUS"
      : "SAFE";
  }, [payload]);

  const runGoogleVerification = async () => {
    if (!payload) return;

    setIsLoading(true);
    setError("");
    try {
      const result = await verifyWithGoogle(payload.mode, payload.input);
      setGoogleResult(result);
    } catch (err) {
      const message =
        err instanceof Error ? err.message : "Google verification failed.";
      setError(message);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    if (payload && !googleResult && !isLoading && !error) {
      void runGoogleVerification();
    }
  }, [payload]);

  if (!payload) {
    return (
      <Card className="p-6 border-2">
        <h3 className="text-xl font-bold mb-2">Google Verification</h3>
        <p className="text-sm text-muted-foreground">
          Analyze content first from Text/Link/Email/Image analyzer, then click
          Compare with Google to run a live Google verdict check here.
        </p>
      </Card>
    );
  }

  const agreement = googleResult
    ? googleResult.googleVerdict === fraudguardVerdict
    : null;

  return (
    <Card className="p-6 border-2 space-y-4">
      <div className="flex items-center justify-between gap-3">
        <h3 className="text-xl font-bold">Google Verification</h3>
        <Button
          onClick={runGoogleVerification}
          disabled={isLoading}
          variant="outline"
        >
          {isLoading ? (
            <>
              <Loader2 className="w-4 h-4 mr-2 animate-spin" /> Verifying...
            </>
          ) : (
            "Re-check with Google"
          )}
        </Button>
      </div>

      <div className="grid md:grid-cols-2 gap-4">
        <div className="rounded-lg border p-4 bg-muted/20">
          <p className="text-sm text-muted-foreground">FraudGuard Verdict</p>
          <p className={`text-lg font-bold ${verdictColor(fraudguardVerdict)}`}>
            {fraudguardVerdict}
          </p>
          <p className="text-sm mt-1">
            Risk: {payload.fraudguard.riskScore}/100 (
            {payload.fraudguard.riskLevel})
          </p>
        </div>

        <div className="rounded-lg border p-4 bg-muted/20">
          <p className="text-sm text-muted-foreground">
            Google Verdict ({googleResult?.source ?? "Google Gemini"})
          </p>
          <p
            className={`text-lg font-bold ${verdictColor(googleResult?.googleVerdict ?? "SUSPICIOUS")}`}
          >
            {googleResult?.googleVerdict ?? "PENDING"}
          </p>
          <p className="text-sm mt-1">
            Risk: {googleResult ? `${googleResult.googleRiskScore}/100` : "--"}
            {googleResult
              ? ` • Confidence ${(googleResult.confidence * 100).toFixed(0)}%`
              : ""}
          </p>
        </div>
      </div>

      {agreement !== null && (
        <div className="rounded-lg border p-3 bg-background">
          <p className="text-sm font-semibold flex items-center gap-2">
            {agreement ? (
              <CheckCircle className="w-4 h-4 text-green-600" />
            ) : (
              <AlertTriangle className="w-4 h-4 text-yellow-600" />
            )}
            Verification Result:{" "}
            {agreement
              ? "FraudGuard and Google agree"
              : "FraudGuard and Google differ"}
          </p>
        </div>
      )}

      {googleResult && (
        <div className="grid md:grid-cols-2 gap-4">
          <div>
            <p className="text-sm font-semibold mb-2">Google Reasons</p>
            <ul className="space-y-1 text-sm text-muted-foreground">
              {googleResult.reasons.map((reason) => (
                <li key={reason} className="flex gap-2">
                  <span>•</span>
                  <span>{reason}</span>
                </li>
              ))}
            </ul>
          </div>

          <div>
            <p className="text-sm font-semibold mb-2">Checks Used</p>
            <ul className="space-y-1 text-sm text-muted-foreground">
              {googleResult.checks.map((check) => (
                <li key={check} className="flex gap-2">
                  <Shield className="w-3 h-3 mt-1" />
                  <span>{check}</span>
                </li>
              ))}
            </ul>
          </div>
        </div>
      )}

      <div className="rounded-lg border p-3 bg-muted/10">
        <p className="text-xs text-muted-foreground">
          Compared content (preview)
        </p>
        <p className="text-sm mt-1 line-clamp-3">{payload.input}</p>
      </div>

      {error && (
        <p className="text-sm text-red-600 dark:text-red-400">{error}</p>
      )}
    </Card>
  );
}
