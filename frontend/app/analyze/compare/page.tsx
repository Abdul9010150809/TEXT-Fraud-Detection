import Link from "next/link";
import { RiskMeter } from "@/components/results/RiskMeter";
import { ArrowLeftRight, CheckCircle, AlertTriangle } from "lucide-react";
import GoogleVerificationPanel from "@/components/analyze/GoogleVerificationPanel";

type CompareMode = "text" | "link" | "email" | "image";

const compareData: Record<
  CompareMode,
  {
    title: string;
    description: string;
    providers: string[];
    normalSample: string;
    fraudSample: string;
    normalNotes: string[];
    fraudNotes: string[];
    normalScore: number;
    fraudScore: number;
  }
> = {
  text: {
    title: "Text Fraud vs Safe Comparison",
    description:
      "Compare plain text messages across FraudGuard, Google, and other provider heuristics.",
    providers: ["FraudGuard", "Google/Gemini", "Rule Engine"],
    normalSample:
      "Hi team, meeting moved to 4 PM. Please share the sprint notes and blockers before EOD.",
    fraudSample:
      "URGENT! Your account is blocked. Verify OTP and password now at bit.ly/secure-login.",
    normalNotes: [
      "Neutral tone with normal workplace context.",
      "No credential request or malicious URL pattern.",
      "Grammar and structure are natural.",
    ],
    fraudNotes: [
      "Strong urgency pressure and account threat language.",
      "Credential theft intent detected (OTP/password).",
      "Shortened URL with phishing footprint.",
    ],
    normalScore: 5,
    fraudScore: 96,
  },
  link: {
    title: "Link Safety Comparison",
    description:
      "Compare suspicious and safe URLs across FraudGuard and external checks.",
    providers: [
      "FraudGuard",
      "Google Safe Browsing (planned)",
      "URL Reputation APIs",
    ],
    normalSample: "https://github.com/microsoft/vscode",
    fraudSample: "https://verify-secure-update.top/login-now",
    normalNotes: [
      "Known trusted domain profile.",
      "No spoof keywords in path or host.",
      "Low-risk URL grammar pattern.",
    ],
    fraudNotes: [
      "High-risk TLD and login bait keywords.",
      "Spoof-like domain construction.",
      "URL grammar anomalies increase risk.",
    ],
    normalScore: 2,
    fraudScore: 99,
  },
  email: {
    title: "Email Scam Comparison",
    description:
      "Compare sender + subject + body scoring across FraudGuard and Google/other checks.",
    providers: ["FraudGuard", "Google/Gemini", "Mail Reputation Rules"],
    normalSample: "From: hr@company.com | Subject: Interview schedule update",
    fraudSample:
      "From: noreply@secure-alert.tk | Subject: URGENT verify account now",
    normalNotes: [
      "Trusted sender pattern and business context.",
      "No manipulation phrases or credential lure.",
      "Balanced tone and normal grammar quality.",
    ],
    fraudNotes: [
      "Suspicious sender/domain pattern.",
      "Urgency-heavy subject with phishing intent.",
      "Body requests sensitive account confirmation.",
    ],
    normalScore: 8,
    fraudScore: 94,
  },
  image: {
    title: "Image OCR Fraud Comparison",
    description:
      "Extract text from screenshots/images, then compare fraud scoring with Google/other APIs.",
    providers: [
      "FraudGuard OCR",
      "Google Vision (optional)",
      "Browser OCR Fallback",
    ],
    normalSample: "Screenshot: team update and schedule details",
    fraudSample:
      "Screenshot: urgent account block + OTP request + suspicious link",
    normalNotes: [
      "OCR extracts clear benign business communication.",
      "No credential theft or extortion pattern.",
      "Risk remains in safe band.",
    ],
    fraudNotes: [
      "OCR extracts urgency + threat language.",
      "Credential and phishing signals are detected.",
      "Fraud risk escalates to high/critical.",
    ],
    normalScore: 7,
    fraudScore: 97,
  },
};

export default function ComparePage({
  searchParams,
}: {
  searchParams?: { mode?: string };
}) {
  const modeParam = searchParams?.mode;
  const mode: CompareMode =
    modeParam === "link" || modeParam === "email" || modeParam === "image"
      ? modeParam
      : "text";

  const selected = compareData[mode];

  return (
    <div className="max-w-6xl mx-auto space-y-8 animate-in fade-in duration-500">
      <div className="text-center space-y-2 mb-8">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-muted text-muted-foreground text-xs font-semibold uppercase tracking-wider mb-2">
          <ArrowLeftRight className="w-4 h-4" />
          Live Comparison
        </div>
        <h1 className="text-3xl font-bold font-display">{selected.title}</h1>
        <p className="text-muted-foreground max-w-2xl mx-auto">
          {selected.description}
        </p>
        <p className="text-xs text-muted-foreground">
          Compared providers: {selected.providers.join(" • ")}
        </p>
        <div className="pt-2">
          <Link
            href="/analyze"
            className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-700 text-white text-sm font-semibold"
          >
            Run New Verification
          </Link>
        </div>
      </div>

      <GoogleVerificationPanel mode={mode} />

      <div className="grid grid-cols-1 md:grid-cols-2 gap-8 relative">
        <div className="hidden md:flex absolute left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2 w-12 h-12 bg-background border border-border rounded-full items-center justify-center font-black z-10 shadow-lg">
          VS
        </div>

        <div className="bg-card border border-border rounded-2xl p-6 shadow-sm flex flex-col gap-6 relative overflow-hidden">
          <div className="absolute top-0 left-0 w-full h-1 bg-safe" />

          <div className="flex items-center justify-between">
            <span className="text-sm font-bold uppercase text-safe flex items-center gap-2">
              <CheckCircle className="w-4 h-4" /> Normal Example
            </span>
            <span className="text-xs text-muted-foreground">Mode: {mode}</span>
          </div>

          <div className="p-4 bg-muted/40 rounded-xl border border-border font-mono text-sm leading-relaxed">
            {selected.normalSample}
          </div>

          <div className="flex-1 border-t border-border pt-6">
            <h4 className="font-semibold mb-3 text-sm">Analysis Highlights</h4>
            <ul className="space-y-2 text-sm text-muted-foreground">
              {selected.normalNotes.map((note) => (
                <li key={note} className="flex items-start gap-2">
                  <span className="text-safe">✔</span>
                  {note}
                </li>
              ))}
            </ul>
          </div>

          <div className="flex justify-center p-4">
            <RiskMeter score={selected.normalScore} level="LOW" />
          </div>
        </div>

        <div className="bg-card border border-border rounded-2xl p-6 shadow-sm flex flex-col gap-6 relative overflow-hidden">
          <div className="absolute top-0 left-0 w-full h-1 bg-danger" />

          <div className="flex items-center justify-between">
            <span className="text-sm font-bold uppercase text-danger flex items-center gap-2">
              <AlertTriangle className="w-4 h-4" /> Fraud Example
            </span>
            <span className="text-xs text-muted-foreground">Mode: {mode}</span>
          </div>

          <div className="p-4 bg-red-50 dark:bg-red-900/10 rounded-xl border border-red-100 dark:border-red-900/30 font-mono text-sm leading-relaxed text-red-900 dark:text-red-100">
            {selected.fraudSample}
          </div>

          <div className="flex-1 border-t border-border pt-6">
            <h4 className="font-semibold mb-3 text-sm">Analysis Highlights</h4>
            <ul className="space-y-2 text-sm text-muted-foreground">
              {selected.fraudNotes.map((note) => (
                <li key={note} className="flex items-start gap-2">
                  <span className="text-danger">✖</span>
                  {note}
                </li>
              ))}
            </ul>
          </div>

          <div className="flex justify-center p-4">
            <RiskMeter score={selected.fraudScore} level="CRITICAL" />
          </div>
        </div>
      </div>
    </div>
  );
}
