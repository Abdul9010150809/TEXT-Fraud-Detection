import { GoogleGenerativeAI } from "@google/generative-ai";

export type CompareMode = "text" | "link" | "email" | "image";

export interface ComparePayload {
  mode: CompareMode;
  input: string;
  fraudguard: {
    isFraud: boolean;
    riskScore: number;
    riskLevel: string;
    messageType?: string;
  };
  timestamp: number;
}

export interface GoogleVerificationResult {
  googleVerdict: "SAFE" | "SUSPICIOUS" | "FRAUD";
  googleRiskScore: number;
  confidence: number;
  reasons: string[];
  checks: string[];
  source: string;
}

const STORAGE_KEY = "fraudguard-google-compare-payload";
const API_KEY = process.env.NEXT_PUBLIC_GEMINI_API_KEY || "";

export function saveComparePayload(payload: ComparePayload): void {
  if (typeof window === "undefined") return;
  window.localStorage.setItem(STORAGE_KEY, JSON.stringify(payload));
}

export function readComparePayload(): ComparePayload | null {
  if (typeof window === "undefined") return null;
  const raw = window.localStorage.getItem(STORAGE_KEY);
  if (!raw) return null;

  try {
    const parsed = JSON.parse(raw) as ComparePayload;
    if (!parsed?.mode || !parsed?.input || !parsed?.fraudguard) return null;
    return parsed;
  } catch {
    return null;
  }
}

function buildPrompt(mode: CompareMode, content: string): string {
  const modeLabel =
    mode === "text"
      ? "text message"
      : mode === "link"
        ? "URL"
        : mode === "email"
          ? "email"
          : "OCR extracted text from image";

  return `You are a security analyst. Analyze this ${modeLabel} and classify fraud risk.

Return STRICT JSON ONLY with exactly this schema:
{
  "google_verdict": "SAFE|SUSPICIOUS|FRAUD",
  "google_risk_score": 0,
  "confidence": 0.0,
  "reasons": ["..."],
  "google_checks": ["..."]
}

Rules:
- google_risk_score must be integer 0-100
- confidence must be number between 0 and 1
- reasons should be short, practical security reasons
- google_checks should include checks you used (domain reputation, urgency, credential theft patterns, impersonation, grammar anomalies, etc.)
- Do not include markdown or code fences.

Content to analyze:
${content.slice(0, 5000)}`;
}

function stripCodeFences(input: string): string {
  return input
    .replace(/^```json\s*/i, "")
    .replace(/^```\s*/i, "")
    .replace(/\s*```$/, "")
    .trim();
}

export async function verifyWithGoogle(
  mode: CompareMode,
  input: string,
): Promise<GoogleVerificationResult> {
  if (!API_KEY) {
    throw new Error(
      "Google Gemini API key missing. Set NEXT_PUBLIC_GEMINI_API_KEY.",
    );
  }

  const genAI = new GoogleGenerativeAI(API_KEY);
  const model = genAI.getGenerativeModel({ model: "gemini-1.5-flash" });

  const response = await model.generateContent(buildPrompt(mode, input));
  const rawText = (await response.response).text();
  const normalized = stripCodeFences(rawText);

  let parsed: {
    google_verdict?: string;
    google_risk_score?: number;
    confidence?: number;
    reasons?: string[];
    google_checks?: string[];
  };

  try {
    parsed = JSON.parse(normalized);
  } catch {
    throw new Error("Google response could not be parsed as JSON.");
  }

  const verdictRaw = (parsed.google_verdict || "SUSPICIOUS").toUpperCase();
  const googleVerdict =
    verdictRaw === "SAFE" ||
    verdictRaw === "FRAUD" ||
    verdictRaw === "SUSPICIOUS"
      ? verdictRaw
      : "SUSPICIOUS";

  const score = Math.max(
    0,
    Math.min(100, Math.round(Number(parsed.google_risk_score ?? 50))),
  );
  const confidence = Math.max(0, Math.min(1, Number(parsed.confidence ?? 0.6)));

  return {
    googleVerdict,
    googleRiskScore: score,
    confidence,
    reasons: Array.isArray(parsed.reasons)
      ? parsed.reasons.slice(0, 6)
      : ["No detailed reasons returned."],
    checks: Array.isArray(parsed.google_checks)
      ? parsed.google_checks.slice(0, 6)
      : ["Pattern-based security analysis"],
    source: "Google Gemini",
  };
}
