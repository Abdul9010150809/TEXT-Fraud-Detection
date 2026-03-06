"use client";

import Link from "next/link";
import { useState, useRef } from "react";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import {
  Image as ImageIcon,
  Upload,
  Shield,
  AlertTriangle,
  CheckCircle,
  Loader2,
  FileImage,
} from "lucide-react";

interface ImageAnalysisResult {
  is_spam: boolean;
  risk_score: number;
  risk_level: string;
  message_type: string;
  grammar_score: number;
  extracted_text: string;
  text_found: boolean;
  scam_type: string[];
  why_spam: string[];
  detected_signals: Record<string, boolean>;
  text_analysis: {
    text_category: string;
    grammar_score: number;
    author_style: string;
    confidence: number;
  } | null;
  recommended_action: string[];
  confidence: number;
  ocr_method: string;
}

interface TextAnalyzeApiResponse {
  is_fraud: boolean;
  risk_score: number;
  risk_level: string;
  text_category?: string;
  fraud_type?: string[];
  why_fraud?: string[];
  detected_signals?: Record<string, boolean>;
  text_error_analysis?: {
    score?: number;
  };
  author_prediction?: string;
  recommended_action?: string[];
  confidence?: number;
}

const IMAGE_DEMOS = {
  safe: "Screenshot with normal team discussion, order confirmation, or scheduling message.",
  scam: "Screenshot with urgency + account blocked message + OTP/password request + suspicious link.",
};

export default function ImageAnalyzePage() {
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [previewUrl, setPreviewUrl] = useState<string>("");
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [result, setResult] = useState<ImageAnalysisResult | null>(null);
  const [error, setError] = useState("");
  const fileInputRef = useRef<HTMLInputElement>(null);

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

  const analyzeExtractedText = async (
    text: string,
    ocrMethod: string,
  ): Promise<ImageAnalysisResult> => {
    let lastError: unknown = null;
    let response: Response | null = null;

    for (const baseUrl of getBackendBaseUrls()) {
      try {
        response = await fetch(`${baseUrl}/api/v1/analyze/text`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({ text }),
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
      throw lastError ?? new Error("Text analysis failed");
    }

    const data = (await response.json()) as TextAnalyzeApiResponse;
    const grammarScore = data.text_error_analysis?.score ?? 60;
    const messageType = data.text_category ?? "General Message";

    return {
      is_spam: Boolean(data.is_fraud),
      risk_score: Number(data.risk_score ?? 0),
      risk_level: data.risk_level ?? "Safe",
      message_type: messageType,
      grammar_score: grammarScore,
      extracted_text: text,
      text_found: true,
      scam_type: data.fraud_type ?? ["None"],
      why_spam: data.why_fraud ?? ["No strong fraud markers found."],
      detected_signals: data.detected_signals ?? {},
      text_analysis: {
        text_category: messageType,
        grammar_score: grammarScore,
        author_style: data.author_prediction ?? "Unknown",
        confidence: data.confidence ?? 0.6,
      },
      recommended_action: data.recommended_action ?? [
        "Verify sender identity and avoid sharing sensitive information.",
      ],
      confidence: data.confidence ?? 0.6,
      ocr_method: ocrMethod,
    };
  };

  const runClientOcr = async (file: File): Promise<string> => {
    const Tesseract = await import("tesseract.js");
    const ocrResult = await Tesseract.recognize(file, "eng");
    return (ocrResult.data?.text ?? "").trim();
  };

  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    // Validate file type
    if (!file.type.startsWith("image/")) {
      setError("Please select an image file");
      return;
    }

    // Validate file size (10MB max)
    if (file.size > 10 * 1024 * 1024) {
      setError("Image size must be less than 10MB");
      return;
    }

    setSelectedFile(file);
    setError("");
    setResult(null);

    // Create preview
    const reader = new FileReader();
    reader.onloadend = () => {
      setPreviewUrl(reader.result as string);
    };
    reader.readAsDataURL(file);
  };

  const analyzeImage = async () => {
    if (!selectedFile) {
      setError("Please select an image");
      return;
    }

    setIsAnalyzing(true);
    setError("");
    setResult(null);

    try {
      const formData = new FormData();
      formData.append("image", selectedFile);

      let lastError: unknown = null;
      let response: Response | null = null;

      for (const baseUrl of getBackendBaseUrls()) {
        try {
          response = await fetch(`${baseUrl}/api/v1/image/analyze`, {
            method: "POST",
            body: formData,
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

      const data = (await response.json()) as ImageAnalysisResult;

      if (data.text_found && data.extracted_text.trim().length > 0) {
        setResult(data);
      } else {
        const clientOcrText = await runClientOcr(selectedFile);
        if (!clientOcrText || clientOcrText.length < 5) {
          setResult({
            ...data,
            why_spam: [
              "No readable text was extracted from this image.",
              "Try a clearer screenshot with higher contrast and larger text.",
            ],
            ocr_method: `${data.ocr_method}+browser-tesseract`,
          });
          return;
        }

        const fallbackResult = await analyzeExtractedText(
          clientOcrText,
          "browser-tesseract",
        );
        setResult(fallbackResult);
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : "Unknown error";
      if (
        message.toLowerCase().includes("failed to fetch") ||
        message.toLowerCase().includes("network")
      ) {
        setError(
          "Failed to connect to backend image analyzer. Ensure backend is running on port 8080.",
        );
      } else {
        setError(
          "Image OCR or fraud analysis failed. Try a clearer screenshot or re-run analysis.",
        );
      }
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
    if (!result || !result.extracted_text?.trim()) {
      setError("Analyze image first to extract text, then verify with Google.");
      return;
    }

    // Create Google search query from extracted text
    const searchQuery = `is this fraud or scam: ${result.extracted_text.substring(0, 200)}`;
    const googleUrl = `https://www.google.com/search?q=${encodeURIComponent(searchQuery)}`;

    // Open Google in new tab
    window.open(googleUrl, "_blank");
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-green-50 via-white to-blue-50 dark:from-slate-950 dark:via-slate-900 dark:to-slate-950">
      <div className="container mx-auto px-4 py-12">
        {/* Header */}
        <div className="text-center mb-12">
          <div className="flex items-center justify-center gap-3 mb-4">
            <ImageIcon className="w-12 h-12 text-green-600" />
            <h1 className="text-4xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-green-600 to-blue-600">
              Image Analyzer
            </h1>
          </div>
          <p className="text-muted-foreground text-lg">
            Extract text from images and detect fraud using OCR + AI
          </p>
          <div className="mt-4">
            <Link
              href="/analyze/compare?mode=image"
              className="text-sm text-blue-600 dark:text-blue-400 font-medium hover:underline"
            >
              Compare Image Result with Google/Other APIs
            </Link>
          </div>
        </div>

        {/* Upload Section */}
        <Card className="max-w-4xl mx-auto p-8 mb-8 border-2">
          <div className="space-y-6">
            <div className="rounded-lg border border-border p-4 bg-muted/20">
              <p className="text-sm font-semibold mb-3">
                Demo Examples (Safe + Scam)
              </p>
              <div className="grid sm:grid-cols-2 gap-3 text-sm">
                <div className="rounded-md border border-green-300 dark:border-green-700 bg-green-50 dark:bg-green-900/20 p-3">
                  <p className="font-semibold text-green-700 dark:text-green-300 mb-1">
                    Safe Demo
                  </p>
                  <p className="text-green-700/90 dark:text-green-300/90">
                    {IMAGE_DEMOS.safe}
                  </p>
                </div>
                <div className="rounded-md border border-red-300 dark:border-red-700 bg-red-50 dark:bg-red-900/20 p-3">
                  <p className="font-semibold text-red-700 dark:text-red-300 mb-1">
                    Scam Demo
                  </p>
                  <p className="text-red-700/90 dark:text-red-300/90">
                    {IMAGE_DEMOS.scam}
                  </p>
                </div>
              </div>
            </div>

            {/* File Input */}
            <div
              onClick={() => fileInputRef.current?.click()}
              className="border-2 border-dashed border-gray-300 dark:border-gray-600 rounded-lg p-12 text-center cursor-pointer hover:border-green-500 transition-colors"
            >
              <input
                ref={fileInputRef}
                type="file"
                accept="image/*"
                onChange={handleFileSelect}
                className="hidden"
              />

              {previewUrl ? (
                <div className="space-y-4">
                  <img
                    src={previewUrl}
                    alt="Preview"
                    className="max-h-64 mx-auto rounded-lg border-2 border-gray-200 dark:border-gray-700"
                  />
                  <p className="text-sm text-muted-foreground">
                    {selectedFile?.name} (
                    {((selectedFile?.size || 0) / 1024 / 1024).toFixed(2)} MB)
                  </p>
                  <Button
                    onClick={(e) => {
                      e.stopPropagation();
                      setSelectedFile(null);
                      setPreviewUrl("");
                      setResult(null);
                    }}
                    variant="outline"
                    size="sm"
                  >
                    Choose Different Image
                  </Button>
                </div>
              ) : (
                <div className="space-y-4">
                  <Upload className="w-16 h-16 mx-auto text-gray-400" />
                  <div>
                    <p className="text-lg font-medium">
                      Click to upload an image
                    </p>
                    <p className="text-sm text-muted-foreground">
                      Supports JPG, PNG, WebP, and other common formats (Max
                      10MB)
                    </p>
                  </div>
                </div>
              )}
            </div>

            {error && (
              <p className="text-red-600 dark:text-red-400 text-sm text-center">
                {error}
              </p>
            )}

            {selectedFile && (
              <div className="flex flex-col sm:flex-row gap-3">
                <Button
                  onClick={analyzeImage}
                  disabled={isAnalyzing}
                  className="flex-1 py-6 text-lg bg-gradient-to-r from-green-600 to-blue-600 hover:from-green-700 hover:to-blue-700"
                >
                  {isAnalyzing ? (
                    <>
                      <Loader2 className="w-5 h-5 mr-2 animate-spin" />
                      Extracting & Analyzing...
                    </>
                  ) : (
                    <>
                      <Shield className="w-5 h-5 mr-2" />
                      Analyze Image
                    </>
                  )}
                </Button>
                <Link
                  href="#"
                  onClick={(e) => {
                    e.preventDefault();
                    handleGoogleCompare();
                  }}
                  className="sm:w-auto w-full px-6 rounded-lg border-2 border-blue-500 text-blue-600 dark:text-blue-400 font-semibold inline-flex items-center justify-center hover:bg-blue-50 dark:hover:bg-blue-900/20"
                >
                  Compare with Google
                </Link>
              </div>
            )}
          </div>
        </Card>

        {/* Results */}
        {result && (
          <div className="max-w-4xl mx-auto space-y-6">
            {/* OCR Info */}
            <Card className="p-6 border-2 bg-blue-50 dark:bg-blue-950/20">
              <div className="flex items-center gap-3 mb-3">
                <FileImage className="w-5 h-5 text-blue-600" />
                <h3 className="font-semibold">OCR Extraction</h3>
              </div>
              <p className="text-sm text-muted-foreground mb-2">
                Method:{" "}
                <span className="font-mono font-semibold">
                  {result.ocr_method}
                </span>
              </p>
              <p className="text-sm">
                Text Found:{" "}
                <span className="font-semibold">
                  {result.text_found ? "Yes ✓" : "No ✗"}
                </span>
              </p>
            </Card>

            {result.text_found ? (
              <>
                {/* Extracted Text */}
                <Card className="p-6 border-2">
                  <h3 className="text-lg font-bold mb-3">Extracted Text</h3>
                  <div className="bg-gray-100 dark:bg-gray-800 p-4 rounded-lg">
                    <p className="whitespace-pre-wrap font-mono text-sm">
                      {result.extracted_text}
                    </p>
                  </div>
                </Card>

                {/* Risk Score Card */}
                <Card className="p-8 border-2">
                  <div className="flex items-center justify-between mb-6">
                    <div className="flex items-center gap-4">
                      <div className={getRiskColor(result.risk_level)}>
                        {getRiskIcon(result.risk_level)}
                      </div>
                      <div>
                        <h2 className="text-2xl font-bold">Risk Assessment</h2>
                        <p className="text-muted-foreground">
                          {result.is_spam
                            ? "Spam/Fraud Detected"
                            : "Appears Safe"}
                        </p>
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
                          className="px-3 py-1 bg-green-100 dark:bg-green-900 text-green-800 dark:text-green-200 rounded-full text-sm"
                        >
                          {type}
                        </span>
                      ))}
                    </div>
                  </div>

                  {/* Why Spam */}
                  <div>
                    <h3 className="text-lg font-semibold mb-3">
                      Analysis Details
                    </h3>
                    <ul className="space-y-2">
                      {result.why_spam.map((reason, idx) => (
                        <li key={idx} className="flex items-start gap-2">
                          <span className="text-green-600 dark:text-green-400 mt-1">
                            •
                          </span>
                          <span>{reason}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                </Card>

                {/* Text Analysis */}
                {result.text_analysis && (
                  <Card className="p-8 border-2">
                    <h3 className="text-xl font-bold mb-4">Text Analysis</h3>
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                      <div>
                        <p className="text-sm text-muted-foreground">
                          Message Type
                        </p>
                        <p className="font-semibold">{result.message_type}</p>
                      </div>
                      <div>
                        <p className="text-sm text-muted-foreground">
                          Grammar Score
                        </p>
                        <p className="text-2xl font-bold">
                          {result.grammar_score}/100
                        </p>
                      </div>
                      <div>
                        <p className="text-sm text-muted-foreground">
                          Author Style
                        </p>
                        <p className="font-semibold">
                          {result.text_analysis.author_style}
                        </p>
                      </div>
                      <div>
                        <p className="text-sm text-muted-foreground">
                          Confidence
                        </p>
                        <p className="text-2xl font-bold">
                          {(result.text_analysis.confidence * 100).toFixed(0)}%
                        </p>
                      </div>
                    </div>
                  </Card>
                )}

                {/* Signal Detection Matrix */}
                {Object.keys(result.detected_signals).length > 0 && (
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
                              className={`text-xs ${
                                detected
                                  ? "text-red-600 dark:text-red-400"
                                  : "text-gray-500"
                              }`}
                            >
                              {detected ? "Detected" : "Not Detected"}
                            </p>
                          </div>
                        ),
                      )}
                    </div>
                  </Card>
                )}

                {/* Recommendations */}
                <Card className="p-8 border-2 bg-gradient-to-br from-green-50 to-blue-50 dark:from-green-950/20 dark:to-blue-950/20">
                  <h3 className="text-xl font-bold mb-4">
                    Recommended Actions
                  </h3>
                  <ul className="space-y-3">
                    {result.recommended_action.map((action, idx) => (
                      <li key={idx} className="flex items-start gap-3">
                        <Shield className="w-5 h-5 text-green-600 mt-0.5 flex-shrink-0" />
                        <span className="font-medium">{action}</span>
                      </li>
                    ))}
                  </ul>
                </Card>
              </>
            ) : (
              <Card className="p-8 border-2 text-center">
                <p className="text-lg text-muted-foreground">
                  No text was detected in the image. Please try another image
                  with visible text.
                </p>
              </Card>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
