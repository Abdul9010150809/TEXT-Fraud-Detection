# 🛡️ AI Fraud Detector (FraudGuard)
> **Multi-Modal AI Intelligence for Prevention of Digital Scams**

![License](https://img.shields.io/badge/License-MIT-blue.svg)
![Status](https://img.shields.io/badge/Status-Production%20Ready-green.svg)
![Tech](https://img.shields.io/badge/Tech-Next.js%20%7C%20Gemini%20AI%20%7C%20Python-indigo.svg)

**FraudGuard** is a state-of-the-art AI system designed to detect, analyze, and explain digital fraud across multiple modalities: **Text, Images, Links, and Emails**. Unlike traditional rule-based systems, it uses Google's **Gemini 1.5 Pro/Flash** to "reason" about fraud, understanding context, detecting visual manipulation, and verifying sender identity.

---

## 🌟 Key Features

### 1. 📧 Deep Email Forensics
*   **Identity Verification**: Cross-checks the "Claimed Identity" (e.g., "We are PayPal") against the actual **Sender Address**.
*   **Spoofing Detection**: Instantly flags generic domains (Gmail/Outlook) used for official business.
*   **Psychological Analysis**: Detects urgency triggers and panic-inducing language in subject lines.

### 2. 📸 Visual Fraud Detection
*   **Safe Image Calibration**: Our *Calibrated AI* distinguishes between a scam screenshot and a harmless family photo.
*   **Manipulation Check**: Detects bad Photoshop jobs, fake text overlays, and stolen branding usage.

### 3. 🏦 Bank & Typosquatting Guard
*   **Link Verification**: Checks for subtle domain typos (e.g., `hdfkbank.com` vs `hdfcbank.com`).
*   **Official Registry**: Cross-references against a known list of official banking domains.

### 4. 🧠 Explainable AI (XAI)
*   **No Black Box**: Every verdict comes with a natural language explanation (`Why it is Risky` vs `What would make it Safe`).
*   **Signal Matrix**: A breakdown of specific signals (Urgency, Impersonation, OTP Request, etc.).

---

## 🏗️ Tech Stack

*   **Frontend**: Next.js 14+ (App Router), TailwindCSS, Framer Motion (Cinematic UI).
*   **AI Engine**: Google Gemini 1.5 (Multimodal Vision & Text), In-Context Learning (Few-Shot).
*   **Backend Support**: Python (FastAPI) for advanced data fusion (optional/fallback).
*   **Dataset**: Custom datasets (`spam_texts.csv`) injected for pattern matching.

---

## 🚀 Getting Started

### Prerequisites
*   Node.js 18+
*   npm
*   Google Gemini API Key

### Installation

1.  **Clone the Repo**
    ```bash
    git clone https://github.com/Abdul9010150809/AI-Fraud-detect.git
    cd AI-Fraud-detect
    ```

2.  **Install Frontend Dependencies**
    ```bash
    cd frontend
    npm install
    # Install legacy peer deps if needed
    npm install --legacy-peer-deps
    ```

3.  **Environment Setup**
    Create a `.env.local` file in `/frontend`:
    ```bash
    NEXT_PUBLIC_GEMINI_API_KEY=your_gemini_key_here
    ```

4.  **Run the App**
    ```bash
    npm run dev
    ```
    Visit `http://localhost:3000`

---

## 🕹️ Demo Workflows

### Scenario A: The "Fake PayPal" Email
1.  Go to **/email-analysis**.
2.  Enter Sender: `support-team@gmail.com`
3.  Enter Body: "Your account is limited. Click here to restore."
4.  **Result**: 🔴 **Sender Mismatch**. The AI knows PayPal doesn't use Gmail.

### Scenario B: The "Lottery" Screenshot
1.  Go to **/image-analysis**.
2.  Upload `scam_lottery_winner.png`.
3.  **Result**: 🔴 **Visual Fraud**. Text overlay analysis confirms it's a fake template.

---

## 🤝 Contributing
We welcome contributions! Please fork the repo and submit a PR.

---

## 📄 License
MIT License. Built for the AI Hackathon 2026.