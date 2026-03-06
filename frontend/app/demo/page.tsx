"use client";

import { useFraudStore } from "@/store/useFraudStore";
import { useRouter } from "next/navigation";
import {
  ShieldCheck,
  Zap,
  Lock,
  Brain,
  Database,
  AlignLeft,
  Mail,
  Paperclip,
  Loader2,
  ArrowRight,
  Search,
} from "lucide-react";
import React from "react";
import { motion } from "framer-motion";
import Link from "next/link";

export default function DemoHubPage() {
  const router = useRouter();
  const { fillDemoData } = useFraudStore();

  const handleDemo = (id: string) => {
    fillDemoData(id);
    router.push("/analyze");
  };

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

  return (
    <div className="relative min-h-screen">
      {/* Background Elements */}
      <div className="absolute inset-0 -z-10 overflow-hidden">
        <div className="absolute top-1/4 left-1/4 w-96 h-96 bg-gradient-to-br from-blue-500/20 to-purple-500/10 rounded-full blur-3xl animate-float"></div>
        <div
          className="absolute bottom-1/4 right-1/4 w-96 h-96 bg-gradient-to-br from-purple-500/20 to-pink-500/10 rounded-full blur-3xl animate-float"
          style={{ animationDelay: "2s" }}
        ></div>
      </div>

      <motion.div
        variants={container}
        initial="hidden"
        animate="show"
        className="max-w-6xl mx-auto space-y-16 py-16 px-4"
      >
        {/* Header */}
        <motion.div variants={item} className="text-center space-y-4">
          <div className="inline-flex items-center justify-center p-4 bg-gradient-to-br from-primary/20 to-secondary/20 rounded-2xl mb-4 border border-primary/30">
            <Brain className="w-8 h-8 text-transparent bg-clip-text bg-gradient-to-r from-blue-600 to-purple-600" />
          </div>
          <h1 className="text-6xl font-display font-bold tracking-tight gradient-text">
            Demo Hub
          </h1>
          <p className="text-xl text-muted-foreground max-w-2xl mx-auto">
            Explore the capabilities of{" "}
            <span className="text-primary font-bold">FraudGuard</span> with
            real-world fraud examples and live datasets.
          </p>
          <div className="pt-2">
            <Link
              href="https://www.google.com/search?q=latest+fraud+scam+patterns"
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-700 text-white text-sm font-semibold"
            >
              <Search className="w-4 h-4" />
              Compare with Google
            </Link>
          </div>
        </motion.div>

        {/* Demo Scenarios Section */}
        <motion.div variants={item} className="space-y-6">
          <div className="flex items-center gap-3 mb-8">
            <Zap className="w-6 h-6 text-primary" />
            <h2 className="text-3xl font-display font-bold">
              Try Demo Scenarios
            </h2>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <DemoCard
              title="Bank Phishing"
              desc="High-urgency banking alert scam with urgent tone"
              onClick={() => handleDemo("eval-1")}
              icon={<Lock className="w-6 h-6 text-danger" />}
              gradient="from-danger/10 to-red-500/5"
            />
            <DemoCard
              title="Delivery Scam"
              desc="Fake package delivery with suspicious tracking link"
              onClick={() => handleDemo("eval-2")}
              icon={<Zap className="w-6 h-6 text-warning" />}
              gradient="from-warning/10 to-yellow-500/5"
            />
            <DemoCard
              title="OTP Fraud"
              desc="Request for sensitive OTP with casual tone"
              onClick={() => handleDemo("eval-4")}
              icon={<ShieldCheck className="w-6 h-6 text-purple-500" />}
              gradient="from-purple-500/10 to-indigo-500/5"
            />
            <DemoCard
              title="Safe Message"
              desc="See how legitimate messages are handled"
              onClick={() => handleDemo("eval-5")}
              icon={<Brain className="w-6 h-6 text-safe" />}
              gradient="from-safe/10 to-green-500/5"
            />
          </div>
        </motion.div>

        {/* Live Dataset Explorer */}
        <motion.div
          variants={item}
          className="border-t border-border/40 pt-16 space-y-8"
        >
          <div className="flex items-center gap-3 mb-8">
            <Database className="w-6 h-6 text-primary" />
            <h2 className="text-3xl font-display font-bold">
              Live Dataset Explorer
            </h2>
          </div>

          <p className="text-lg text-muted-foreground max-w-2xl">
            Fetch real-world samples directly from our imported CSV datasets.
            Each click loads a random true or false fraud example.
          </p>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            <LiveDatasetCard
              title="Jobs Dataset"
              desc="Real & Fake Employment Postings"
              datasetType="jobs"
              icon={<AlignLeft className="w-5 h-5 text-sky-500" />}
              gradient="from-sky-500/10 to-cyan-500/5"
            />
            <LiveDatasetCard
              title="Spam Dataset"
              desc="Indian SMS Spam/Ham Messages"
              datasetType="spam"
              icon={<Mail className="w-5 h-5 text-slate-500" />}
              gradient="from-slate-500/10 to-zinc-500/5"
            />
            <LiveDatasetCard
              title="Phishing URLs"
              desc="Legitimate & Phishing Link DB"
              datasetType="phishing"
              icon={<Paperclip className="w-5 h-5 text-red-500" />}
              gradient="from-red-500/10 to-orange-500/5"
            />
          </div>
        </motion.div>

        {/* Features Grid */}
        <motion.div
          variants={item}
          className="border-t border-border/40 pt-16 space-y-8"
        >
          <h2 className="text-3xl font-display font-bold">Why FraudGuard?</h2>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            {[
              {
                title: "Explainable AI",
                desc: "Understand why content is flagged as fraud",
                icon: <Brain className="w-6 h-6" />,
              },
              {
                title: "Real-Time Detection",
                desc: "Identify threats in milliseconds",
                icon: <Zap className="w-6 h-6" />,
              },
              {
                title: "Multi-Modal Analysis",
                desc: "Analyzes text, tone, patterns, and signals",
                icon: <Database className="w-6 h-6" />,
              },
            ].map((feature, i) => (
              <motion.div
                key={i}
                variants={item}
                className="card-hover bg-gradient-to-br from-card via-card to-card/50 p-6 border border-border/50"
              >
                <div className="w-12 h-12 rounded-xl bg-primary/20 flex items-center justify-center text-primary mb-4">
                  {feature.icon}
                </div>
                <h3 className="font-bold text-lg mb-2">{feature.title}</h3>
                <p className="text-muted-foreground text-sm">{feature.desc}</p>
              </motion.div>
            ))}
          </div>
        </motion.div>

        {/* Trust Section */}
        <motion.div
          variants={item}
          className="border-t border-border/40 pt-16 text-center space-y-8"
        >
          <div>
            <h2 className="text-2xl font-display font-bold mb-2">
              Powered by Google Gemini
            </h2>
            <p className="text-muted-foreground">
              Enterprise-grade AI analysis with 99.8% accuracy
            </p>
          </div>
          <div className="flex flex-wrap justify-center gap-8">
            <div className="flex items-center gap-2 font-semibold">
              <ShieldCheck className="w-5 h-5 text-safe" />
              <span>Secure & Private</span>
            </div>
            <div className="flex items-center gap-2 font-semibold">
              <Zap className="w-5 h-5 text-primary" />
              <span>Lightning Fast</span>
            </div>
            <div className="flex items-center gap-2 font-semibold">
              <Brain className="w-5 h-5 text-secondary" />
              <span>AI-Powered</span>
            </div>
          </div>
        </motion.div>
      </motion.div>
    </div>
  );
}

function LiveDatasetCard({
  title,
  desc,
  datasetType,
  icon,
  gradient,
}: {
  title: string;
  desc: string;
  datasetType: string;
  icon: React.ReactNode;
  gradient: string;
}) {
  const router = useRouter();
  const { setInputText } = useFraudStore();
  const [loading, setLoading] = React.useState(false);

  const handleFetch = async () => {
    setLoading(true);
    try {
      const res = await fetch(
        `http://localhost:8000/api/v1/datasets/${datasetType}/sample`,
      );
      if (!res.ok) throw new Error("Failed to fetch");
      const data = await res.json();

      setInputText(data.text || JSON.stringify(data));
      router.push("/analyze");
    } catch (error) {
      console.error(error);
      alert("Ensure the Python backend is running on port 8000!");
    } finally {
      setLoading(false);
    }
  };

  return (
    <motion.button
      whileHover={{ scale: 1.02 }}
      onClick={handleFetch}
      disabled={loading}
      className={`card-hover relative bg-gradient-to-br ${gradient} p-8 rounded-2xl border border-border/50 text-left group overflow-hidden h-full transition-all disabled:opacity-50 disabled:cursor-not-allowed`}
    >
      <div className="absolute inset-0 opacity-0 group-hover:opacity-100 transition-opacity duration-500 bg-gradient-to-br from-primary/5 to-secondary/5 pointer-events-none"></div>
      <div className="relative z-10">
        <div className="w-12 h-12 rounded-xl bg-background/80 dark:bg-background/50 backdrop-blur border border-border/50 flex items-center justify-center mb-4 group-hover:scale-110 transition-transform">
          {loading ? (
            <Loader2 className="w-5 h-5 animate-spin text-primary" />
          ) : (
            icon
          )}
        </div>
        <h3 className="text-lg font-display font-bold mb-2">{title}</h3>
        <p className="text-muted-foreground text-sm mb-4">{desc}</p>
        <div className="flex items-center gap-2 text-sm text-primary font-semibold group-hover:translate-x-1 transition-transform">
          Load Sample <ArrowRight className="w-4 h-4" />
        </div>
      </div>
    </motion.button>
  );
}

function DemoCard({
  title,
  desc,
  onClick,
  icon,
  gradient,
}: {
  title: string;
  desc: string;
  onClick: () => void;
  icon: React.ReactNode;
  gradient: string;
}) {
  return (
    <motion.button
      whileHover={{ scale: 1.02 }}
      onClick={onClick}
      className={`card-hover relative bg-gradient-to-br ${gradient} p-8 rounded-2xl border border-border/50 text-left group overflow-hidden transition-all`}
    >
      <div className="absolute inset-0 opacity-0 group-hover:opacity-100 transition-opacity duration-500 bg-gradient-to-br from-primary/5 to-secondary/5 pointer-events-none"></div>
      <div className="relative z-10">
        <div className="w-12 h-12 rounded-xl bg-background/80 dark:bg-background/50 backdrop-blur border border-border/50 flex items-center justify-center mb-4 group-hover:scale-110 transition-transform">
          {icon}
        </div>
        <h3 className="text-lg font-display font-bold mb-2">{title}</h3>
        <p className="text-muted-foreground text-sm mb-4">{desc}</p>
        <div className="flex items-center gap-2 text-sm text-primary font-semibold group-hover:translate-x-1 transition-transform">
          Try Demo <ArrowRight className="w-4 h-4" />
        </div>
      </div>
    </motion.button>
  );
}
