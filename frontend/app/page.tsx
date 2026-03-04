import Link from "next/link";
import { Button } from "@/components/ui/button";
import { ShieldAlert, BrainCircuit, Lock, ArrowRight } from "lucide-react";

export default function Home() {
  return (
    <div className="flex flex-col items-center justify-center space-y-12 py-10">

      {/* Hero Header */}
      <div className="text-center space-y-4 max-w-3xl">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-blue-100 dark:bg-blue-900/30 text-blue-700 dark:text-blue-300 text-xs font-semibold uppercase tracking-wider mb-4">
          <BrainCircuit className="w-4 h-4" />
          AI-Powered Security
        </div>
        <h1 className="text-4xl sm:text-6xl font-display font-bold tracking-tight text-foreground">
          Detect Fraud <br className="hidden sm:block" />
          <span className="text-transparent bg-clip-text bg-gradient-to-r from-blue-600 to-purple-600">Before It Happens</span>
        </h1>
        <p className="text-xl text-muted-foreground max-w-2xl mx-auto">
          Advanced AI analysis to identify scams, phishing, and manipulative language in real-time.
        </p>
      </div>

      {/* Main Analysis Component */}
      <div className="w-full max-w-3xl relative z-10">
        <div className="flex flex-col sm:flex-row gap-4 justify-center">
          <Link href="/analyze">
            <Button size="lg" className="text-lg px-8 h-12 rounded-full shadow-lg hover:shadow-xl transition-all">
              Start Analysis <ArrowRight className="ml-2 w-5 h-5" />
            </Button>
          </Link>
          <Link href="/demo">
            <Button variant="outline" size="lg" className="text-lg px-8 h-12 rounded-full">
              Try Demo Scenarios
            </Button>
          </Link>
        </div>

        {/* Background Decorative Blur */}
        <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-full h-full bg-blue-500/10 dark:bg-blue-500/20 blur-3xl -z-10 rounded-full scale-110 pointer-events-none" />
      </div>

      {/* Feature Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-8 w-full max-w-5xl mt-12">
        <FeatureCard
          icon={<ShieldAlert className="w-8 h-8 text-danger" />}
          title="Phishing Detection"
          description="Instantly identifies suspicious domains and urgent language patterns used by attackers."
        />
        <FeatureCard
          icon={<BrainCircuit className="w-8 h-8 text-warning" />}
          title="AI Content Analysis"
          description="Distinguishes between human conversation and AI-generated script attacks."
        />
        <FeatureCard
          icon={<Lock className="w-8 h-8 text-safe" />}
          title="Secure & Private"
          description="Analyze text locally or securely via API. No data is stored permanently."
        />
      </div>

    </div>
  );
}

function FeatureCard({ icon, title, description }: { icon: React.ReactNode, title: string, description: string }) {
  return (
    <div className="bg-card border border-border p-6 rounded-xl shadow-sm hover:shadow-md transition-shadow text-center flex flex-col items-center">
      <div className="mb-4 bg-muted/50 p-3 rounded-full">{icon}</div>
      <h3 className="font-bold text-lg mb-2">{title}</h3>
      <p className="text-muted-foreground text-sm">{description}</p>
    </div>
  );
}
