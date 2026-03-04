"use client"

import { useFraudStore } from '@/store/useFraudStore';
import { useRouter } from 'next/navigation';
import { ShieldCheck, Zap, Lock, Brain } from 'lucide-react';

export default function DemoHubPage() {
    const router = useRouter();
    const { fillDemoData } = useFraudStore();

    const handleDemo = (id: string) => {
        fillDemoData(id);
        router.push('/analyze');
    };

    return (
        <div className="max-w-4xl mx-auto space-y-12 py-10 animate-in zoom-in-95 duration-500">

            <div className="text-center space-y-4">
                <h1 className="text-5xl font-bold font-display tracking-tight">Judge Demo Hub</h1>
                <p className="text-xl text-muted-foreground max-w-2xl mx-auto">
                    Explore the capabilities of <span className="text-primary font-bold">FraudGuard</span> with dedicated test scenarios.
                </p>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <DemoCard
                    title="Bank Phishing"
                    desc="Simulate a high-urgency banking alert scam (Subtle)."
                    onClick={() => handleDemo('eval-1')}
                    icon={<Lock className="w-6 h-6 text-danger" />}
                    color="border-danger/20 hover:border-danger bg-red-50/50 dark:bg-red-900/10"
                />
                <DemoCard
                    title="Delivery Scam"
                    desc="Simulate a fake package delivery text."
                    onClick={() => handleDemo('eval-2')}
                    icon={<Zap className="w-6 h-6 text-warning" />}
                    color="border-warning/20 hover:border-warning bg-yellow-50/50 dark:bg-yellow-900/10"
                />
                <DemoCard
                    title="OTP Fraud"
                    desc="Simulate a request for sensitive OTP (Casual)."
                    onClick={() => handleDemo('eval-4')}
                    icon={<ShieldCheck className="w-6 h-6 text-purple-500" />}
                    color="border-purple-500/20 hover:border-purple-500 bg-purple-50/50 dark:bg-purple-900/10"
                />
                <DemoCard
                    title="Safe Message"
                    desc="See how a normal message is handled."
                    onClick={() => handleDemo('eval-5')}
                    icon={<Brain className="w-6 h-6 text-safe" />}
                    color="border-safe/20 hover:border-safe bg-green-50/50 dark:bg-green-900/10"
                />
            </div>

            {/* Trust Badges */}
            <div className="border-t border-border pt-10">
                <h3 className="text-center text-sm font-bold uppercase text-muted-foreground mb-6">Powered By</h3>
                <div className="flex flex-wrap justify-center gap-8 opacity-70 grayscale hover:grayscale-0 transition-all">
                    <span className="flex items-center gap-2 font-bold"><Brain className="w-5 h-5" /> Explainable AI</span>
                    <span className="flex items-center gap-2 font-bold"><Zap className="w-5 h-5" /> Real-Time Tone</span>
                    <span className="flex items-center gap-2 font-bold"><Lock className="w-5 h-5" /> Google Verified</span>
                </div>
            </div>

        </div>
    );
}

function DemoCard({ title, desc, onClick, icon, color }: any) {
    return (
        <button
            onClick={onClick}
            className={`p-6 rounded-2xl border text-left transition-all hover:scale-[1.02] hover:shadow-lg ${color}`}
        >
            <div className="bg-background w-12 h-12 rounded-full flex items-center justify-center mb-4 shadow-sm border border-border">
                {icon}
            </div>
            <h3 className="text-xl font-bold mb-1">{title}</h3>
            <p className="text-muted-foreground text-sm">{desc}</p>
        </button>
    )
}
