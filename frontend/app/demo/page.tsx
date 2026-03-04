"use client"

import { useFraudStore } from '@/store/useFraudStore';
import { useRouter } from 'next/navigation';
import { ShieldCheck, Zap, Lock, Brain, Database, AlignLeft, Mail, Paperclip, Loader2 } from 'lucide-react';
import React from 'react';
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

            {/* Live Dataset Explorer */}
            <div className="border-t border-border pt-10">
                <div className="text-center space-y-2 mb-8">
                    <h2 className="text-3xl font-bold flex items-center justify-center gap-2">
                        <Database className="w-6 h-6 text-primary" />
                        Live Dataset Explorer
                    </h2>
                    <p className="text-muted-foreground text-sm max-w-xl mx-auto">
                        Fetch real-world raw samples directly from our imported CSV datasets.
                    </p>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                    <LiveDatasetCard
                        title="Jobs Dataset"
                        desc="Real & Fake Employment Postings"
                        datasetType="jobs"
                        icon={<AlignLeft className="w-5 h-5 text-sky-500" />}
                        color="border-sky-500/20 hover:border-sky-500 bg-sky-50/50 dark:bg-sky-900/10"
                    />
                    <LiveDatasetCard
                        title="Spam Dataset"
                        desc="Indian SMS Spam/Ham Messages"
                        datasetType="spam"
                        icon={<Mail className="w-5 h-5 text-slate-500" />}
                        color="border-slate-500/20 hover:border-slate-500 bg-slate-50/50 dark:bg-slate-900/10"
                    />
                    <LiveDatasetCard
                        title="Phishing URLs"
                        desc="Legitimate & Phishing Link DB"
                        datasetType="phishing"
                        icon={<Paperclip className="w-5 h-5 text-red-500" />}
                        color="border-red-500/20 hover:border-red-500 bg-red-50/50 dark:bg-red-900/10"
                    />
                </div>
            </div>

            {/* Trust Badges */}
            <div className="border-t border-border pt-10">
                <h3 className="text-center text-sm font-bold uppercase text-muted-foreground mb-6">Powered By Gemini</h3>
                <div className="flex flex-wrap justify-center gap-8 opacity-70 grayscale hover:grayscale-0 transition-all">
                    <span className="flex items-center gap-2 font-bold"><Brain className="w-5 h-5" /> Explainable AI</span>
                    <span className="flex items-center gap-2 font-bold"><Zap className="w-5 h-5" /> Real-Time Tone</span>
                    <span className="flex items-center gap-2 font-bold"><Lock className="w-5 h-5" /> Google Verified</span>
                </div>
            </div>

        </div>
    );
}

function LiveDatasetCard({ title, desc, datasetType, icon, color }: { title: string, desc: string, datasetType: string, icon: React.ReactNode, color: string }) {
    const router = useRouter();
    const { setInputText } = useFraudStore();
    const [loading, setLoading] = React.useState(false);

    const handleFetch = async () => {
        setLoading(true);
        try {
            const res = await fetch(`http://localhost:8000/api/v1/datasets/${datasetType}/sample`);
            if (!res.ok) throw new Error("Failed to fetch");
            const data = await res.json();

            setInputText(data.text || JSON.stringify(data));
            router.push('/analyze');
        } catch (error) {
            console.error(error);
            alert("Ensure the Python backend is running on port 8000!");
        } finally {
            setLoading(false);
        }
    };

    return (
        <button
            onClick={handleFetch}
            disabled={loading}
            className={`p-6 rounded-2xl border text-left transition-all hover:scale-[1.02] hover:shadow-lg ${color} ${loading ? 'opacity-50 cursor-not-allowed' : ''}`}
        >
            <div className="bg-background w-10 h-10 rounded-full flex items-center justify-center mb-4 shadow-sm border border-border">
                {loading ? <Loader2 className="w-4 h-4 animate-spin text-primary" /> : icon}
            </div>
            <h3 className="text-lg font-bold mb-1">{title}</h3>
            <p className="text-muted-foreground text-xs">{desc}</p>
        </button>
    )
}

function DemoCard({ title, desc, onClick, icon, color }: { title: string, desc: string, onClick: () => void, icon: React.ReactNode, color: string }) {
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
