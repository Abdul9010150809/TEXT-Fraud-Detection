import { Card, CardContent } from "@/components/ui/card";
import { CheckCircle2, Circle, ArrowRight, Server, Globe, Search, Shield } from "lucide-react";

export default function TimelinePage() {
    const steps = [
        {
            id: 1,
            title: "Ingestion",
            desc: "Raw text/URL input received via API Gateway",
            icon: Server,
            status: "complete",
            time: "0ms"
        },
        {
            id: 2,
            title: "Text Analysis",
            desc: "NLP Processing for semantics & urgency detection",
            icon: Search,
            status: "complete",
            time: "+150ms"
        },
        {
            id: 3,
            title: "Link Expansion",
            desc: "Resolving shortlinks and checking domain age",
            icon: Globe,
            status: "complete",
            time: "+400ms"
        },
        {
            id: 4,
            title: "Fusion Engine",
            desc: "Aggregating 50+ signals for final scoring",
            icon: Shield,
            status: "complete",
            time: "+600ms"
        }
    ];

    return (
        <div className="max-w-4xl mx-auto py-12 space-y-12 animate-slide-up">
            <div className="text-center space-y-2">
                <h1 className="text-3xl font-bold">Analysis Timeline Logic</h1>
                <p className="text-muted-foreground">Visualizing the millisecond-level decision flow of the AI Engine</p>
            </div>

            <div className="relative">
                <div className="absolute left-1/2 h-full w-0.5 bg-border -translate-x-1/2 hidden md:block" />

                <div className="space-y-12">
                    {steps.map((step, idx) => (
                        <div key={step.id} className={`flex flex-col md:flex-row items-center gap-8 ${idx % 2 === 0 ? 'md:flex-row-reverse' : ''}`}>
                            <div className="flex-1 w-full">
                                <Card className="transform transition-all hover:scale-105 hover:shadow-lg">
                                    <CardContent className="p-6">
                                        <div className="flex items-center justify-between mb-2">
                                            <div className="flex items-center gap-2 text-primary font-bold">
                                                <step.icon className="w-5 h-5" />
                                                {step.title}
                                            </div>
                                            <span className="text-xs font-mono bg-secondary px-2 py-1 rounded">{step.time}</span>
                                        </div>
                                        <p className="text-sm text-muted-foreground">{step.desc}</p>
                                    </CardContent>
                                </Card>
                            </div>

                            <div className="bg-primary text-primary-foreground w-8 h-8 rounded-full flex items-center justify-center z-10 font-bold shrink-0">
                                {step.id}
                            </div>

                            <div className="flex-1 w-full hidden md:block text-center text-sm text-muted-foreground">
                                {idx % 2 === 0 ? (
                                    <div className="flex items-center justify-end gap-2 pr-8">
                                        Input Processing <ArrowRight className="w-4 h-4" />
                                    </div>
                                ) : (
                                    <div className="flex items-center gap-2 pl-8">
                                        <ArrowRight className="w-4 h-4" /> Signal Pass
                                    </div>
                                )}
                            </div>
                        </div>
                    ))}
                </div>
            </div>
        </div>
    );
}
