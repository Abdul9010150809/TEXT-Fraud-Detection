import { FraudSignal } from "@/types";
import { AlertTriangle, Shield, Globe, Zap, FileText } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { cn } from "@/lib/utils";

interface SignalMatrixProps {
    signals: FraudSignal[];
}

const getIcon = (category: string) => {
    switch (category) {
        case 'URL': return Globe;
        case 'BEHAVIOR': return Zap;
        case 'TECHNICAL': return AlertTriangle;
        default: return FileText;
    }
};

export function SignalMatrix({ signals }: SignalMatrixProps) {
    return (
        <Card className="h-full">
            <CardHeader>
                <CardTitle className="text-lg flex items-center gap-2">
                    <Shield className="w-5 h-5 text-primary" />
                    Signal Matrix
                </CardTitle>
            </CardHeader>
            <CardContent className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                {signals.map((signal) => {
                    const Icon = getIcon(signal.category);
                    return (
                        <div
                            key={signal.id}
                            className={cn(
                                "p-3 rounded-lg border flex items-start gap-3 transition-colors",
                                signal.detected
                                    ? "bg-red-50/50 border-red-100 text-red-900 dark:bg-red-950/20 dark:border-red-900/50 dark:text-red-200"
                                    : "bg-green-50/50 border-green-100 text-green-900 dark:bg-green-950/20 dark:border-green-900/50 dark:text-green-200"
                            )}
                        >
                            <div className={cn(
                                "p-1.5 rounded-full shrink-0 mt-0.5",
                                signal.detected ? "bg-red-100 text-red-600 dark:bg-red-900 dark:text-red-400" : "bg-green-100 text-green-600 dark:bg-green-900 dark:text-green-400"
                            )}>
                                <Icon className="w-4 h-4" />
                            </div>
                            <div>
                                <div className="flex items-center gap-2">
                                    <span className="font-semibold text-sm">{signal.name}</span>
                                    {signal.detected && (
                                        <span className="text-[10px] bg-red-200 dark:bg-red-800 px-1.5 py-0.5 rounded-sm font-mono font-bold">
                                            +{signal.score}
                                        </span>
                                    )}
                                </div>
                                <p className="text-xs opacity-90 mt-1 leading-snug">
                                    {signal.description}
                                </p>
                            </div>
                        </div>
                    );
                })}
            </CardContent>
        </Card>
    );
}
