import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { CheckCircle2, XCircle } from "lucide-react";

interface ExplanationSectionProps {
    whyFraud: string[];
    whyNotFraud: string[];
}

export function ExplanationSection({ whyFraud, whyNotFraud }: ExplanationSectionProps) {
    return (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <Card className="border-l-4 border-l-fraud-500">
                <CardHeader>
                    <CardTitle className="text-lg text-fraud-600 flex items-center gap-2">
                        <XCircle className="w-5 h-5" /> Why it&apos;s Fraud
                    </CardTitle>
                </CardHeader>
                <CardContent>
                    {whyFraud.length === 0 ? (
                        <p className="text-sm text-muted-foreground italic">No fraud indicators found.</p>
                    ) : (
                        <ul className="space-y-2">
                            {whyFraud.map((reason, i) => (
                                <li key={i} className="flex gap-2 text-sm text-foreground/90">
                                    <span className="text-fraud-500 font-bold">•</span> {reason}
                                </li>
                            ))}
                        </ul>
                    )}
                </CardContent>
            </Card>

            <Card className="border-l-4 border-l-safe-500">
                <CardHeader>
                    <CardTitle className="text-lg text-safe-600 flex items-center gap-2">
                        <CheckCircle2 className="w-5 h-5" /> Why it seems Safe
                    </CardTitle>
                </CardHeader>
                <CardContent>
                    {whyNotFraud.length === 0 ? (
                        <p className="text-sm text-muted-foreground italic">No positive trust signals found.</p>
                    ) : (
                        <ul className="space-y-2">
                            {whyNotFraud.map((reason, i) => (
                                <li key={i} className="flex gap-2 text-sm text-foreground/90">
                                    <span className="text-safe-500 font-bold">•</span> {reason}
                                </li>
                            ))}
                        </ul>
                    )}
                </CardContent>
            </Card>
        </div>
    );
}
