import { FraudTypeConfidence } from "@/types";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

interface ConfidenceBarsProps {
    types: FraudTypeConfidence[];
    confidence: number;
}

export function ConfidenceBars({ types, confidence }: ConfidenceBarsProps) {
    return (
        <Card>
            <CardHeader>
                <CardTitle className="text-lg">AI Confidence Analysis</CardTitle>
            </CardHeader>
            <CardContent className="space-y-6">
                <div className="space-y-2">
                    <div className="flex justify-between text-sm font-medium">
                        <span>Overall Model Confidence</span>
                        <span>{confidence}%</span>
                    </div>
                    <div className="h-2 w-full bg-secondary rounded-full overflow-hidden">
                        <div
                            className="h-full bg-primary transition-all duration-1000"
                            style={{ width: `${confidence}%` }}
                        />
                    </div>
                </div>

                <div className="space-y-4">
                    <p className="text-sm font-medium text-muted-foreground">Classified Fraud Types</p>
                    {types.length === 0 ? (
                        <p className="text-sm text-safe-600">No specific fraud types detected.</p>
                    ) : (
                        types.map((type, idx) => (
                            <div key={idx} className="space-y-1">
                                <div className="flex justify-between text-sm">
                                    <span>{type.type}</span>
                                    <span className="text-muted-foreground">{type.confidence}%</span>
                                </div>
                                <div className="h-1.5 w-full bg-secondary rounded-full overflow-hidden">
                                    <div
                                        className="h-full bg-fraud-500 transition-all duration-1000"
                                        style={{ width: `${type.confidence}%` }}
                                    />
                                </div>
                            </div>
                        ))
                    )}
                </div>
            </CardContent>
        </Card>
    );
}
