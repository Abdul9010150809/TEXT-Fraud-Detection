import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Globe, Lock, CornerDownRight, ShieldCheck, ShieldAlert } from "lucide-react";
import { cn } from "@/lib/utils";

interface LinkIntelProps {
    data?: {
        url: string;
        domain: string;
        domainAge: string;
        hasSsl: boolean;
        redirectCount: number;
        isMasked: boolean;
        reputation: 'CLEAN' | 'SUSPICIOUS' | 'MALICIOUS';
    };
}

export function LinkIntelligence({ data }: LinkIntelProps) {
    if (!data) return null;

    return (
        <Card>
            <CardHeader>
                <CardTitle className="text-lg flex items-center gap-2">
                    <Globe className="w-5 h-5 text-brand-600" />
                    Link Intelligence
                </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
                <div className="bg-muted p-2 rounded text-xs font-mono break-all border">
                    {data.url}
                </div>

                <div className="grid grid-cols-2 gap-4">
                    <div className="space-y-1">
                        <p className="text-xs text-muted-foreground uppercase font-bold">Domain Age</p>
                        <p className="font-semibold">{data.domainAge}</p>
                    </div>
                    <div className="space-y-1">
                        <p className="text-xs text-muted-foreground uppercase font-bold">SSL Security</p>
                        <div className="flex items-center gap-1">
                            {data.hasSsl ? <Lock className="w-4 h-4 text-safe-500" /> : <Lock className="w-4 h-4 text-fraud-500" />}
                            <span className={data.hasSsl ? "text-safe-600" : "text-fraud-600"}>
                                {data.hasSsl ? "Secure (HTTPS)" : "Insecure (HTTP)"}
                            </span>
                        </div>
                    </div>
                    <div className="space-y-1">
                        <p className="text-xs text-muted-foreground uppercase font-bold">Redirects</p>
                        <div className="flex items-center gap-1">
                            <CornerDownRight className="w-4 h-4 text-muted-foreground" />
                            <span>{data.redirectCount} hops</span>
                        </div>
                    </div>
                    <div className="space-y-1">
                        <p className="text-xs text-muted-foreground uppercase font-bold">Reputation</p>
                        <div className={cn(
                            "inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-bold",
                            data.reputation === 'CLEAN' ? "bg-safe-100 text-safe-700" :
                                data.reputation === 'MALICIOUS' ? "bg-fraud-100 text-fraud-700" : "bg-warning-100 text-warning-700"
                        )}>
                            {data.reputation === 'CLEAN' ? <ShieldCheck className="w-3 h-3" /> : <ShieldAlert className="w-3 h-3" />}
                            {data.reputation}
                        </div>
                    </div>
                </div>
            </CardContent>
        </Card>
    );
}
