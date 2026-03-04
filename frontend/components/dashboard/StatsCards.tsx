import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Activity, ShieldCheck, ShieldAlert, Users } from "lucide-react";

export function StatsCards() {
    const stats = [
        { title: "Messages Analyzed", value: "12,450", icon: Activity, change: "+12% today" },
        { title: "Threats Blocked", value: "1,203", icon: ShieldAlert, change: "+5% today", alert: true },
        { title: "Safe Transactions", value: "11,142", icon: ShieldCheck, change: "+98% accuracy" },
        { title: "Active Users", value: "542", icon: Users, change: "+20% this week" },
    ];

    return (
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
            {stats.map((stat, i) => (
                <Card key={i}>
                    <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                        <CardTitle className="text-sm font-medium">
                            {stat.title}
                        </CardTitle>
                        <stat.icon className={`h-4 w-4 ${stat.alert ? 'text-fraud-500' : 'text-muted-foreground'}`} />
                    </CardHeader>
                    <CardContent>
                        <div className="text-2xl font-bold">{stat.value}</div>
                        <p className="text-xs text-muted-foreground">
                            {stat.change}
                        </p>
                    </CardContent>
                </Card>
            ))}
        </div>
    );
}
