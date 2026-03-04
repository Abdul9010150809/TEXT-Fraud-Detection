'use client';

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';

const data = [
    { name: 'Mon', safe: 4000, fraud: 240 },
    { name: 'Tue', safe: 3000, fraud: 139 },
    { name: 'Wed', safe: 2000, fraud: 980 },
    { name: 'Thu', safe: 2780, fraud: 390 },
    { name: 'Fri', safe: 1890, fraud: 480 },
    { name: 'Sat', safe: 2390, fraud: 380 },
    { name: 'Sun', safe: 3490, fraud: 430 },
];

export function FraudTrendChart() {
    return (
        <Card className="col-span-4">
            <CardHeader>
                <CardTitle>Analysis Trend (7 Days)</CardTitle>
            </CardHeader>
            <CardContent className="pl-2">
                <ResponsiveContainer width="100%" height={350}>
                    <LineChart data={data}>
                        <CartesianGrid strokeDasharray="3 3" className="stroke-muted" />
                        <XAxis dataKey="name" fontSize={12} tickLine={false} axisLine={false} />
                        <YAxis fontSize={12} tickLine={false} axisLine={false} tickFormatter={(value) => `${value}`} />
                        <Tooltip
                            contentStyle={{ backgroundColor: 'var(--background)', border: '1px solid var(--border)' }}
                            itemStyle={{ color: 'var(--foreground)' }}
                        />
                        <Line type="monotone" dataKey="safe" stroke="#10b981" strokeWidth={2} activeDot={{ r: 8 }} />
                        <Line type="monotone" dataKey="fraud" stroke="#ef4444" strokeWidth={2} />
                    </LineChart>
                </ResponsiveContainer>
            </CardContent>
        </Card>
    );
}
