'use client';

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip, Legend } from 'recharts';

const data = [
    { name: 'Safe', value: 75, color: '#10b981' },
    { name: 'Phishing', value: 15, color: '#f59e0b' },
    { name: 'Scam', value: 5, color: '#ef4444' },
    { name: 'Malware', value: 5, color: '#7c3aed' },
];

export function RiskDistributionChart() {
    return (
        <Card className="col-span-4 lg:col-span-3">
            <CardHeader>
                <CardTitle>Risk Distribution</CardTitle>
            </CardHeader>
            <CardContent>
                <ResponsiveContainer width="100%" height={300}>
                    <PieChart>
                        <Pie
                            data={data}
                            cx="50%"
                            cy="50%"
                            innerRadius={60}
                            outerRadius={80}
                            paddingAngle={5}
                            dataKey="value"
                        >
                            {data.map((entry, index) => (
                                <Cell key={`cell-${index}`} fill={entry.color} />
                            ))}
                        </Pie>
                        <Tooltip />
                        <Legend verticalAlign="bottom" height={36} />
                    </PieChart>
                </ResponsiveContainer>
            </CardContent>
        </Card>
    );
}
