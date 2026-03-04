"use client"

import React from 'react';
import Link from 'next/link';
import { ArrowLeft, Clock, Search, ShieldCheck, AlertTriangle, FileText, Smartphone, Mail, Image as ImageIcon } from 'lucide-react';
import { Button } from '@/components/ui/button';

export default function UploadHistoryPage() {
    // Mock History Data for Demo
    const history = [
        {
            id: '1',
            type: 'image',
            summary: 'WhatsApp Screenshot.jpg',
            date: 'Just now',
            status: 'High Risk',
            icon: <ImageIcon className="w-4 h-4" />,
            riskColor: 'text-red-500'
        },
        {
            id: '2',
            type: 'text',
            summary: 'Dear customer, KYC pending...',
            date: '2 mins ago',
            status: 'Critical',
            icon: <Smartphone className="w-4 h-4" />,
            riskColor: 'text-red-600 font-bold'
        },
        {
            id: '3',
            type: 'email',
            summary: 'Subject: URGENT ACTION',
            date: '10 mins ago',
            status: 'Safe',
            icon: <Mail className="w-4 h-4" />,
            riskColor: 'text-green-500'
        },
        {
            id: '4',
            type: 'link',
            summary: 'http://sbi.co.in',
            date: '1 hour ago',
            status: 'Official Bank Link',
            icon: <ShieldCheck className="w-4 h-4" />,
            riskColor: 'text-green-600 font-bold'
        }
    ];

    return (
        <div className="max-w-4xl mx-auto space-y-8 animate-in fade-in duration-500 pb-12">
            <div className="flex items-center gap-4">
                <Link href="/" className="p-2 hover:bg-muted rounded-full">
                    <ArrowLeft className="w-6 h-6" />
                </Link>
                <div>
                    <h1 className="text-3xl font-bold font-display flex items-center gap-2">
                        <Clock className="w-8 h-8 text-primary" />
                        Analysis History
                    </h1>
                    <p className="text-muted-foreground">Audit trail of verified scan requests.</p>
                </div>
            </div>

            <div className="bg-card border border-border rounded-xl shadow-sm overflow-hidden">
                <div className="p-4 border-b border-border bg-muted/40 flex justify-between items-center">
                    <h3 className="font-bold flex items-center gap-2">
                        <Search className="w-4 h-4" /> Recent Scans
                    </h3>
                    <Button variant="outline" size="sm">Export Report</Button>
                </div>

                <div className="divide-y divide-border">
                    {history.map((item) => (
                        <div key={item.id} className="p-4 flex items-center justify-between hover:bg-muted/30 transition-colors group">
                            <div className="flex items-center gap-4">
                                <div className="p-2 bg-muted rounded-lg group-hover:bg-background transition-colors">
                                    {item.icon}
                                </div>
                                <div>
                                    <div className="font-medium">{item.summary}</div>
                                    <div className="text-xs text-muted-foreground">{item.date} • {item.type.toUpperCase()}</div>
                                </div>
                            </div>

                            <div className={`text-sm font-medium ${item.riskColor}`}>
                                {item.status}
                            </div>
                        </div>
                    ))}
                </div>
            </div>

            <div className="text-center">
                <p className="text-muted-foreground text-sm">History is stored locally and cleared on session end for privacy.</p>
            </div>
        </div>
    );
}
