"use client"

import { motion } from 'framer-motion';

interface RiskMeterProps {
    score: number;
    level: string;
}

export function RiskMeter({ score, level }: RiskMeterProps) {
    const getColor = (level: string) => {
        switch (level) {
            case 'CRITICAL': return 'text-danger shadow-[0_0_20px_rgba(255,50,50,0.5)]';
            case 'HIGH': return 'text-warning shadow-[0_0_20px_rgba(255,200,0,0.5)]';
            default: return 'text-safe shadow-[0_0_20px_rgba(50,255,50,0.5)]';
        }
    };

    const getBorderColor = (level: string) => {
        switch (level) {
            case 'CRITICAL': return 'border-danger';
            case 'HIGH': return 'border-warning';
            default: return 'border-safe';
        }
    };

    return (
        <div className="relative flex items-center justify-center">
            <div className={`w-48 h-48 rounded-full border-8 ${getBorderColor(level)} flex flex-col items-center justify-center bg-card transition-all duration-500`}>
                <motion.span
                    initial={{ opacity: 0, scale: 0.5 }}
                    animate={{ opacity: 1, scale: 1 }}
                    transition={{ duration: 0.5 }}
                    className={`text-6xl font-bold ${getColor(level)?.split(' ')[0]}`}
                >
                    {score}
                </motion.span>
                <span className="text-sm font-semibold uppercase tracking-wider text-muted-foreground mt-1">Risk Score</span>
            </div>

            {/* Animated Pulse Ring */}
            <div className={`absolute inset-0 rounded-full border-4 ${getBorderColor(level)} opacity-20 animate-ping`} />
        </div>
    );
}
