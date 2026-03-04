"use client"

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { ShieldCheck } from 'lucide-react';
import { ThemeToggle } from '@/components/ui/ThemeToggle';
import { LanguageToggle } from '@/components/ui/LanguageToggle';
import { cn } from '@/lib/utils';

export function Navbar() {
    const pathname = usePathname();

    const navItems = [
        { name: 'Analyze', href: '/analyze' },
        { name: 'Email Verifier', href: '/email-analysis' },
        { name: 'Image Forensics', href: '/image-analysis' },
        { name: 'Results', href: '/results' },
        { name: 'Compare', href: '/analyze/compare' },
        { name: 'Demo', href: '/demo' },
    ];

    return (
        <nav className="border-b border-border bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60 sticky top-0 z-50">
            <div className="container flex h-16 items-center justify-between">

                {/* Logo */}
                <Link href="/" className="flex items-center gap-2 font-display text-xl font-bold hover:opacity-80 transition-opacity mr-4">
                    <ShieldCheck className="h-6 w-6 text-safe" />
                    <span className="hidden sm:inline-block">Fraud<span className="text-primary">Guard</span></span>
                </Link>

                {/* Desktop Nav Links */}
                <div className="hidden md:flex items-center gap-1">
                    {navItems.map((item) => (
                        <Link
                            key={item.href}
                            href={item.href}
                            className={cn(
                                "px-3 py-1.5 rounded-md text-sm font-medium transition-colors hover:bg-muted",
                                pathname === item.href ? "bg-muted text-primary" : "text-muted-foreground"
                            )}
                        >
                            {item.name}
                        </Link>
                    ))}
                </div>

                {/* Global Controls */}
                <div className="flex items-center gap-3">
                    <LanguageToggle />
                    <div className="w-px h-6 bg-border mx-1"></div>
                    <ThemeToggle />
                </div>
            </div>
        </nav>
    );
}
