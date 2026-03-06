"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { ShieldCheck } from "lucide-react";
import { ThemeToggle } from "@/components/ui/ThemeToggle";
import { cn } from "@/lib/utils";

export function Navbar() {
  const pathname = usePathname();

  const navItems = [
    { name: "Text", href: "/analyze" },
    { name: "Link", href: "/analyze/link" },
    { name: "Email", href: "/analyze/email" },
    { name: "Image", href: "/analyze/image" },
    { name: "Compare", href: "/analyze/compare" },
    { name: "Results", href: "/results" },
    { name: "Demo", href: "/demo" },
  ];

  return (
    <nav className="sticky top-0 z-50 w-full">
      {/* Gradient Background */}
      <div className="absolute inset-0 bg-gradient-to-b from-background/95 to-background/70 dark:from-background/90 dark:to-background/50 backdrop-blur-xl border-b border-border/40"></div>

      <div className="relative container flex h-16 items-center justify-between px-4">
        {/* Logo with Custom SVG */}
        <Link
          href="/"
          className="group flex items-center gap-3 font-display text-xl font-bold hover:opacity-80 transition-opacity"
        >
          <div className="relative">
            <div className="absolute inset-0 bg-gradient-to-r from-blue-600 to-purple-600 rounded-xl blur-lg opacity-75 group-hover:opacity-100 transition-opacity"></div>
            <div className="relative bg-background dark:bg-slate-900 rounded-xl p-2.5 border border-blue-500/30">
              {/* Custom Shield with F Logo */}
              <svg
                width="28"
                height="28"
                viewBox="0 0 24 24"
                fill="none"
                xmlns="http://www.w3.org/2000/svg"
                className="relative z-10"
              >
                <path
                  d="M12 2L4 6V11C4 16 7 20.5 12 22C17 20.5 20 16 20 11V6L12 2Z"
                  fill="url(#gradShield)"
                  stroke="url(#gradStroke)"
                  strokeWidth="1.5"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                />
                <text
                  x="12"
                  y="16"
                  fontSize="12"
                  fontWeight="bold"
                  fill="white"
                  textAnchor="middle"
                  fontFamily="system-ui"
                >
                  F
                </text>
                <defs>
                  <linearGradient id="gradShield" x1="4" y1="2" x2="20" y2="22">
                    <stop offset="0%" stopColor="#3b82f6" stopOpacity="0.9" />
                    <stop offset="100%" stopColor="#8b5cf6" stopOpacity="0.9" />
                  </linearGradient>
                  <linearGradient id="gradStroke" x1="4" y1="2" x2="20" y2="22">
                    <stop offset="0%" stopColor="#60a5fa" />
                    <stop offset="100%" stopColor="#a78bfa" />
                  </linearGradient>
                </defs>
              </svg>
            </div>
          </div>
          <div className="flex flex-col leading-tight">
            <span className="hidden sm:inline-block text-transparent bg-clip-text bg-gradient-to-r from-blue-600 via-purple-600 to-blue-600">
              Fraud<span className="font-extrabold">Guard</span>
            </span>
            <span className="hidden sm:inline-block text-[10px] text-muted-foreground font-normal tracking-wider">
              AI FRAUD DETECTOR
            </span>
          </div>
        </Link>

        {/* Desktop Nav Links - Enhanced */}
        <div className="hidden md:flex items-center gap-1 flex-1 justify-center mx-8">
          {navItems.map((item) => {
            const isActive = pathname === item.href;
            return (
              <Link
                key={item.href}
                href={item.href}
                className={cn(
                  "px-4 py-2 rounded-lg text-sm font-medium transition-all duration-300 relative group",
                  isActive
                    ? "bg-gradient-to-r from-blue-500/20 to-purple-500/20 text-primary border border-primary/30"
                    : "text-muted-foreground hover:text-foreground",
                )}
              >
                {item.name}
                {isActive && (
                  <div className="absolute inset-0 bg-gradient-to-r from-blue-600/10 to-purple-600/10 rounded-lg -z-10 blur-md"></div>
                )}
                {!isActive && (
                  <div className="absolute inset-0 bg-muted rounded-lg opacity-0 group-hover:opacity-50 transition-opacity -z-10"></div>
                )}
              </Link>
            );
          })}
        </div>

        {/* Global Controls */}
        <div className="flex items-center gap-4">
          <ThemeToggle />
        </div>
      </div>

      {/* Bottom border glow effect */}
      <div className="absolute bottom-0 left-0 right-0 h-px bg-gradient-to-r from-transparent via-primary/50 to-transparent opacity-50"></div>
    </nav>
  );
}
