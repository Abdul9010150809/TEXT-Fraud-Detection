"use client"

import * as React from "react"
import { Languages } from "lucide-react"
import { useFraudStore } from "@/store/useFraudStore"

export function LanguageToggle() {
    const { language, setLanguage } = useFraudStore()

    return (
        <button
            onClick={() => setLanguage(language === 'en' ? 'hi' : 'en')}
            className="flex items-center gap-2 px-3 py-1.5 rounded-full border border-border hover:bg-muted transition-colors text-sm font-medium"
            title="Toggle Language"
        >
            <Languages className="w-4 h-4" />
            <span>{language === 'en' ? 'EN' : 'HI'}</span>
        </button>
    )
}
