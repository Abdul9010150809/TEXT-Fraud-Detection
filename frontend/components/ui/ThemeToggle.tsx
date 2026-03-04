"use client"

import * as React from "react"
import { Moon, Sun, Monitor } from "lucide-react"
import { useTheme } from "next-themes"

export function ThemeToggle() {
    const { setTheme, theme } = useTheme()
    const [mounted, setMounted] = React.useState(false)

    React.useEffect(() => {
        setMounted(true)
    }, [])

    if (!mounted) {
        return (
            <div className="flex items-center gap-2 p-1 border rounded-full bg-background border-border">
                <div className="p-2 rounded-full opacity-50"><Sun className="h-4 w-4" /></div>
                <div className="p-2 rounded-full opacity-50"><Moon className="h-4 w-4" /></div>
                <div className="p-2 rounded-full opacity-50"><Monitor className="h-4 w-4" /></div>
            </div>
        )
    }

    return (
        <div className="flex items-center gap-2 p-1 border rounded-full bg-background border-border">
            <button
                onClick={() => setTheme("light")}
                className={`p-2 rounded-full transition-all ${theme === "light" ? "bg-foreground text-background" : "text-foreground opacity-50 hover:opacity-100"
                    }`}
                aria-label="Light Mode"
            >
                <Sun className="h-4 w-4" />
            </button>
            <button
                onClick={() => setTheme("dark")}
                className={`p-2 rounded-full transition-all ${theme === "dark" ? "bg-foreground text-background" : "text-foreground opacity-50 hover:opacity-100"
                    }`}
                aria-label="Dark Mode"
            >
                <Moon className="h-4 w-4" />
            </button>
            <button
                onClick={() => setTheme("system")}
                className={`p-2 rounded-full transition-all ${theme === "system" ? "bg-foreground text-background" : "text-foreground opacity-50 hover:opacity-100"
                    }`}
                aria-label="System Theme"
            >
                <Monitor className="h-4 w-4" />
            </button>
        </div>
    )
}
