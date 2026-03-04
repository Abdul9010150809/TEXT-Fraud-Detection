import type { Config } from "tailwindcss";

const config: Config = {
    darkMode: ["class"],
    content: [
        "./pages/**/*.{js,ts,jsx,tsx,mdx}",
        "./components/**/*.{js,ts,jsx,tsx,mdx}",
        "./app/**/*.{js,ts,jsx,tsx,mdx}",
    ],
    theme: {
        extend: {
            colors: {
                background: "var(--background)",
                foreground: "var(--foreground)",
                border: "var(--border)",

                // Semantic Colors for Risk Levels
                safe: {
                    DEFAULT: "var(--safe)",
                    foreground: "var(--safe-foreground)",
                },
                warning: {
                    DEFAULT: "var(--warning)",
                    foreground: "var(--warning-foreground)",
                },
                danger: {
                    DEFAULT: "var(--danger)",
                    foreground: "var(--danger-foreground)",
                },
            },
            fontFamily: {
                sans: ["var(--font-inter)", "sans-serif"],
                display: ["var(--font-outfit)", "sans-serif"],
            },
        },
        container: {
            center: true,
            padding: '2rem',
            screens: {
                '2xl': '1400px',
            },
        },
    },
    plugins: [],
};
export default config;
