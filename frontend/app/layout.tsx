import type { Metadata } from "next";
import { Inter, Outfit } from "next/font/google";
import "./globals.css";
import { Navbar } from "@/components/navigation/Navbar";
import { ThemeProvider } from "@/components/ui/theme-provider";

const inter = Inter({ subsets: ["latin"], variable: "--font-inter" });
const outfit = Outfit({ subsets: ["latin"], variable: "--font-outfit" });

export const metadata: Metadata = {
  title: "AI Fraud Detection Engine",
  description: "Advanced AI-powered fraud detection demo",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body className={`${inter.variable} ${outfit.variable} font-sans`}>
        <ThemeProvider
          attribute="class"
          defaultTheme="system"
          enableSystem
          disableTransitionOnChange
        >
          <div className="min-h-screen flex flex-col bg-background text-foreground">
            <Navbar />
            <main className="flex-1 container mx-auto px-4 py-8">
              {children}
            </main>
            <footer className="border-t border-border py-6 text-center text-sm text-muted-foreground bg-muted/20">
              <p>© 2026 AI Fraud Detection Engine. Hackathon Demo.</p>
              <p className="text-xs mt-1 opacity-70">Powered by Gemini & Next.js</p>
            </footer>
          </div>
        </ThemeProvider>
      </body>
    </html>
  );
}
