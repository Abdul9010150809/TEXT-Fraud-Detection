import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  /* config options here */
  reactStrictMode: true,
  images: {
    domains: [],
    unoptimized: true,
  },
  // Enable experimental features for better performance
  experimental: {
    optimizePackageImports: ['lucide-react', 'recharts', 'framer-motion'],
  },
  // TypeScript path aliases
  typescript: {
    ignoreBuildErrors: false,
  },

  // Transpile packages
  transpilePackages: [],
};

export default nextConfig;
