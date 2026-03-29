import type { NextConfig } from 'next';

const nextConfig: NextConfig = {
  // Silence build warnings from Supabase realtime internals
  serverExternalPackages: ['ws'],

  // Vercel free tier: max function duration is 60s
  // The 300s values in vercel.json only work on Pro — keep them but they
  // won't error; Vercel just caps at 60s on free tier.
  async headers() {
    return [
      {
        source: '/api/:path*',
        headers: [
          { key: 'Access-Control-Allow-Origin', value: '*' },
          { key: 'Access-Control-Allow-Methods', value: 'GET, POST, OPTIONS' },
        ],
      },
    ];
  },

  // Suppress noisy build output
  typescript: {
    // We run tsc separately; don't fail the build on type errors
    // (remove this line if you want strict build-time type checking)
    ignoreBuildErrors: false,
  },

  eslint: {
    ignoreDuringBuilds: true,
  },
};

export default nextConfig;
