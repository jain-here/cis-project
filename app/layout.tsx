import type { Metadata } from 'next';
import { Inter, JetBrains_Mono } from 'next/font/google';
import './globals.css';

const inter = Inter({
  subsets: ['latin'],
  variable: '--font-inter',
});

const jetbrains = JetBrains_Mono({
  subsets: ['latin'],
  variable: '--font-mono',
});

export const metadata: Metadata = {
  title: 'SecureScan — Cloud Vulnerability Intelligence',
  description: 'Scan any domain for security vulnerabilities, SSL issues, DNS misconfigurations, and known CVEs.',
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className={`${inter.variable} ${jetbrains.variable}`}>
      <body className="bg-[#0f172a] text-slate-100 antialiased font-sans min-h-screen">
        <nav className="border-b border-white/5 px-6 py-4">
          <div className="max-w-6xl mx-auto flex items-center justify-between">
            <a href="/" className="flex items-center gap-2">
              <div className="w-7 h-7 rounded-lg bg-gradient-to-br from-cyan-400 to-blue-600 flex items-center justify-center">
                <span className="text-xs font-bold text-white">S</span>
              </div>
              <span className="font-bold text-white tracking-tight">SecureScan</span>
            </a>
            <div className="flex items-center gap-6 text-sm text-slate-400">
              <a href="/" className="hover:text-white transition-colors">Scan</a>
              <a href="/compare" className="hover:text-white transition-colors">Compare</a>
              <a href="/schedule" className="hover:text-white transition-colors">Schedule</a>
              <a href="/dashboard" className="hover:text-white transition-colors">Dashboard</a>
            </div>
          </div>
        </nav>
        <main>{children}</main>
      </body>
    </html>
  );
}
