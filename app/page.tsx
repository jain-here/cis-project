'use client';

import { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { supabase } from '@/lib/supabase';
import { formatDate } from '@/lib/utils';
import { riskLevelColor } from '@/lib/scoring';
import { DebugPanel } from '@/components/DebugPanel';
import type { Scan, RiskLevel } from '@/types';

export default function HomePage() {
  const router = useRouter();
  const [url, setUrl] = useState('');
  const [url2, setUrl2] = useState('');
  const [compare, setCompare] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [recentScans, setRecentScans] = useState<Scan[]>([]);

  useEffect(() => {
    supabase
      .from('scans')
      .select('*')
      .order('created_at', { ascending: false })
      .limit(5)
      .then(({ data }) => {
        if (data) setRecentScans(data as Scan[]);
      });
  }, []);

  async function handleScan(e: React.FormEvent) {
    e.preventDefault();
    if (!url.trim()) return;
    setError('');
    setLoading(true);

    console.log('[HOME] Starting scan request for:', url.trim());

    try {
      const res = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: url.trim() }),
      });
      const data = await res.json();
      console.log('[HOME] Scan response:', { status: res.status, data });
      if (!res.ok || !data.scanId) throw new Error(data.error || 'Scan failed');
      console.log('[HOME] Scan created successfully, navigating to:', data.scanId);
      router.push(`/scan/${data.scanId}`);
    } catch (err: any) {
      console.error('[HOME] Scan error:', err);
      setError(err.message);
      setLoading(false);
    }
  }

  const riskBadge = (level: RiskLevel | null) => {
    const color = riskLevelColor(level);
    return (
      <span
        className="text-xs font-semibold px-2 py-0.5 rounded"
        style={{ color, backgroundColor: `${color}20`, border: `1px solid ${color}40` }}
      >
        {level ? level.toUpperCase() : 'PENDING'}
      </span>
    );
  };

  return (
    <div className="min-h-[calc(100vh-65px)] flex flex-col">
      {/* Hero */}
      <div className="flex-1 flex flex-col items-center justify-center px-4 py-20">
        {/* Glow */}
        <div className="absolute inset-0 overflow-hidden pointer-events-none">
          <div className="absolute top-1/4 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[600px] h-[300px] bg-cyan-500/10 rounded-full blur-3xl" />
        </div>

        <div className="relative z-10 text-center mb-10">
          <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full border border-cyan-500/30 bg-cyan-500/10 text-cyan-400 text-xs font-medium mb-6">
            <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-pulse" />
            Cloud Vulnerability Intelligence Platform
          </div>
          <h1 className="text-5xl sm:text-7xl font-black tracking-tighter text-white mb-4">
            Secure<span className="text-cyan-400">Scan</span>
          </h1>
          <p className="text-slate-400 text-lg max-w-md mx-auto">
            Instant security analysis. SSL grades, header audits, DNS records, CVE lookups — all in one scan.
          </p>
        </div>

        {/* Scan form */}
        <div className="relative z-10 w-full max-w-xl">
          <form onSubmit={handleScan} className="space-y-3">
            <div className="flex gap-2">
              <input
                type="text"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                placeholder="Enter domain or URL (e.g. example.com)"
                className="flex-1 bg-white/5 border border-white/10 rounded-xl px-4 py-3 text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500/50 focus:bg-white/8 transition-all text-sm"
                disabled={loading}
              />
              <button
                type="submit"
                disabled={loading || !url.trim()}
                className="px-6 py-3 bg-cyan-500 hover:bg-cyan-400 disabled:bg-slate-700 disabled:text-slate-500 text-black font-bold rounded-xl transition-all text-sm whitespace-nowrap"
              >
                {loading ? 'Scanning…' : 'Scan →'}
              </button>
            </div>

            {compare && (
              <div className="flex gap-2">
                <input
                  type="text"
                  value={url2}
                  onChange={(e) => setUrl2(e.target.value)}
                  placeholder="Second domain to compare"
                  className="flex-1 bg-white/5 border border-white/10 rounded-xl px-4 py-3 text-white placeholder-slate-500 focus:outline-none focus:border-purple-500/50 transition-all text-sm"
                />
                <button
                  type="button"
                  onClick={() => router.push(`/compare?d1=${encodeURIComponent(url)}&d2=${encodeURIComponent(url2)}`)}
                  disabled={!url.trim() || !url2.trim()}
                  className="px-4 py-3 bg-purple-500/20 border border-purple-500/30 text-purple-300 hover:bg-purple-500/30 disabled:opacity-40 font-bold rounded-xl transition-all text-sm"
                >
                  Compare →
                </button>
              </div>
            )}

            <button
              type="button"
              onClick={() => setCompare(!compare)}
              className="text-xs text-slate-500 hover:text-slate-300 transition-colors"
            >
              {compare ? '− Hide comparison' : '+ Compare two domains'}
            </button>
          </form>

          {error && (
            <div className="mt-3 px-4 py-3 rounded-xl bg-red-500/10 border border-red-500/30 text-red-400 text-sm">
              {error}
            </div>
          )}
        </div>

        {/* Feature badges */}
        <div className="relative z-10 flex flex-wrap gap-2 justify-center mt-10">
          {['SSL/TLS Grade', 'Security Headers', 'DNS Records', 'CVE Lookup', 'Risk Score'].map((f) => (
            <span key={f} className="text-xs px-3 py-1.5 rounded-full border border-white/10 bg-white/5 text-slate-400">
              {f}
            </span>
          ))}
        </div>
      </div>

      {/* Recent scans */}
      {recentScans.length > 0 && (
        <div className="max-w-4xl mx-auto w-full px-4 pb-16">
          <h2 className="text-xs font-semibold uppercase tracking-widest text-slate-500 mb-4">
            Recent Scans
          </h2>
          <div className="rounded-2xl border border-white/5 bg-white/3 overflow-hidden">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-white/5">
                  <th className="text-left px-5 py-3 text-slate-500 font-medium">Domain</th>
                  <th className="text-left px-5 py-3 text-slate-500 font-medium">Score</th>
                  <th className="text-left px-5 py-3 text-slate-500 font-medium">Risk</th>
                  <th className="text-left px-5 py-3 text-slate-500 font-medium">Date</th>
                  <th className="px-5 py-3" />
                </tr>
              </thead>
              <tbody>
                {recentScans.map((scan) => (
                  <tr
                    key={scan.id}
                    className="border-b border-white/5 last:border-0 hover:bg-white/3 transition-colors"
                  >
                    <td className="px-5 py-3 font-mono text-cyan-400 text-xs">{scan.domain}</td>
                    <td className="px-5 py-3 text-white font-bold">
                      {scan.overall_score ?? '—'}
                    </td>
                    <td className="px-5 py-3">{riskBadge(scan.risk_level)}</td>
                    <td className="px-5 py-3 text-slate-500">{formatDate(scan.created_at)}</td>
                    <td className="px-5 py-3 text-right">
                      <a
                        href={`/scan/${scan.id}`}
                        className="text-xs text-cyan-500 hover:text-cyan-300 transition-colors"
                      >
                        View →
                      </a>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
      <DebugPanel />
    </div>
  );
}
