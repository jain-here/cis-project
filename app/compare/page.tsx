'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { riskLevelColor } from '@/lib/scoring';
import { RiskGauge } from '@/components/RiskGauge';
import { SeverityChart } from '@/components/SeverityChart';
import type { Scan, Finding, CVEResult, Severity, SeverityCount, RiskLevel } from '@/types';
import { supabase } from '@/lib/supabase';
import { formatDate } from '@/lib/utils';

const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

function SeverityBadge({ severity }: { severity: Severity }) {
  const colors: Record<Severity, string> = {
    critical: 'bg-red-500/20 text-red-400 border-red-500/30',
    high: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
    medium: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
    low: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
    info: 'bg-slate-500/20 text-slate-400 border-slate-500/30',
  };
  return (
    <span className={`text-xs font-semibold px-2 py-0.5 rounded border ${colors[severity]}`}>
      {severity.toUpperCase()}
    </span>
  );
}

interface DomainData {
  scan: Scan;
  findings: Finding[];
  cves: CVEResult[];
}

async function fetchLatestScanForDomain(domain: string): Promise<DomainData | null> {
  const { data: scan } = await supabase
    .from('scans')
    .select('*')
    .eq('domain', domain)
    .eq('status', 'completed')
    .order('created_at', { ascending: false })
    .limit(1)
    .single();

  if (!scan) return null;

  const [{ data: findings }, { data: cves }] = await Promise.all([
    supabase.from('findings').select('*').eq('scan_id', scan.id),
    supabase.from('cve_results').select('*').eq('scan_id', scan.id).order('cvss_score', { ascending: false }),
  ]);

  return {
    scan: scan as Scan,
    findings: (findings || []) as Finding[],
    cves: (cves || []) as CVEResult[],
  };
}

function DomainColumn({
  data,
  winner,
}: {
  data: DomainData;
  winner: boolean;
}) {
  const { scan, findings, cves } = data;
  const color = riskLevelColor(scan.risk_level);

  const severityCounts: SeverityCount[] = SEVERITY_ORDER.map((sev) => ({
    severity: sev,
    count: findings.filter((f) => f.severity === sev).length,
  }));

  return (
    <div
      className={`flex-1 rounded-2xl border p-6 space-y-6 ${
        winner ? 'border-green-500/30 bg-green-500/5' : 'border-white/10 bg-white/5'
      }`}
    >
      {winner && (
        <div className="text-xs font-bold text-green-400 text-center bg-green-500/10 border border-green-500/20 rounded-full py-1">
          ✓ MORE SECURE
        </div>
      )}

      {/* Domain + score */}
      <div className="text-center">
        <h2 className="text-xl font-black font-mono text-white mb-1">{scan.domain}</h2>
        <p className="text-xs text-slate-500 mb-4">{formatDate(scan.created_at)}</p>
        <RiskGauge score={scan.overall_score ?? 0} riskLevel={scan.risk_level} size={160} />
      </div>

      {/* Risk level */}
      <div className="text-center">
        <span
          className="text-sm font-bold px-4 py-1.5 rounded-lg"
          style={{ color, backgroundColor: `${color}20`, border: `1px solid ${color}40` }}
        >
          {(scan.risk_level ?? 'unknown').toUpperCase()} RISK
        </span>
      </div>

      {/* Stats grid */}
      <div className="grid grid-cols-2 gap-2 text-center text-sm">
        <div className="rounded-xl bg-black/20 p-3">
          <div className="text-2xl font-black text-white">{findings.length}</div>
          <div className="text-xs text-slate-500">Findings</div>
        </div>
        <div className="rounded-xl bg-black/20 p-3">
          <div className="text-2xl font-black text-white">{cves.length}</div>
          <div className="text-xs text-slate-500">CVEs</div>
        </div>
        <div className="rounded-xl bg-black/20 p-3">
          <div className="text-2xl font-black" style={{ color: '#ef4444' }}>
            {findings.filter((f) => f.severity === 'critical').length}
          </div>
          <div className="text-xs text-slate-500">Critical</div>
        </div>
        <div className="rounded-xl bg-black/20 p-3">
          <div className="text-xl font-bold text-blue-300">{scan.ssl_grade ?? '—'}</div>
          <div className="text-xs text-slate-500">SSL Grade</div>
        </div>
      </div>

      {/* Severity chart */}
      <div>
        <div className="text-xs text-slate-500 uppercase tracking-widest mb-2">Findings Breakdown</div>
        <SeverityChart data={severityCounts} />
      </div>

      {/* Top findings */}
      <div>
        <div className="text-xs text-slate-500 uppercase tracking-widest mb-2">Top Issues</div>
        <div className="space-y-2">
          {findings
            .sort((a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity))
            .slice(0, 5)
            .map((f) => (
              <div key={f.id} className="flex items-start gap-2 p-2 rounded-lg bg-black/20">
                <SeverityBadge severity={f.severity} />
                <span className="text-xs text-slate-300">{f.title}</span>
              </div>
            ))}
          {findings.length === 0 && (
            <p className="text-xs text-green-400">✓ No findings</p>
          )}
        </div>
      </div>

      <a
        href={`/scan/${scan.id}`}
        className="block text-center text-xs text-cyan-500 hover:text-cyan-300 transition-colors pt-2 border-t border-white/5"
      >
        View full report →
      </a>
    </div>
  );
}

export default function ComparePage() {
  const [domain1, setDomain1] = useState('');
  const [domain2, setDomain2] = useState('');
  const [data1, setData1] = useState<DomainData | null>(null);
  const [data2, setData2] = useState<DomainData | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  async function handleCompare(e: React.FormEvent) {
    e.preventDefault();
    if (!domain1.trim() || !domain2.trim()) return;
    setError('');
    setLoading(true);
    setData1(null);
    setData2(null);

    try {
      const clean1 = domain1.trim().replace(/^https?:\/\/(www\.)?/, '').split('/')[0];
      const clean2 = domain2.trim().replace(/^https?:\/\/(www\.)?/, '').split('/')[0];

      const [result1, result2] = await Promise.all([
        fetchLatestScanForDomain(clean1),
        fetchLatestScanForDomain(clean2),
      ]);

      if (!result1) {
        setError(`No completed scan found for "${clean1}". Scan it first.`);
        setLoading(false);
        return;
      }
      if (!result2) {
        setError(`No completed scan found for "${clean2}". Scan it first.`);
        setLoading(false);
        return;
      }

      setData1(result1);
      setData2(result2);
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  const winner =
    data1 && data2
      ? (data1.scan.overall_score ?? 0) >= (data2.scan.overall_score ?? 0)
        ? 'left'
        : 'right'
      : null;

  return (
    <div className="max-w-6xl mx-auto px-4 py-10">
      <div className="mb-8">
        <h1 className="text-2xl font-black text-white">Compare Domains</h1>
        <p className="text-sm text-slate-500 mt-1">
          Side-by-side security comparison of two domains
        </p>
      </div>

      {/* Input form */}
      <form onSubmit={handleCompare} className="flex gap-3 mb-8 flex-wrap">
        <input
          type="text"
          value={domain1}
          onChange={(e) => setDomain1(e.target.value)}
          placeholder="First domain (e.g. github.com)"
          className="flex-1 min-w-[200px] bg-white/5 border border-white/10 rounded-xl px-4 py-3 text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500/50 text-sm"
        />
        <div className="flex items-center text-slate-600 font-bold text-sm">vs</div>
        <input
          type="text"
          value={domain2}
          onChange={(e) => setDomain2(e.target.value)}
          placeholder="Second domain (e.g. gitlab.com)"
          className="flex-1 min-w-[200px] bg-white/5 border border-white/10 rounded-xl px-4 py-3 text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500/50 text-sm"
        />
        <button
          type="submit"
          disabled={loading || !domain1.trim() || !domain2.trim()}
          className="px-6 py-3 bg-cyan-500 hover:bg-cyan-400 disabled:bg-slate-700 disabled:text-slate-500 text-black font-bold rounded-xl transition-all text-sm"
        >
          {loading ? 'Loading…' : 'Compare'}
        </button>
      </form>

      {error && (
        <div className="mb-6 px-4 py-3 rounded-xl bg-red-500/10 border border-red-500/30 text-red-400 text-sm">
          {error}{' '}
          <a href="/" className="text-cyan-400 hover:text-cyan-300 underline">
            Start a new scan →
          </a>
        </div>
      )}

      {/* Comparison columns */}
      {data1 && data2 && (
        <>
          {/* Score delta banner */}
          <div className="rounded-2xl border border-white/10 bg-white/5 p-4 mb-6 text-center">
            <div className="text-sm text-slate-400">
              <span className="font-mono font-bold text-white">{data1.scan.domain}</span>
              <span
                className="mx-2 text-lg font-black"
                style={{
                  color:
                    (data1.scan.overall_score ?? 0) > (data2.scan.overall_score ?? 0)
                      ? '#22c55e'
                      : '#ef4444',
                }}
              >
                {data1.scan.overall_score ?? 0}
              </span>
              <span className="text-slate-600">vs</span>
              <span
                className="mx-2 text-lg font-black"
                style={{
                  color:
                    (data2.scan.overall_score ?? 0) > (data1.scan.overall_score ?? 0)
                      ? '#22c55e'
                      : '#ef4444',
                }}
              >
                {data2.scan.overall_score ?? 0}
              </span>
              <span className="font-mono font-bold text-white">{data2.scan.domain}</span>
            </div>
            <div className="text-xs text-slate-500 mt-1">
              Score difference:{' '}
              <span className="font-bold text-white">
                {Math.abs((data1.scan.overall_score ?? 0) - (data2.scan.overall_score ?? 0))} points
              </span>
            </div>
          </div>

          <div className="flex gap-4 flex-col md:flex-row">
            <DomainColumn data={data1} winner={winner === 'left'} />
            <DomainColumn data={data2} winner={winner === 'right'} />
          </div>
        </>
      )}

      {!data1 && !data2 && !loading && !error && (
        <div className="text-center py-16 text-slate-600">
          <div className="text-4xl mb-3">⚔️</div>
          <p className="text-sm">Enter two domains to compare their security posture.</p>
          <p className="text-xs mt-1">Both domains must have been scanned previously.</p>
        </div>
      )}
    </div>
  );
}
