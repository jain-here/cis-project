'use client';

import { useEffect, useState } from 'react';
import { supabase } from '@/lib/supabase';
import { riskLevelColor } from '@/lib/scoring';
import { formatDate } from '@/lib/utils';
import { SeverityChart } from '@/components/SeverityChart';
import { ScanTimeline } from '@/components/ScanTimeline';
import type { Scan, Finding, Severity, SeverityCount, ScoreHistory, RiskLevel } from '@/types';

const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

function RiskBadge({ level }: { level: RiskLevel | null }) {
  const color = riskLevelColor(level);
  return (
    <span
      className="text-xs font-semibold px-2 py-0.5 rounded"
      style={{ color, backgroundColor: `${color}20`, border: `1px solid ${color}40` }}
    >
      {level ? level.toUpperCase() : '—'}
    </span>
  );
}

function StatCard({ label, value, sub }: { label: string; value: string | number; sub?: string }) {
  return (
    <div className="rounded-2xl border border-white/10 bg-white/5 p-5">
      <div className="text-xs text-slate-500 uppercase tracking-widest mb-1">{label}</div>
      <div className="text-3xl font-black text-white">{value}</div>
      {sub && <div className="text-xs text-slate-500 mt-1">{sub}</div>}
    </div>
  );
}

export default function DashboardPage() {
  const [scans, setScans] = useState<Scan[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(true);
  const [domainFilter, setDomainFilter] = useState('');
  const [selectedDomain, setSelectedDomain] = useState<string>('');

  useEffect(() => {
    async function fetchAll() {
      const [scansRes, findingsRes] = await Promise.all([
        supabase
          .from('scans')
          .select('*')
          .order('created_at', { ascending: false })
          .limit(100),
        supabase
          .from('findings')
          .select('*')
          .order('severity'),
      ]);

      if (scansRes.data) setScans(scansRes.data as Scan[]);
      if (findingsRes.data) setFindings(findingsRes.data as Finding[]);
      setLoading(false);
    }
    fetchAll();
  }, []);

  const completedScans = scans.filter((s) => s.status === 'completed');
  const avgScore =
    completedScans.length > 0
      ? Math.round(completedScans.reduce((s, c) => s + (c.overall_score ?? 0), 0) / completedScans.length)
      : 0;

  const criticalCount = scans.filter((s) => s.risk_level === 'critical').length;
  const uniqueDomains = [...new Set(scans.map((s) => s.domain))];

  // Severity breakdown across all findings
  const severityCounts: SeverityCount[] = SEVERITY_ORDER.map((sev) => ({
    severity: sev,
    count: findings.filter((f) => f.severity === sev).length,
  }));

  // Timeline for selected domain
  const timelineDomain = selectedDomain || (uniqueDomains[0] ?? '');
  const timelineData: ScoreHistory[] = scans
    .filter((s) => s.domain === timelineDomain && s.overall_score !== null && s.status === 'completed')
    .sort((a, b) => new Date(a.created_at).getTime() - new Date(b.created_at).getTime())
    .map((s) => ({
      date: s.created_at,
      score: s.overall_score!,
      domain: s.domain,
    }));

  // Filtered scans for table
  const filteredScans = scans.filter((s) =>
    domainFilter ? s.domain.toLowerCase().includes(domainFilter.toLowerCase()) : true
  );

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-[60vh]">
        <div className="text-slate-500 text-sm animate-pulse">Loading dashboard…</div>
      </div>
    );
  }

  return (
    <div className="max-w-6xl mx-auto px-4 py-10">
      {/* Header */}
      <div className="flex items-center justify-between mb-8">
        <div>
          <h1 className="text-2xl font-black text-white">Dashboard</h1>
          <p className="text-sm text-slate-500 mt-1">Security scan history and trends</p>
        </div>
        <a
          href="/"
          className="text-sm px-4 py-2 rounded-xl bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 hover:bg-cyan-500/30 transition-colors"
        >
          + New Scan
        </a>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-8">
        <StatCard label="Total Scans" value={scans.length} />
        <StatCard label="Avg Score" value={avgScore} sub="across completed scans" />
        <StatCard label="Critical Domains" value={criticalCount} sub="risk level: critical" />
        <StatCard label="Unique Domains" value={uniqueDomains.length} />
      </div>

      {/* Charts row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 mb-8">
        {/* Severity breakdown */}
        <div className="rounded-2xl border border-white/10 bg-white/5 p-6">
          <h2 className="text-xs font-semibold text-slate-400 uppercase tracking-widest mb-4">
            Findings by Severity
          </h2>
          <SeverityChart data={severityCounts} />
        </div>

        {/* Score timeline */}
        <div className="rounded-2xl border border-white/10 bg-white/5 p-6">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-xs font-semibold text-slate-400 uppercase tracking-widest">
              Score Timeline
            </h2>
            {uniqueDomains.length > 1 && (
              <select
                value={timelineDomain}
                onChange={(e) => setSelectedDomain(e.target.value)}
                className="text-xs bg-white/5 border border-white/10 rounded-lg px-2 py-1 text-slate-300 focus:outline-none focus:border-cyan-500/50"
              >
                {uniqueDomains.map((d) => (
                  <option key={d} value={d} className="bg-slate-900">
                    {d}
                  </option>
                ))}
              </select>
            )}
          </div>
          <ScanTimeline data={timelineData} />
        </div>
      </div>

      {/* Risk distribution */}
      <div className="grid grid-cols-4 gap-3 mb-8">
        {(['critical', 'high', 'medium', 'low'] as RiskLevel[]).map((level) => {
          const count = scans.filter((s) => s.risk_level === level).length;
          const color = riskLevelColor(level);
          return (
            <div
              key={level}
              className="rounded-xl border p-4 text-center"
              style={{ borderColor: `${color}30`, backgroundColor: `${color}10` }}
            >
              <div className="text-2xl font-black" style={{ color }}>{count}</div>
              <div className="text-xs font-semibold mt-1" style={{ color: `${color}cc` }}>
                {level.toUpperCase()}
              </div>
            </div>
          );
        })}
      </div>

      {/* Scans table */}
      <div className="rounded-2xl border border-white/10 bg-white/5 overflow-hidden">
        <div className="flex items-center justify-between px-5 py-4 border-b border-white/5">
          <h2 className="text-xs font-semibold text-slate-400 uppercase tracking-widest">
            Scan History ({filteredScans.length})
          </h2>
          <input
            type="text"
            placeholder="Filter by domain…"
            value={domainFilter}
            onChange={(e) => setDomainFilter(e.target.value)}
            className="text-xs bg-white/5 border border-white/10 rounded-lg px-3 py-1.5 text-slate-300 placeholder-slate-600 focus:outline-none focus:border-cyan-500/50 w-48"
          />
        </div>

        {filteredScans.length === 0 ? (
          <div className="px-5 py-10 text-center text-slate-500 text-sm">
            No scans found.{' '}
            <a href="/" className="text-cyan-500 hover:text-cyan-300 transition-colors">
              Start your first scan →
            </a>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-white/5">
                  <th className="text-left px-5 py-3 text-slate-500 font-medium">Domain</th>
                  <th className="text-left px-5 py-3 text-slate-500 font-medium">Score</th>
                  <th className="text-left px-5 py-3 text-slate-500 font-medium">Risk</th>
                  <th className="text-left px-5 py-3 text-slate-500 font-medium">SSL</th>
                  <th className="text-left px-5 py-3 text-slate-500 font-medium">Status</th>
                  <th className="text-left px-5 py-3 text-slate-500 font-medium">Date</th>
                  <th className="px-5 py-3" />
                </tr>
              </thead>
              <tbody>
                {filteredScans.map((scan) => (
                  <tr
                    key={scan.id}
                    className="border-b border-white/5 last:border-0 hover:bg-white/3 transition-colors"
                  >
                    <td className="px-5 py-3 font-mono text-cyan-400 text-xs">{scan.domain}</td>
                    <td className="px-5 py-3">
                      {scan.overall_score !== null ? (
                        <span
                          className="font-bold text-sm"
                          style={{ color: riskLevelColor(scan.risk_level) }}
                        >
                          {scan.overall_score}
                        </span>
                      ) : (
                        <span className="text-slate-600">—</span>
                      )}
                    </td>
                    <td className="px-5 py-3">
                      <RiskBadge level={scan.risk_level} />
                    </td>
                    <td className="px-5 py-3">
                      {scan.ssl_grade ? (
                        <span className="text-xs font-mono font-bold text-blue-300">{scan.ssl_grade}</span>
                      ) : (
                        <span className="text-slate-600 text-xs">—</span>
                      )}
                    </td>
                    <td className="px-5 py-3">
                      <span
                        className={`text-xs px-2 py-0.5 rounded-full border font-medium ${
                          scan.status === 'completed'
                            ? 'bg-green-500/10 text-green-400 border-green-500/30'
                            : scan.status === 'partial'
                            ? 'bg-yellow-500/10 text-yellow-400 border-yellow-500/30'
                            : scan.status === 'running'
                            ? 'bg-cyan-500/10 text-cyan-400 border-cyan-500/30 animate-pulse'
                            : scan.status === 'failed'
                            ? 'bg-red-500/10 text-red-400 border-red-500/30'
                            : 'bg-slate-500/10 text-slate-400 border-slate-500/30'
                        }`}
                      >
                        {scan.status}
                      </span>
                    </td>
                    <td className="px-5 py-3 text-slate-500 text-xs">{formatDate(scan.created_at)}</td>
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
        )}
      </div>

      {/* Findings breakdown by domain */}
      {uniqueDomains.length > 0 && (
        <div className="mt-8">
          <h2 className="text-xs font-semibold text-slate-400 uppercase tracking-widest mb-4">
            Top Vulnerable Domains
          </h2>
          <div className="space-y-2">
            {uniqueDomains
              .map((domain) => {
                const domainScans = completedScans.filter((s) => s.domain === domain);
                const latest = domainScans[0];
                const domainFindings = findings.filter((f) =>
                  domainScans.some((s) => s.id === f.scan_id)
                );
                const criticalCount = domainFindings.filter((f) => f.severity === 'critical').length;
                const highCount = domainFindings.filter((f) => f.severity === 'high').length;
                return { domain, latest, criticalCount, highCount, total: domainFindings.length };
              })
              .sort((a, b) => b.criticalCount - a.criticalCount || b.highCount - a.highCount)
              .slice(0, 10)
              .map(({ domain, latest, criticalCount, highCount, total }) => (
                <div
                  key={domain}
                  className="flex items-center gap-4 px-4 py-3 rounded-xl border border-white/5 bg-white/3 hover:bg-white/5 transition-colors"
                >
                  <span className="font-mono text-sm text-cyan-400 flex-1">{domain}</span>
                  {criticalCount > 0 && (
                    <span className="text-xs bg-red-500/20 text-red-400 border border-red-500/30 px-2 py-0.5 rounded">
                      {criticalCount} critical
                    </span>
                  )}
                  {highCount > 0 && (
                    <span className="text-xs bg-orange-500/20 text-orange-400 border border-orange-500/30 px-2 py-0.5 rounded">
                      {highCount} high
                    </span>
                  )}
                  <span className="text-xs text-slate-500">{total} total</span>
                  {latest && (
                    <span
                      className="text-sm font-bold"
                      style={{ color: riskLevelColor(latest.risk_level) }}
                    >
                      {latest.overall_score ?? '—'}
                    </span>
                  )}
                  {latest && (
                    <a
                      href={`/scan/${latest.id}`}
                      className="text-xs text-cyan-500 hover:text-cyan-300 transition-colors"
                    >
                      View →
                    </a>
                  )}
                </div>
              ))}
          </div>
        </div>
      )}
    </div>
  );
}
