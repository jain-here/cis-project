'use client';

import { useCallback, useEffect, useState } from 'react';
import { useParams, useRouter } from 'next/navigation';
import { supabase } from '@/lib/supabase';
import { riskLevelColor } from '@/lib/scoring';
import { formatDate } from '@/lib/utils';
import { RiskGauge } from '@/components/RiskGauge';
import { CVECard } from '@/components/CVECard';
import { ScanProgress } from '@/components/ScanProgress';
import { DebugPanel } from '@/components/DebugPanel';
import type { Scan, Finding, CVEResult, DNSRecord, Severity, RiskLevel, ConfidenceLevel } from '@/types';

function RescanButton({ scanId }: { scanId: string }) {
  const router = useRouter();
  const [loading, setLoading] = useState(false);

  async function handleRescan() {
    setLoading(true);
    try {
      const res = await fetch('/api/rescan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scanId }),
      });
      const data = await res.json();
      if (data.scanId) router.push(`/scan/${data.scanId}`);
    } finally {
      setLoading(false);
    }
  }

  return (
    <button
      onClick={handleRescan}
      disabled={loading}
      className="text-xs px-3 py-1.5 rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 hover:bg-cyan-500/20 transition-all disabled:opacity-50"
    >
      {loading ? 'Starting…' : '↺ Rescan'}
    </button>
  );
}

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

function RiskBadge({ level, isIncomplete }: { level: RiskLevel | null; isIncomplete: boolean }) {
  const effectiveLevel: RiskLevel | null = isIncomplete ? 'unknown' : level;
  const color = riskLevelColor(effectiveLevel);
  return (
    <span
      className="text-sm font-bold px-3 py-1 rounded-lg"
      style={{ color, backgroundColor: `${color}20`, border: `1px solid ${color}40` }}
    >
      {effectiveLevel ? effectiveLevel.toUpperCase() : 'PENDING'}
    </span>
  );
}

function SectionCard({ title, icon, children }: { title: string; icon: string; children: React.ReactNode }) {
  return (
    <div className="rounded-2xl border border-white/10 bg-white/5 p-6">
      <h2 className="text-sm font-semibold text-slate-400 uppercase tracking-widest mb-4 flex items-center gap-2">
        <span>{icon}</span>
        {title}
      </h2>
      {children}
    </div>
  );
}

const URL_REGEX = /(https?:\/\/[^\s<>"'`]+)/g;

function renderTextWithLinks(text: string): React.ReactNode {
  const parts = text.split(URL_REGEX);

  return parts.map((part, index) => {
    if (index % 2 === 0) {
      return <span key={`text-${index}`}>{part}</span>;
    }

    const match = part.match(/^(https?:\/\/[^\s<>"'`]+?)([).,!?;:]*)$/);
    const href = match ? match[1] : part;
    const trailing = match ? match[2] : '';

    return (
      <span key={`link-${index}`}>
        <a
          href={href}
          target="_blank"
          rel="noopener noreferrer"
          className="text-cyan-400 hover:text-cyan-300 underline decoration-dotted underline-offset-2 break-all"
        >
          {href}
        </a>
        {trailing}
      </span>
    );
  });
}

export default function ScanReportPage() {
  const params = useParams();
  const scanId = params.id as string;

  const [scan, setScan] = useState<Scan | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [cves, setCves] = useState<CVEResult[]>([]);
  const [dnsRecords, setDnsRecords] = useState<DNSRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const fetchData = useCallback(async () => {
    console.log('[SCAN PAGE] Fetching data for scan:', scanId);
    const [scanRes, findingsRes, cvesRes, dnsRes] = await Promise.all([
      supabase.from('scans').select('*').eq('id', scanId).single(),
      supabase.from('findings').select('*').eq('scan_id', scanId).order('severity'),
      supabase.from('cve_results').select('*').eq('scan_id', scanId).order('cvss_score', { ascending: false }),
      supabase.from('dns_records').select('*').eq('scan_id', scanId),
    ]);

    console.log('[SCAN PAGE] Fetch results:', {
      scan: scanRes.data,
      findingsCount: findingsRes.data?.length,
      cvesCount: cvesRes.data?.length,
      dnsCount: dnsRes.data?.length,
    });

    if (scanRes.error || !scanRes.data) {
      console.error('[SCAN PAGE] Scan not found:', scanRes.error);
      setError('Scan not found');
      setLoading(false);
      return;
    }

    setScan(scanRes.data as Scan);
    setFindings((findingsRes.data || []) as Finding[]);
    setCves((cvesRes.data || []) as CVEResult[]);
    setDnsRecords((dnsRes.data || []) as DNSRecord[]);
    setLoading(false);
  }, [scanId]);

  // Initial fetch
  useEffect(() => {
    fetchData();
  }, [fetchData]);

  // Real-time subscription
  useEffect(() => {
    console.log('[SCAN PAGE] Setting up real-time subscription for scan:', scanId);
    const channel = supabase
      .channel(`scan-${scanId}`)
      .on('postgres_changes', { event: 'UPDATE', schema: 'public', table: 'scans', filter: `id=eq.${scanId}` }, (payload) => {
        console.log('[REALTIME] Scan updated:', payload.new);
        setScan(payload.new as Scan);
      })
      .on('postgres_changes', { event: 'INSERT', schema: 'public', table: 'findings', filter: `scan_id=eq.${scanId}` }, (payload) => {
        console.log('[REALTIME] New finding:', payload.new);
        setFindings((prev) => {
          const next = payload.new as Finding;
          return prev.some((f) => f.id === next.id) ? prev : [...prev, next];
        });
      })
      .on('postgres_changes', { event: 'INSERT', schema: 'public', table: 'cve_results', filter: `scan_id=eq.${scanId}` }, (payload) => {
        console.log('[REALTIME] New CVE:', payload.new);
        setCves((prev) => {
          const next = payload.new as CVEResult;
          return prev.some((cve) => cve.id === next.id) ? prev : [...prev, next];
        });
      })
      .on('postgres_changes', { event: 'INSERT', schema: 'public', table: 'dns_records', filter: `scan_id=eq.${scanId}` }, (payload) => {
        console.log('[REALTIME] New DNS record:', payload.new);
        setDnsRecords((prev) => {
          const next = payload.new as DNSRecord;
          return prev.some((r) => r.id === next.id) ? prev : [...prev, next];
        });
      })
      .subscribe();

    return () => { supabase.removeChannel(channel); };
  }, [scanId]);

  // Fallback polling: keeps UI fresh even if realtime is unavailable/misconfigured.
  useEffect(() => {
    if (!scan || (scan.status !== 'running' && scan.status !== 'pending')) return;
    const interval = setInterval(() => {
      fetchData();
    }, 3000);
    return () => clearInterval(interval);
  }, [scan, fetchData]);

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-[60vh]">
        <div className="text-slate-500 text-sm animate-pulse">Loading scan data…</div>
      </div>
    );
  }

  if (error || !scan) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[60vh] gap-3">
        <p className="text-red-400">{error || 'Scan not found'}</p>
        <a href="/" className="text-cyan-500 hover:text-cyan-300 text-sm transition-colors">← Back to home</a>
      </div>
    );
  }

  const sslFindings = findings.filter((f) => f.category === 'ssl');
  const headerFindings = findings.filter((f) => f.category === 'headers');
  const dnsFindings = findings.filter((f) => f.category === 'dns');
  const observatoryFindings = findings.filter((f) => f.category === 'observatory');

  const isRunning = scan.status === 'running' || scan.status === 'pending';
  const isPartial = scan.status === 'partial';

  // Parse unavailable API reasons stored in notes field
  const parsedNotes = (() => {
    try {
      const s = (scan as any).notes;
      return s ? JSON.parse(s) : null;
    } catch { return null; }
  })();

  const unavailableApis: string[] = Array.isArray(parsedNotes)
    ? parsedNotes
    : Array.isArray(parsedNotes?.unavailableApis)
      ? parsedNotes.unavailableApis
      : [];
  const confidence: ConfidenceLevel = parsedNotes?.confidence === 'high' || parsedNotes?.confidence === 'medium' || parsedNotes?.confidence === 'low'
    ? parsedNotes.confidence
    : (isPartial ? 'low' : 'high');
  const isIncomplete = !isRunning && scan.overall_score === null && confidence === 'low';

  const sslUnavailable = unavailableApis.some((reason) => reason.startsWith('SSL Labs:'));
  const observatoryUnavailable = unavailableApis.some((reason) => reason.startsWith('Observatory:'));

  const stepStatus = {
    ssl: sslUnavailable ? 'unavailable' : (scan.ssl_grade || sslFindings.length > 0 || !isRunning ? 'completed' : 'pending'),
    headers: !isRunning || headerFindings.length > 0 ? 'completed' : 'pending',
    dns: !isRunning || dnsRecords.length > 0 ? 'completed' : 'pending',
    observatory: observatoryUnavailable ? 'unavailable' : (!isRunning || observatoryFindings.length > 0 ? 'completed' : 'pending'),
    cve: !isRunning || cves.length > 0 ? 'completed' : 'pending',
    score: !isRunning ? 'completed' : 'pending',
  } as const;

  // Group DNS records by type
  const dnsGrouped = dnsRecords.reduce<Record<string, string[]>>((acc, r) => {
    if (!acc[r.type]) acc[r.type] = [];
    acc[r.type].push(r.value);
    return acc;
  }, {});

  // Sort findings by severity
  const sortedFindings = [...findings].sort((a, b) =>
    SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity)
  );

  return (
    <div className="max-w-5xl mx-auto px-4 py-10">
      {/* Header */}
      <div className="flex items-start justify-between mb-3 flex-wrap gap-2">
        <a href="/" className="text-xs text-slate-500 hover:text-slate-300 transition-colors">← New scan</a>
        <div className="flex items-center gap-2">
          <RescanButton scanId={scanId} />
          <a
            href={`/api/export?scanId=${scanId}`}
            target="_blank"
            rel="noopener noreferrer"
            className="text-xs px-3 py-1.5 rounded-lg bg-white/5 border border-white/10 text-slate-400 hover:text-white hover:border-white/20 transition-all"
          >
            ↓ Export Report
          </a>
          <a href="/dashboard" className="text-xs text-slate-500 hover:text-slate-300 transition-colors">Dashboard →</a>
        </div>
      </div>

      {/* Hero card */}
      <div className="rounded-2xl border border-white/10 bg-gradient-to-br from-white/5 to-white/3 p-8 mb-6">
        <div className="flex flex-col md:flex-row items-center md:items-start gap-8">
          {/* Gauge */}
          <div className="flex-shrink-0">
            {isRunning ? (
              <div className="w-[180px] h-[180px] rounded-full border-4 border-dashed border-slate-700 flex items-center justify-center">
                <span className="text-slate-500 text-xs text-center">Scanning…</span>
              </div>
            ) : isIncomplete ? (
              <div className="w-[180px] h-[180px] rounded-full border-4 border-dashed border-yellow-500/40 bg-yellow-500/10 flex items-center justify-center px-4">
                <span className="text-yellow-300 text-xs text-center font-medium">Scan incomplete<br />confidence low</span>
              </div>
            ) : (
              <RiskGauge
                score={scan.overall_score ?? 0}
                riskLevel={scan.risk_level}
                size={180}
              />
            )}
          </div>

          {/* Info */}
          <div className="flex-1 text-center md:text-left">
            <div className="flex items-center gap-3 justify-center md:justify-start mb-2">
              <h1 className="text-2xl font-black text-white font-mono">{scan.domain}</h1>
              {isRunning && (
                <span className="text-xs px-2 py-0.5 rounded-full bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 animate-pulse">
                  Scanning
                </span>
              )}
            </div>
            <p className="text-slate-500 text-sm mb-4">{scan.url}</p>

            <div className="flex flex-wrap gap-3 justify-center md:justify-start">
              <div className="text-center">
                <div className="text-xs text-slate-500 mb-1">Risk Level</div>
                <RiskBadge level={scan.risk_level} isIncomplete={isIncomplete} />
              </div>
              {scan.ssl_grade && (
                <div className="text-center">
                  <div className="text-xs text-slate-500 mb-1">SSL Grade</div>
                  <span className="text-sm font-bold px-3 py-1 rounded-lg bg-blue-500/20 text-blue-300 border border-blue-500/30">
                    {scan.ssl_grade}
                  </span>
                </div>
              )}
              <div className="text-center">
                <div className="text-xs text-slate-500 mb-1">Scanned</div>
                <span className="text-sm text-slate-300">{formatDate(scan.created_at)}</span>
              </div>
              <div className="text-center">
                <div className="text-xs text-slate-500 mb-1">Findings</div>
                <span className="text-sm font-bold text-white">{findings.length}</span>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Partial scan warning banner */}
      {isPartial && (
        <div className="mb-6 flex items-start gap-3 px-4 py-3 rounded-xl border border-yellow-500/30 bg-yellow-500/10">
          <span className="text-yellow-400 text-base mt-0.5 flex-shrink-0">⚠️</span>
          <div>
            <p className="text-sm font-semibold text-yellow-300">Partial scan — some external APIs were unavailable</p>
            <p className="text-xs text-yellow-400/80 mt-0.5">
              {scan.overall_score === null
                ? 'Scan incomplete — confidence low. Risk level is marked as unknown until SSL and Observatory data are available.'
                : 'Score is based on currently available checks only.'}
            </p>
            {unavailableApis.length > 0 && (
              <ul className="mt-1 space-y-0.5">
                {unavailableApis.map((reason, i) => (
                  <li key={i} className="text-xs text-yellow-500/70 font-mono">{reason}</li>
                ))}
              </ul>
            )}
          </div>
        </div>
      )}

      {/* Scan progress (only when running) */}
      {isRunning && (
        <div className="mb-6">
          <ScanProgress status={scan.status} stepStatus={stepStatus} />
        </div>
      )}

      {/* Summary strip */}
      {!isRunning && findings.length > 0 && (
        <div className="grid grid-cols-5 gap-2 mb-6">
          {SEVERITY_ORDER.map((sev) => {
            const count = findings.filter((f) => f.severity === sev).length;
            const colors: Record<Severity, string> = {
              critical: 'border-red-500/30 bg-red-500/10 text-red-400',
              high: 'border-orange-500/30 bg-orange-500/10 text-orange-400',
              medium: 'border-yellow-500/30 bg-yellow-500/10 text-yellow-400',
              low: 'border-blue-500/30 bg-blue-500/10 text-blue-400',
              info: 'border-slate-500/30 bg-slate-500/10 text-slate-400',
            };
            return (
              <div key={sev} className={`rounded-xl border p-3 text-center ${colors[sev]}`}>
                <div className="text-2xl font-black">{count}</div>
                <div className="text-xs font-semibold mt-0.5">{sev.toUpperCase()}</div>
              </div>
            );
          })}
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 mb-4">
        {/* SSL Details */}
        <SectionCard title="SSL / TLS" icon="🔒">
          {isRunning && !sslUnavailable && sslFindings.length === 0 && !scan.ssl_grade ? (
            <p className="text-sm text-slate-400 flex items-center gap-2 animate-pulse">
              <span>…</span> Checking SSL / TLS configuration
            </p>
          ) : sslUnavailable ? (
            <p className="text-sm text-yellow-300 flex items-center gap-2">
              <span>⚠</span> SSL scan unavailable for this run
            </p>
          ) : sslFindings.length === 0 ? (
            <p className="text-sm text-green-400 flex items-center gap-2">
              <span>✓</span> No SSL issues detected
            </p>
          ) : (
            <div className="space-y-3">
              {sslFindings.map((f) => (
                <div key={f.id} className="space-y-1">
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-sm text-white font-medium">{f.title}</span>
                    <SeverityBadge severity={f.severity} />
                  </div>
                  <p className="text-xs text-slate-400 leading-relaxed">{f.description}</p>
                  {f.mitigation && (
                    <p className="text-xs text-slate-500 italic">Fix: {f.mitigation}</p>
                  )}
                </div>
              ))}
            </div>
          )}
          {scan.ssl_grade && (
            <div className="mt-4 pt-4 border-t border-white/5">
              <span className="text-xs text-slate-500">SSL Labs Grade: </span>
              <span className="text-sm font-bold text-white">{scan.ssl_grade}</span>
            </div>
          )}
        </SectionCard>

        {/* Security Headers */}
        <SectionCard title="Security Headers" icon="🛡️">
          {isRunning && headerFindings.length === 0 ? (
            <p className="text-sm text-slate-400 flex items-center gap-2 animate-pulse">
              <span>…</span> Analyzing security headers
            </p>
          ) : headerFindings.length === 0 ? (
            <p className="text-sm text-green-400 flex items-center gap-2">
              <span>✓</span> All security headers present
            </p>
          ) : (
            <div className="space-y-3">
              {headerFindings.map((f) => (
                <div key={f.id} className="space-y-1">
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-xs font-mono text-slate-200">{f.title.replace('Missing ', '')}</span>
                    <SeverityBadge severity={f.severity} />
                  </div>
                  {f.mitigation && (
                    <p className="text-xs text-slate-500 font-mono bg-black/30 rounded px-2 py-1">{f.mitigation}</p>
                  )}
                </div>
              ))}
            </div>
          )}
        </SectionCard>

        {/* DNS Records */}
        <SectionCard title="DNS Records" icon="🌐">
          {isRunning && dnsRecords.length === 0 ? (
            <p className="text-sm text-slate-400 animate-pulse">Looking up DNS records…</p>
          ) : dnsRecords.length === 0 && !isRunning ? (
            <p className="text-sm text-slate-500">No DNS records found</p>
          ) : (
            <div className="space-y-3">
              {Object.entries(dnsGrouped).map(([type, values]) => (
                <div key={type}>
                  <span className="text-xs font-bold text-cyan-400 font-mono">{type}</span>
                  <div className="mt-1 space-y-1">
                    {values.map((v, i) => (
                      <div key={i} className="text-xs text-slate-300 font-mono bg-black/30 rounded px-2 py-1 break-all">
                        {v}
                      </div>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          )}
          {dnsFindings.length > 0 && (
            <div className="mt-4 pt-4 border-t border-white/5 space-y-2">
              {dnsFindings.map((f) => (
                <div key={f.id} className="flex items-start justify-between gap-2">
                  <span className="text-xs text-slate-300">{f.title}</span>
                  <SeverityBadge severity={f.severity} />
                </div>
              ))}
            </div>
          )}
        </SectionCard>

        {/* Observatory */}
        <SectionCard title="Mozilla Observatory" icon="🔭">
          <div className="mb-3">
            <a
              href={`https://observatory.mozilla.org/analyze/${encodeURIComponent(scan.domain)}`}
              target="_blank"
              rel="noopener noreferrer"
              className="text-xs text-cyan-400 hover:text-cyan-300 hover:underline transition-colors"
            >
              Open in Mozilla Observatory ↗
            </a>
          </div>
          {isRunning && !observatoryUnavailable && observatoryFindings.length === 0 ? (
            <p className="text-sm text-slate-400 flex items-center gap-2 animate-pulse">
              <span>…</span> Running Observatory checks
            </p>
          ) : observatoryUnavailable ? (
            <p className="text-sm text-yellow-300 flex items-center gap-2">
              <span>⚠</span> Observatory scan unavailable for this run
            </p>
          ) : observatoryFindings.length === 0 ? (
            <p className="text-sm text-green-400 flex items-center gap-2">
              <span>✓</span> Passed all Observatory tests
            </p>
          ) : (
            <div className="space-y-3">
              {observatoryFindings.map((f) => (
                <div key={f.id} className="space-y-1">
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-xs text-slate-200">{f.title.replace('Observatory: ', '')}</span>
                    <SeverityBadge severity={f.severity} />
                  </div>
                  <p className="text-xs text-slate-500">{renderTextWithLinks(f.description)}</p>
                  {f.mitigation && (
                    <p className="text-xs text-slate-500">{renderTextWithLinks(f.mitigation)}</p>
                  )}
                </div>
              ))}
            </div>
          )}
        </SectionCard>
      </div>

      {/* CVE Findings */}
      {(cves.length > 0 || isRunning) && (
        <SectionCard title={`CVE Findings (${cves.length})`} icon="⚠️">
          {cves.length === 0 ? (
            <p className="text-sm text-slate-500 animate-pulse">Looking up CVEs…</p>
          ) : (
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              {cves.map((cve) => (
                <CVECard key={cve.id} cve={cve} />
              ))}
            </div>
          )}
        </SectionCard>
      )}

      {/* All findings list */}
      {!isRunning && sortedFindings.length > 0 && (
        <div className="mt-4">
          <SectionCard title={`All Findings (${sortedFindings.length})`} icon="📋">
            <div className="space-y-2">
              {sortedFindings.map((f) => (
                <div
                  key={f.id}
                  className="flex items-start gap-3 p-3 rounded-xl bg-black/20 hover:bg-black/30 transition-colors"
                >
                  <SeverityBadge severity={f.severity} />
                  <div className="flex-1 min-w-0">
                    <p className="text-sm text-white font-medium">{f.title}</p>
                    <p className="text-xs text-slate-400 mt-0.5 leading-relaxed">{f.description}</p>
                    {f.mitigation && (
                      <p className="text-xs text-slate-500 mt-1">
                        <span className="text-slate-600">Mitigation:</span> {f.mitigation}
                      </p>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </SectionCard>
        </div>
      )}

      {/* No findings at all */}
      {!isRunning && (scan.status === 'completed' || scan.status === 'partial') && findings.length === 0 && cves.length === 0 && (
        <div className="rounded-2xl border border-green-500/20 bg-green-500/5 p-8 text-center">
          <div className="text-4xl mb-3">🎉</div>
          <h3 className="text-lg font-bold text-green-400 mb-1">No issues detected</h3>
          <p className="text-sm text-slate-500">This domain passed all security checks.</p>
        </div>
      )}

      {scan.status === 'failed' && (
        <div className="rounded-2xl border border-red-500/20 bg-red-500/5 p-6 text-center">
          <p className="text-red-400 font-medium">Scan failed. The target may be unreachable.</p>
          <a href="/" className="text-sm text-cyan-500 hover:text-cyan-300 transition-colors mt-2 inline-block">
            Try again →
          </a>
        </div>
      )}

      <DebugPanel />
    </div>
  );
}
