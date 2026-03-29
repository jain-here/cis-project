import { NextRequest, NextResponse } from 'next/server';
import { createServerClient } from '@/lib/supabase';
import { calculateRiskScore } from '@/lib/scoring';
import { extractDomain, normalizeUrl } from '@/lib/utils';
import type {
  SSLAnalysis,
  HeadersAnalysis,
  DNSAnalysis,
  ObservatoryAnalysis,
  CVEAnalysis,
  ConfidenceLevel,
  FinalScanResponse,
  RiskLevel,
} from '@/types';

const BASE_URL = process.env.NEXT_PUBLIC_APP_URL || 'http://localhost:3000';

type AvailabilityPayload = {
  available?: boolean;
  reason?: string;
  retryAttempts?: number;
};

type SSLApiPayload = SSLAnalysis & AvailabilityPayload;
type ObservatoryApiPayload = ObservatoryAnalysis & AvailabilityPayload;

function normalizeTechToken(value: string): string {
  return value
    .toLowerCase()
    .replace(/\(.*?\)/g, ' ')
    .replace(/[;,]/g, ' ')
    .trim();
}

function extractCVEKeyword(serverHeader?: string, xPoweredBy?: string): string | null {
  const source = (xPoweredBy || serverHeader || '').trim();
  if (!source) return null;

  const normalized = normalizeTechToken(source);
  const primary = normalized
    .split(/[\/\s]+/)
    .map((part) => part.trim())
    .find(Boolean);

  if (!primary) return null;

  const blocked = new Set([
    'server',
    'gws',
    'akamai',
    'elb',
    'cloudfront',
  ]);

  if (blocked.has(primary)) return null;

  const mapped: Record<string, string> = {
    nginx: 'nginx',
    apache: 'apache',
    iis: 'iis',
    'node.js': 'node.js',
    nodejs: 'node.js',
    express: 'express',
  };

  return mapped[primary] || null;
}

async function callInternal<T>(path: string, timeoutMs = 25000): Promise<T | null> {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(`${BASE_URL}${path}`, {
      next: { revalidate: 0 },
      signal: controller.signal,
    });
    if (!res.ok) return null;
    return res.json();
  } catch {
    return null;
  } finally {
    clearTimeout(timeoutId);
  }
}

function readRetryAttempts(data: unknown): number {
  if (!data || typeof data !== 'object' || !("retryAttempts" in data)) return 0;
  const attempts = (data as { retryAttempts?: unknown }).retryAttempts;
  if (typeof attempts !== 'number') return 0;
  return Math.max(0, attempts);
}

export async function POST(req: NextRequest) {
  const body = await req.json().catch(() => ({}));
  const { url } = body;

  console.log('[SCAN] Request received:', { url });

  if (!url) {
    console.error('[SCAN] Missing URL in request');
    return NextResponse.json({ error: 'url required' }, { status: 400 });
  }

  const normalizedUrl = normalizeUrl(url);
  const domain = extractDomain(normalizedUrl);
  const supabase = createServerClient();

  console.log('[SCAN] Normalized URL:', normalizedUrl);
  console.log('[SCAN] Extracted domain:', domain);

  // Create scan record
  const { data: scan, error: scanError } = await supabase
    .from('scans')
    .insert({ url: normalizedUrl, domain, status: 'running' })
    .select()
    .single();

  if (scanError || !scan) {
    console.error('[SCAN] Failed to create scan record:', scanError);
    return NextResponse.json({ error: 'Failed to create scan' }, { status: 500 });
  }

  const scanId = scan.id;
  console.log('[SCAN] Created scan record:', scanId);

  // Process inside the request lifecycle so Vercel does not terminate work early.
  await (async () => {
    try {
      console.log('[SCAN] Starting async API calls for:', domain);
      const [sslResult, headersResult, dnsResult, observatoryResult, headersForCVEResult] =
        await Promise.allSettled([
          callInternal<SSLApiPayload>(`/api/ssl?domain=${encodeURIComponent(domain)}`),
          callInternal<HeadersAnalysis>(`/api/headers?url=${encodeURIComponent(normalizedUrl)}`),
          callInternal<DNSAnalysis>(`/api/dns?domain=${encodeURIComponent(domain)}`),
          callInternal<ObservatoryApiPayload>(`/api/observatory?domain=${encodeURIComponent(domain)}`),
          callInternal<HeadersAnalysis>(`/api/headers?url=${encodeURIComponent(normalizedUrl)}`),
        ]);

      const sslRaw    = sslResult.status === 'fulfilled'          ? sslResult.value          : null;
      const headers   = headersResult.status === 'fulfilled'      ? headersResult.value      : null;
      const dns       = dnsResult.status === 'fulfilled'          ? dnsResult.value          : null;
      const obsRaw    = observatoryResult.status === 'fulfilled'  ? observatoryResult.value  : null;
      const hdrsForCV = headersForCVEResult.status === 'fulfilled'? headersForCVEResult.value: null;

      console.log('[SSL] Response:', sslRaw);
      console.log('[HEADERS] Response:', headers);
      console.log('[DNS] Response:', dns);
      console.log('[OBSERVATORY] Response:', obsRaw);
      console.log('[CVE] Technology extracted:', { serverHeader: hdrsForCV?.headers?.['server'], xPoweredBy: hdrsForCV?.headers?.['x-powered-by'] });

      // Determine availability of external APIs
      const sslAvailable = sslRaw?.available === true;
      const observatoryAvailable = obsRaw?.available === true;
      const sslUnavailable = !sslAvailable;
      const obsUnavailable = !observatoryAvailable;

      console.log('[AVAILABILITY] SSL Available:', sslAvailable, '| Observatory Available:', observatoryAvailable);

      // Cast to typed shapes only when available
      const ssl: SSLAnalysis | null        = sslAvailable ? (sslRaw as SSLAnalysis) : null;
      const obs: ObservatoryAnalysis | null = observatoryAvailable ? (obsRaw as ObservatoryAnalysis) : null;

      // --- CVE lookup ---
      const serverHeader = ((hdrsForCV as HeadersAnalysis | null)?.headers?.['server'] || '').trim();
      const xPoweredBy   = ((hdrsForCV as HeadersAnalysis | null)?.headers?.['x-powered-by'] || '').trim();
      const cveKeyword   = extractCVEKeyword(serverHeader, xPoweredBy);

      console.log('[CVE] Keyword selected:', cveKeyword || 'none (skipped due to generic/unknown technology)');

      const cveData = cveKeyword
        ? await callInternal<CVEAnalysis>(`/api/cve?keyword=${encodeURIComponent(cveKeyword)}`)
        : { cves: [], findings: [] };

      // --- Aggregate findings ---
      // Only include SSL/Observatory findings when those APIs were actually available
      const allFindings = [
        ...(ssl?.findings          || []),   // empty if SSL unavailable
        ...(headers?.findings      || []),   // always run
        ...(dns?.findings          || []),   // always run
        ...(!obsUnavailable ? (obs?.findings || []) : []), // skip if obs down
        ...(cveData?.findings      || []),   // always run
      ];

      const allCVEs = cveData?.cves || [];

      console.log('[FINDINGS] Aggregated findings count:', allFindings.length);
      console.log('[FINDINGS] SSL findings:', ssl?.findings?.length || 0);
      console.log('[FINDINGS] Headers findings:', headers?.findings?.length || 0);
      console.log('[FINDINGS] DNS findings:', dns?.findings?.length || 0);
      console.log('[FINDINGS] Observatory findings:', obs?.findings?.length || 0);
      console.log('[CVE] Total CVEs found:', allCVEs.length);

      // --- Score ---
      const nonCriticalMissing = !headers || !dns;
      const confidence: ConfidenceLevel = (sslAvailable && observatoryAvailable)
        ? (nonCriticalMissing ? 'medium' : 'high')
        : 'low';

      const scored = calculateRiskScore({
        sslGrade:             ssl?.grade || null,
        sslAvailable,
        observatoryAvailable,
        findings:             allFindings,
        cves:                 allCVEs,
      });

      // Both SSL and Observatory are now self-hosted — they should almost always
      // be available unless the TARGET domain itself is unreachable.
      // Only null out the score if BOTH critical checks failed (true outage case).
      let score: number | null = scored.score;
      let riskLevel: RiskLevel = scored.riskLevel;

      if (!sslAvailable && !observatoryAvailable) {
        // Completely blind — no data to score from
        score = null;
        riskLevel = 'unknown';
      } else if (scored.score === null) {
        // calculateRiskScore returned null (one check unavailable) — use partial score
        // Recalculate with whatever we have, neutral base for missing checks
        score = null;
        riskLevel = 'unknown';
      }

      console.log('[SCORE] Calculated:', {
        score,
        riskLevel,
        confidence,
        sslGrade: ssl?.grade || null,
        sslAvailable,
        observatoryAvailable,
      });

      // --- Determine final status ---
      // 'partial' = scan completed but one or more external APIs were unavailable
      const isPartial = sslUnavailable || obsUnavailable;
      const finalDbStatus = isPartial ? 'partial' : 'completed';
      const finalApiStatus: FinalScanResponse['status'] = isPartial ? 'partial' : 'complete';

      console.log('[STATUS] Final status:', finalDbStatus, { sslUnavailable, obsUnavailable });

      // --- Persist ---
      if (allFindings.length > 0) {
        await supabase.from('findings').insert(
          allFindings.map((f) => ({
            scan_id: scanId,
            category: f.category,
            title: f.title,
            severity: f.severity,
            description: f.description,
            mitigation: f.mitigation ?? null,
          }))
        );
      }

      if (allCVEs.length > 0) {
        await supabase.from('cve_results').insert(
          allCVEs.map((c) => ({ ...c, scan_id: scanId }))
        );
      }

      const dnsRecords = dns?.records || [];
      if (dnsRecords.length > 0) {
        await supabase.from('dns_records').insert(
          dnsRecords.map((r) => ({ ...r, scan_id: scanId }))
        );
      }

      // Store unavailability reasons in the scan record so the UI can display them
      const unavailableApis: string[] = [];
      if (sslUnavailable) unavailableApis.push(`SSL Labs: ${sslRaw?.reason || 'unavailable'}`);
      if (obsUnavailable) unavailableApis.push(`Observatory: ${obsRaw?.reason || 'unavailable'}`);

      const finalResponse: FinalScanResponse = {
        status: finalApiStatus,
        score,
        riskLevel,
        confidence,
        findings: allFindings,
        meta: {
          sslAvailable,
          observatoryAvailable,
          retries: {
            ssl: readRetryAttempts(sslRaw),
            observatory: readRetryAttempts(obsRaw),
          },
        },
      };

      console.log('[DB] Saving scan with unavailableApis:', unavailableApis);

      await supabase
        .from('scans')
        .update({
          status:        finalDbStatus,
          overall_score: score,
          // Keep DB value null for unknown to avoid enum/check-constraint mismatch.
          risk_level:    riskLevel === 'unknown' ? null : riskLevel,
          ssl_grade:     ssl?.grade || null,
          completed_at:  new Date().toISOString(),
          notes: JSON.stringify({
            unavailableApis,
            confidence,
            meta: finalResponse.meta,
          }),
        })
        .eq('id', scanId);

      console.log('[SCAN] Complete! Final result:', { scanId, ...finalResponse });

    } catch (err) {
      console.error('[scan orchestrator]', err);
      await supabase.from('scans').update({ status: 'failed' }).eq('id', scanId);
    }
  })();

  return NextResponse.json({ scanId });
}
