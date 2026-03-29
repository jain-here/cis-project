import { NextRequest, NextResponse } from 'next/server';
import { normalizeUrl, extractDomain } from '@/lib/utils';
import type { HeadersAnalysis, Finding } from '@/types';

export const dynamic = 'force-dynamic';

interface HeaderConfig {
  name: string;
  display: string;
  description: string;
  recommendation: string;
  baselineSeverity: 'high' | 'medium' | 'low' | 'info';
  importance: 'critical' | 'important' | 'standard' | 'advisory';
}

const SECURITY_HEADERS: HeaderConfig[] = [
  {
    name: 'strict-transport-security',
    display: 'Strict-Transport-Security',
    description: 'Forces browsers to use HTTPS for all future requests, preventing MITM downgrade attacks.',
    recommendation: 'Add `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`.',
    baselineSeverity: 'high',
    importance: 'critical',
  },
  {
    name: 'content-security-policy',
    display: 'Content-Security-Policy',
    description: 'Controls which resources the browser loads, providing strong XSS and injection protection.',
    recommendation: "Implement CSP with restrictive directives like `default-src 'self'`.",
    baselineSeverity: 'high',
    importance: 'critical',
  },
  {
    name: 'x-frame-options',
    display: 'X-Frame-Options',
    description: 'Prevents clickjacking by controlling iframe embedding.',
    recommendation: "Add `X-Frame-Options: SAMEORIGIN` or use CSP's `frame-ancestors 'none'`.",
    baselineSeverity: 'medium',
    importance: 'important',
  },
  {
    name: 'x-content-type-options',
    display: 'X-Content-Type-Options',
    description: 'Disables MIME-sniffing to prevent content-type-based attacks.',
    recommendation: 'Add `X-Content-Type-Options: nosniff`.',
    baselineSeverity: 'medium',
    importance: 'important',
  },
  {
    name: 'referrer-policy',
    display: 'Referrer-Policy',
    description: 'Controls referrer leakage across cross-origin requests.',
    recommendation: 'Add `Referrer-Policy: strict-origin-when-cross-origin`.',
    baselineSeverity: 'low',
    importance: 'standard',
  },
  {
    name: 'permissions-policy',
    display: 'Permissions-Policy',
    description: 'Restricts access to browser APIs (camera, microphone, geolocation, etc.).',
    recommendation: 'Add `Permissions-Policy: camera=(), microphone=(), geolocation=()`.',
    baselineSeverity: 'low',
    importance: 'standard',
  },
];

// Known CDN and large infrastructure providers that manage headers at edge
const CDN_DOMAINS = new Set([
  'google.com', 'facebook.com', 'instagram.com', 'whatsapp.com', 'meta.com',
  'amazon.com', 'amazon.co.uk', 'amazon.de', 'aws.amazon.com',
  'microsoft.com', 'github.com', 'office365.com', 'outlook.com',
  'apple.com', 'icloud.com',
  'twitter.com', 'x.com', 'linkedin.com',
  'netflix.com', 'disney.com',
  'cloudflare.com', 'akamai.com', 'fastly.com',
  'stripe.com', 'paypal.com',
  'wikipedia.org', 'youtube.com', 'gmail.com',
]);

function isCdnManagedDomain(domain: string): boolean {
  const normalized = domain.toLowerCase().replace(/^www\./, '');
  return CDN_DOMAINS.has(normalized);
}

/**
 * Fetch with exponential backoff retry (up to 2 retries, ~1s and ~2s delays).
 * Follows redirects (up to 5 hops) and uses a realistic User-Agent.
 */
async function fetchWithRetry(
  url: string,
  maxRetries = 2,
  timeout = 10000
): Promise<Response> {
  const userAgent =
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36';

  let lastErr: Error | null = null;

  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), timeout);

      const res = await fetch(url, {
        method: 'HEAD',
        redirect: 'follow',
        headers: { 'User-Agent': userAgent },
        signal: controller.signal,
        next: { revalidate: 0 },
      }).catch(() =>
        // Fallback to GET if HEAD fails with small limit
        fetch(url, {
          method: 'GET',
          redirect: 'follow',
          headers: { 'User-Agent': userAgent, Range: 'bytes=0-1' },
          signal: controller.signal,
          next: { revalidate: 0 },
        })
      );

      clearTimeout(timeoutId);
      return res;
    } catch (err) {
      clearTimeout(0);
      lastErr = err instanceof Error ? err : new Error(String(err));
      if (attempt < maxRetries) {
        // Exponential backoff: 500ms * 2^attempt
        const delay = 500 * Math.pow(2, attempt);
        await new Promise((r) => setTimeout(r, delay));
      }
    }
  }

  throw lastErr || new Error('Failed to fetch after retries');
}

/**
 * Compute severity based on:
 * - Header importance
 * - Whether domain is CDN-managed (downgrades severity)
 * - Overall risk context
 */
function computeSeverity(
  header: HeaderConfig,
  isCdn: boolean,
  missingCount: number
): 'critical' | 'high' | 'medium' | 'low' | 'info' {
  // CDN-managed domains: downgrade missing header severity significantly
  if (isCdn) {
    return 'low'; // CDN likely handles at edge
  }

  // For non-CDN sites, use baseline but cap critical headers at high
  if (header.baselineSeverity === 'high') {
    // If multiple critical headers missing, it's concerning; otherwise just high
    return missingCount > 2 ? 'high' : 'medium';
  }

  return header.baselineSeverity;
}

/**
 * Analyze headers and return deduplicated findings.
 */
function analyzeHeaders(
  headers: Record<string, string>,
  isCdn: boolean
): Array<Omit<Finding, 'id' | 'scan_id'>> {
  const findingsMap = new Map<string, Omit<Finding, 'id' | 'scan_id'>>();

  // Count missing important headers to contextualize risk
  const missingCriticalCount = SECURITY_HEADERS.filter(
    (h) => h.importance === 'critical' && !(h.name in headers)
  ).length;

  // Check security headers
  for (const header of SECURITY_HEADERS) {
    const present = header.name in headers;
    if (!present) {
      const severity = computeSeverity(header, isCdn, missingCriticalCount);
      const key = `missing-${header.name}`;

      // Only add finding if severity is not 'info' to avoid noise
      if (severity !== 'info') {
        findingsMap.set(key, {
          category: 'headers',
          title: `${header.display} header missing`,
          severity,
          description: `${header.display} is not set. ${header.description}${
            isCdn ? ' (Note: This may be managed by CDN infrastructure.)' : ''
          }`,
          mitigation: header.recommendation,
          confidence: 'high',
        });
      }
    }
  }

  // Check for info-level fingerprinting issues (deduplicate by type)
  if (headers['x-powered-by']) {
    const tech = headers['x-powered-by'].split(';')[0].trim();
    findingsMap.set('fingerprint-x-powered-by', {
      category: 'headers',
      title: 'Technology Stack Exposed (X-Powered-By)',
      severity: 'info',
      description: `Server identifies itself via X-Powered-By: ${tech}. This aids attackers in targeting known vulnerabilities.`,
      mitigation: 'Remove or obfuscate the X-Powered-By header (set to empty or generic value).',
      confidence: 'high',
    });
  }

  if (headers['server']) {
    const serverRaw = headers['server'];
    // Only flag if it looks like a detailed version string
    if (/\d+\.\d+/.test(serverRaw)) {
      findingsMap.set('fingerprint-server', {
        category: 'headers',
        title: 'Server Version Information Exposed',
        severity: 'info',
        description: `Server reveals version details: ${serverRaw}. This enables targeted attacks.`,
        mitigation: 'Genericize or remove the Server header.',
        confidence: 'high',
      });
    }
  }

  return Array.from(findingsMap.values());
}

/**
 * Calculate risk summary (low = true positives only; avoids false-positive inflation).
 */
function calculateRiskSummary(
  findings: Array<Omit<Finding, 'id' | 'scan_id'>>,
  isCdn: boolean
): { riskLevel: 'low' | 'medium' | 'high'; score: number } {
  // For CDN domains, cap at MEDIUM even with missing headers (they're managed at edge)
  if (isCdn) {
    const criticalCount = findings.filter((f) => f.severity === 'high').length;
    return {
      riskLevel: criticalCount > 1 ? 'medium' : 'low',
      score: criticalCount > 1 ? 65 : 85,
    };
  }

  // For smaller/custom sites, be more strict
  const criticalCount = findings.filter((f) => f.severity === 'high').length;
  const mediumCount = findings.filter((f) => f.severity === 'medium').length;

  if (criticalCount >= 2) {
    return { riskLevel: 'high', score: 50 };
  } else if (criticalCount === 1 || mediumCount >= 2) {
    return { riskLevel: 'medium', score: 65 };
  }

  return { riskLevel: 'low', score: 85 };
}

export async function GET(req: NextRequest) {
  const urlParam = req.nextUrl.searchParams.get('url');
  if (!urlParam) {
    return NextResponse.json({ error: 'url required' }, { status: 400 });
  }

  try {
    const targetUrl = normalizeUrl(urlParam);
    const domain = extractDomain(targetUrl);
    const isCdn = isCdnManagedDomain(domain);

    console.log(`[HEADERS] Analyzing ${domain} (CDN-managed: ${isCdn})`);

    // Fetch with retry and redirect following
    const response = await fetchWithRetry(targetUrl);

    // Collect headers from final response
    const headers: Record<string, string> = {};
    response.headers.forEach((value, key) => {
      headers[key.toLowerCase()] = value;
    });

    console.log(`[HEADERS] Got ${Object.keys(headers).length} headers`);

    // Analyze and deduplicate
    const findings = analyzeHeaders(headers, isCdn);
    const { riskLevel, score } = calculateRiskSummary(findings, isCdn);

    // Build notes
    const notes: string[] = [];
    if (isCdn) {
      notes.push(
        'This domain is managed by a large provider (CDN/edge infrastructure). Security headers may be configured at the edge and not visible in direct responses.'
      );
    }
    if (response.redirected) {
      notes.push(`Final response after ${response.url} (followed redirects).`);
    }

    const result: HeadersAnalysis & { summary?: any; notes?: string[] } = {
      headers,
      findings,
      summary: { riskLevel, score },
      notes,
    };

    return NextResponse.json(result);
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    console.error('[HEADERS] Error:', message);
    return NextResponse.json(
      { error: message, headers: {}, findings: [], summary: { riskLevel: 'unknown', score: null }, notes: [] },
      { status: 200 }
    );
  }
}
