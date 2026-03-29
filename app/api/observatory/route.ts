import { NextRequest, NextResponse } from 'next/server';

export const dynamic = 'force-dynamic';

// ─────────────────────────────────────────────────────────────────────────────
// Self-hosted Observatory replacement — replicates Mozilla Observatory scoring.
// Analyzes security headers directly. No external API, no rate limits, instant.
// Scoring weights mirror Observatory’s actual test modifiers.
// ─────────────────────────────────────────────────────────────────────────────

interface ObsFinding {
  category: 'observatory';
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  description: string;
  mitigation: string;
}

function toErrorMessage(value: unknown): string {
  return value instanceof Error ? value.message : String(value);
}

function unavailable(reason: string): NextResponse {
  console.warn('[OBSERVATORY] Unavailable:', reason);
  return NextResponse.json(
    { available: false, reason, retryAttempts: 0, score: null, grade: null, findings: [] },
    { status: 200 }
  );
}

function scoreToGrade(score: number): string {
  if (score >= 90) return 'A+';
  if (score >= 85) return 'A';
  if (score >= 80) return 'A-';
  if (score >= 75) return 'B+';
  if (score >= 70) return 'B';
  if (score >= 65) return 'B-';
  if (score >= 60) return 'C+';
  if (score >= 55) return 'C';
  if (score >= 50) return 'C-';
  if (score >= 45) return 'D+';
  if (score >= 40) return 'D';
  return 'F';
}

async function fetchHeaders(url: string): Promise<Record<string, string>> {
  const res = await fetch(url, {
    method: 'HEAD',
    redirect: 'follow',
    next: { revalidate: 0 },
  }).catch(() =>
    fetch(url, { method: 'GET', redirect: 'follow', next: { revalidate: 0 } })
  );
  const headers: Record<string, string> = {};
  res.headers.forEach((value, key) => { headers[key.toLowerCase()] = value; });
  return headers;
}

function analyzeHeaders(headers: Record<string, string>): { score: number; grade: string; findings: ObsFinding[] } {
  let score = 100;
  const findings: ObsFinding[] = [];
  const h = (name: string) => headers[name.toLowerCase()] ?? null;

  // ─ Content-Security-Policy ───────────────────────────────── weight: −25
  const csp = h('content-security-policy');
  if (!csp) {
    score -= 25;
    findings.push({
      category: 'observatory', title: 'Content-Security-Policy not implemented', severity: 'high',
      description: 'No CSP header found. CSP is the primary defense against XSS attacks.',
      mitigation: "Add `Content-Security-Policy: default-src 'self'` and restrict other sources explicitly.",
    });
  } else {
    const cspLow = csp.toLowerCase();
    if (cspLow.includes("'unsafe-inline'") && !cspLow.includes('nonce-') && !cspLow.includes('hash-')) {
      score -= 10;
      findings.push({
        category: 'observatory', title: "CSP uses 'unsafe-inline' without nonce/hash", severity: 'medium',
        description: "'unsafe-inline' in CSP without a nonce or hash weakens XSS protection.",
        mitigation: "Replace 'unsafe-inline' with a nonce-based or hash-based CSP directive.",
      });
    }
    if (cspLow.includes("'unsafe-eval'")) {
      score -= 5;
      findings.push({
        category: 'observatory', title: "CSP uses 'unsafe-eval'", severity: 'medium',
        description: "'unsafe-eval' allows eval() and related functions, creating XSS risk.",
        mitigation: "Remove 'unsafe-eval' and refactor code that relies on eval().",
      });
    }
  }

  // ─ Strict-Transport-Security ─────────────────────────────── weight: −20
  const hsts = h('strict-transport-security');
  if (!hsts) {
    score -= 20;
    findings.push({
      category: 'observatory', title: 'Strict-Transport-Security (HSTS) not implemented', severity: 'high',
      description: 'No HSTS header. Browsers may be downgraded to HTTP via MITM attacks.',
      mitigation: 'Add `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`.',
    });
  } else {
    const maxAgeMatch = hsts.match(/max-age=(\d+)/i);
    const maxAge = maxAgeMatch ? parseInt(maxAgeMatch[1]) : 0;
    if (maxAge < 15552000) {
      score -= 5;
      findings.push({
        category: 'observatory', title: 'HSTS max-age too short', severity: 'medium',
        description: `HSTS max-age is ${maxAge}s (< 6 months), limiting its protection against SSL stripping.`,
        mitigation: 'Set HSTS max-age to at least 31536000 (1 year).',
      });
    }
    if (!hsts.toLowerCase().includes('includesubdomains')) {
      score -= 3;
      findings.push({
        category: 'observatory', title: 'HSTS missing includeSubDomains', severity: 'low',
        description: 'HSTS does not include includeSubDomains, leaving subdomains unprotected.',
        mitigation: 'Add includeSubDomains to your HSTS header.',
      });
    }
  }

  // ─ X-Frame-Options ─────────────────────────────────────── weight: −20
  const xfo = h('x-frame-options');
  const cspHasFrameAncestors = csp?.toLowerCase().includes('frame-ancestors') ?? false;
  if (!xfo && !cspHasFrameAncestors) {
    score -= 20;
    findings.push({
      category: 'observatory', title: 'X-Frame-Options not implemented', severity: 'high',
      description: 'No clickjacking protection. The page can be embedded in iframes.',
      mitigation: "Add `X-Frame-Options: DENY` or CSP `frame-ancestors 'none'`.",
    });
  }

  // ─ X-Content-Type-Options ──────────────────────────────── weight: −5
  const xcto = h('x-content-type-options');
  if (!xcto) {
    score -= 5;
    findings.push({
      category: 'observatory', title: 'X-Content-Type-Options not set', severity: 'low',
      description: 'Browsers may MIME-sniff responses, potentially executing malicious content.',
      mitigation: 'Add `X-Content-Type-Options: nosniff`.',
    });
  }

  // ─ Referrer-Policy ─────────────────────────────────────── weight: −5
  const rp = h('referrer-policy');
  if (!rp) {
    score -= 5;
    findings.push({
      category: 'observatory', title: 'Referrer-Policy not set', severity: 'low',
      description: 'Browser may send full referrer URLs to third parties, leaking sensitive paths.',
      mitigation: 'Add `Referrer-Policy: strict-origin-when-cross-origin`.',
    });
  } else if (['unsafe-url', 'no-referrer-when-downgrade'].includes(rp.toLowerCase())) {
    score -= 3;
    findings.push({
      category: 'observatory', title: `Referrer-Policy too permissive (${rp})`, severity: 'low',
      description: `Referrer-Policy "${rp}" leaks full URLs cross-origin.`,
      mitigation: 'Use `strict-origin-when-cross-origin` or `no-referrer`.',
    });
  }

  // ─ Permissions-Policy ──────────────────────────────────── weight: −5
  const pp = h('permissions-policy') ?? h('feature-policy');
  if (!pp) {
    score -= 5;
    findings.push({
      category: 'observatory', title: 'Permissions-Policy not set', severity: 'low',
      description: 'Browser features like camera, microphone, geolocation are unrestricted.',
      mitigation: 'Add `Permissions-Policy: camera=(), microphone=(), geolocation=()`.',
    });
  }

  // ─ Cookie security ──────────────────────────────────────── weight: −10
  const setCookie = h('set-cookie');
  if (setCookie) {
    const cl = setCookie.toLowerCase();
    if (!cl.includes('httponly')) {
      score -= 5;
      findings.push({
        category: 'observatory', title: 'Cookie missing HttpOnly flag', severity: 'medium',
        description: 'A cookie is set without HttpOnly, making it accessible to JavaScript.',
        mitigation: 'Add the HttpOnly flag to all sensitive cookies.',
      });
    }
    if (!cl.includes('secure')) {
      score -= 5;
      findings.push({
        category: 'observatory', title: 'Cookie missing Secure flag', severity: 'medium',
        description: 'A cookie can be transmitted over unencrypted HTTP.',
        mitigation: 'Add the Secure flag to all sensitive cookies.',
      });
    }
    if (!cl.includes('samesite')) {
      score -= 3;
      findings.push({
        category: 'observatory', title: 'Cookie missing SameSite attribute', severity: 'low',
        description: 'Cookie without SameSite is vulnerable to CSRF.',
        mitigation: 'Add `SameSite=Strict` or `SameSite=Lax` to all cookies.',
      });
    }
  }

  score = Math.max(0, Math.min(100, Math.round(score)));
  return { score, grade: scoreToGrade(score), findings };
}

export async function GET(req: NextRequest) {
  const domain = req.nextUrl.searchParams.get('domain');
  console.log('[OBSERVATORY] Request for domain:', domain);

  if (!domain) {
    return NextResponse.json({ error: 'domain required' }, { status: 400 });
  }

  try {
    console.log('[OBSERVATORY] Running self-hosted header analysis...');
    const headers = await fetchHeaders(`https://${domain}`);
    if (Object.keys(headers).length === 0) {
      return unavailable(`Could not fetch headers from ${domain}`);
    }
    const { score, grade, findings } = analyzeHeaders(headers);
    console.log(`[OBSERVATORY] Score: ${score} (${grade}) | Findings: ${findings.length}`);
    return NextResponse.json({ available: true, retryAttempts: 0, score, grade, findings, source: 'self-hosted' });
  } catch (err: unknown) {
    const message = toErrorMessage(err);
    console.error('[OBSERVATORY] Analysis failed:', message);
    return unavailable(`Header analysis failed: ${message}`);
  }
}
