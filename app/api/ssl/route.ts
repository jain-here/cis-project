import { NextRequest, NextResponse } from 'next/server';
import * as tls from 'tls';

export const dynamic = 'force-dynamic';

// ─────────────────────────────────────────────────────────────────────────────
// Self-hosted TLS inspector — replaces SSL Labs entirely.
// Uses Node.js built-in tls module: no external API, no rate limits, ~200ms.
// ─────────────────────────────────────────────────────────────────────────────

interface TLSFinding {
  category: 'ssl';
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  description: string;
  mitigation: string;
}

type PeerCertWithSAN = tls.PeerCertificate & { subjectaltname?: string };
type CipherWithBits = tls.CipherNameAndProtocol & { bits?: number };

function toErrorMessage(value: unknown): string {
  return value instanceof Error ? value.message : String(value);
}

function unavailable(reason: string): NextResponse {
  console.warn('[SSL] Unavailable:', reason);
  return NextResponse.json(
    { available: false, reason, retryAttempts: 0, grade: null, findings: [] },
    { status: 200 }
  );
}

/** Derive an SSL Labs-style letter grade from raw TLS data. */
function deriveGrade(params: {
  tlsVersion: string | null;
  authorized: boolean;
  cipherBits: number | null;
  daysUntilExpiry: number | null;
}): string {
  const { tlsVersion, authorized, cipherBits, daysUntilExpiry } = params;

  if (!authorized) return 'F';
  if (daysUntilExpiry !== null && daysUntilExpiry <= 0) return 'F';

  if (!tlsVersion) return 'C';
  if (tlsVersion === 'TLSv1.3') return cipherBits && cipherBits >= 256 ? 'A+' : 'A';
  if (tlsVersion === 'TLSv1.2') {
    if (cipherBits && cipherBits >= 256) return 'A';
    if (cipherBits && cipherBits >= 128) return 'B';
    return 'C';
  }
  if (tlsVersion === 'TLSv1.1') return 'C';
  if (tlsVersion === 'TLSv1' || tlsVersion === 'TLSv1.0') return 'D';
  if (tlsVersion.toLowerCase().includes('ssl')) return 'F';
  return 'C';
}

async function inspectTLS(hostname: string, port = 443) {
  return new Promise<{
    available: true;
    grade: string;
    certExpiry: string | null;
    certSubject: string | null;
    certIssuer: string | null;
    certSANs: string[];
    protocols: string[];
    tlsVersion: string | null;
    cipherSuite: string | null;
    cipherBits: number | null;
    authorized: boolean;
    vulnerabilities: string[];
    findings: TLSFinding[];
    retryAttempts: number;
  }>((resolve, reject) => {
    const timeout = setTimeout(() => {
      socket.destroy();
      reject(new Error('TLS connection timed out after 10s'));
    }, 10000);

    const socket = tls.connect(
      { host: hostname, port, servername: hostname, rejectUnauthorized: false },
      () => {
        clearTimeout(timeout);
        try {
          const cert       = socket.getPeerCertificate(true) as PeerCertWithSAN;
          const tlsVersion = socket.getProtocol() ?? null;
          const cipher     = socket.getCipher() as CipherWithBits;
          const authorized = socket.authorized;

          const certExpiry = cert?.valid_to ? new Date(cert.valid_to).toISOString() : null;
          const daysUntilExpiry = certExpiry
            ? (new Date(certExpiry).getTime() - Date.now()) / 86400000
            : null;

          const sanRaw   = cert?.subjectaltname ?? '';
          const certSANs = sanRaw
            ? sanRaw.split(',').map((s: string) => s.trim().replace(/^DNS:/, ''))
            : [];

          const certSubjectRaw = cert?.subject?.CN ?? null;
          const certIssuerRaw = cert?.issuer?.O ?? cert?.issuer?.CN ?? null;
          const certSubject = Array.isArray(certSubjectRaw) ? certSubjectRaw[0] ?? null : certSubjectRaw;
          const certIssuer = Array.isArray(certIssuerRaw) ? certIssuerRaw[0] ?? null : certIssuerRaw;
          const cipherSuite = cipher?.name ?? null;
          const cipherBits  = typeof cipher?.bits === 'number' ? cipher.bits : null;

          const grade         = deriveGrade({ tlsVersion, authorized, cipherBits, daysUntilExpiry });
          const vulnerabilities: string[] = [];
          const findings: TLSFinding[]   = [];

          // TLS version findings
          if (tlsVersion === 'TLSv1' || tlsVersion === 'TLSv1.0') {
            vulnerabilities.push('TLS 1.0 (deprecated)');
            findings.push({
              category: 'ssl', title: 'TLS 1.0 in use (deprecated)', severity: 'high',
              description: 'TLS 1.0 is deprecated and vulnerable to POODLE and BEAST attacks.',
              mitigation: 'Disable TLS 1.0 and TLS 1.1. Only allow TLS 1.2 and TLS 1.3.',
            });
          } else if (tlsVersion === 'TLSv1.1') {
            vulnerabilities.push('TLS 1.1 (deprecated)');
            findings.push({
              category: 'ssl', title: 'TLS 1.1 in use (deprecated)', severity: 'medium',
              description: 'TLS 1.1 is deprecated. Modern clients should use TLS 1.2 or 1.3.',
              mitigation: 'Disable TLS 1.1 and only allow TLS 1.2 and TLS 1.3.',
            });
          }

          // Certificate validity
          if (!authorized) {
            findings.push({
              category: 'ssl', title: 'Certificate Not Trusted', severity: 'critical',
              description: `The SSL certificate is not trusted: ${socket.authorizationError ?? 'unknown reason'}`,
              mitigation: 'Obtain a certificate from a trusted Certificate Authority (CA).',
            });
          }

          // Expiry
          if (daysUntilExpiry !== null) {
            if (daysUntilExpiry <= 0) {
              findings.push({
                category: 'ssl', title: 'Certificate Expired', severity: 'critical',
                description: 'The SSL certificate has expired.',
                mitigation: 'Renew the SSL certificate immediately.',
              });
            } else if (daysUntilExpiry <= 7) {
              findings.push({
                category: 'ssl',
                title: `Certificate Expiring in ${Math.round(daysUntilExpiry)} days`,
                severity: 'critical',
                description: `SSL certificate expires very soon (${Math.round(daysUntilExpiry)} days).`,
                mitigation: 'Renew the SSL certificate immediately.',
              });
            } else if (daysUntilExpiry <= 30) {
              findings.push({
                category: 'ssl',
                title: `Certificate Expiring Soon (${Math.round(daysUntilExpiry)} days)`,
                severity: 'high',
                description: `SSL certificate expires in ${Math.round(daysUntilExpiry)} days.`,
                mitigation: 'Renew the SSL certificate before it expires.',
              });
            }
          }

          // Weak cipher
          if (cipherBits && cipherBits < 128) {
            findings.push({
              category: 'ssl', title: `Weak Cipher Suite (${cipherBits} bits)`, severity: 'high',
              description: `Cipher suite uses only ${cipherBits}-bit keys, which is considered weak.`,
              mitigation: 'Configure the server to use strong cipher suites with at least 128-bit keys.',
            });
          }

          socket.destroy();
          resolve({
            available: true,
            grade,
            certExpiry,
            certSubject,
            certIssuer,
            certSANs,
            protocols: tlsVersion ? [tlsVersion] : [],
            tlsVersion,
            cipherSuite,
            cipherBits,
            authorized,
            vulnerabilities,
            findings,
            retryAttempts: 0,
          });
        } catch (parseErr: unknown) {
          socket.destroy();
          reject(new Error(`TLS parse error: ${toErrorMessage(parseErr)}`));
        }
      }
    );

    socket.on('error', (err) => {
      clearTimeout(timeout);
      reject(err);
    });
  });
}

export async function GET(req: NextRequest) {
  const domain = req.nextUrl.searchParams.get('domain');
  console.log('[SSL] Request for domain:', domain);

  if (!domain) {
    return NextResponse.json({ error: 'domain required' }, { status: 400 });
  }

  try {
    console.log('[SSL] Running self-hosted TLS inspection...');
    const result = await inspectTLS(domain);
    console.log(`[SSL] Grade: ${result.grade} | TLS: ${result.tlsVersion} | Cipher: ${result.cipherSuite} | Authorized: ${result.authorized}`);
    console.log('[SSL] Findings:', result.findings.length);
    return NextResponse.json(result);
  } catch (err: unknown) {
    const message = toErrorMessage(err);
    console.error('[SSL] TLS inspection failed:', message);
    return unavailable(`TLS inspection failed: ${message}`);
  }
}
