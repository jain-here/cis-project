import { NextRequest, NextResponse } from 'next/server';
import type { DNSAnalysis } from '@/types';

const DOH_BASE = 'https://dns.google/resolve';
const RECORD_TYPES = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME'] as const;

async function fetchDNS(name: string, type: string): Promise<any> {
  const res = await fetch(`${DOH_BASE}?name=${encodeURIComponent(name)}&type=${type}`, {
    headers: { Accept: 'application/dns-json' },
    next: { revalidate: 0 },
  });
  if (!res.ok) return null;
  return res.json();
}

export async function GET(req: NextRequest) {
  const domain = req.nextUrl.searchParams.get('domain');
  if (!domain) {
    return NextResponse.json({ error: 'domain required' }, { status: 400 });
  }

  try {
    const results = await Promise.allSettled(
      RECORD_TYPES.map((type) => fetchDNS(domain, type))
    );

    const records: DNSAnalysis['records'] = [];
    const txtValues: string[] = [];

    for (let i = 0; i < RECORD_TYPES.length; i++) {
      const type = RECORD_TYPES[i];
      const result = results[i];
      if (result.status !== 'fulfilled' || !result.value?.Answer) continue;

      for (const answer of result.value.Answer) {
        const value = String(answer.data || '').trim().replace(/"/g, '');
        records.push({ type, value });
        if (type === 'TXT') txtValues.push(value.toLowerCase());
      }
    }

    // Check for SPF
    const hasSPF = txtValues.some((v) => v.startsWith('v=spf1'));
    // Check for DMARC
    const dmarcResult = await fetchDNS(`_dmarc.${domain}`, 'TXT');
    const hasDMARC =
      dmarcResult?.Answer?.some((a: any) =>
        String(a.data).toLowerCase().includes('v=dmarc1')
      ) ?? false;

    if (hasDMARC) {
      dmarcResult.Answer.forEach((a: any) => {
        records.push({ type: 'DMARC', value: String(a.data).replace(/"/g, '') });
      });
    }

    const findings: DNSAnalysis['findings'] = [];

    if (!hasSPF) {
      findings.push({
        category: 'dns',
        title: 'Missing SPF Record',
        severity: 'medium',
        description:
          'No SPF (Sender Policy Framework) TXT record found. This allows anyone to send email from your domain.',
        mitigation:
          'Add a TXT record: `v=spf1 include:your-mail-server.com ~all` to authorize mail senders.',
      });
    }

    if (!hasDMARC) {
      findings.push({
        category: 'dns',
        title: 'Missing DMARC Record',
        severity: 'medium',
        description:
          'No DMARC record found at _dmarc subdomain. DMARC prevents email spoofing and phishing.',
        mitigation:
          'Add a TXT record at _dmarc.yourdomain.com: `v=DMARC1; p=reject; rua=mailto:dmarc@yourdomain.com`',
      });
    }

    const result: DNSAnalysis = { records, findings };
    return NextResponse.json(result);
  } catch (err: any) {
    console.error('[dns]', err);
    return NextResponse.json({ error: err.message, records: [], findings: [] }, { status: 200 });
  }
}
