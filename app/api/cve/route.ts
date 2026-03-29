import { NextRequest, NextResponse } from 'next/server';
import type { CVEAnalysis } from '@/types';

const NVD_BASE = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
const CVE_ALLOWLIST = new Set(['nginx', 'apache', 'iis', 'node.js', 'express']);
const CVE_BLOCKLIST = new Set(['server', 'cloudfront', 'gws', 'elb', 'akamai']);

function normalizeKeyword(value: string): string {
  return value
    .toLowerCase()
    .trim()
    .replace(/\(.*?\)/g, ' ')
    .replace(/[;,]/g, ' ')
    .split(/[\/\s]+/)
    .find(Boolean) || '';
}

export async function GET(req: NextRequest) {
  const keyword = req.nextUrl.searchParams.get('keyword');
  if (!keyword) {
    return NextResponse.json({ error: 'keyword required' }, { status: 400 });
  }

  const normalizedKeyword = normalizeKeyword(keyword);
  if (!normalizedKeyword || CVE_BLOCKLIST.has(normalizedKeyword) || !CVE_ALLOWLIST.has(normalizedKeyword)) {
    return NextResponse.json({ cves: [], findings: [], skipped: true, reason: 'No meaningful technology detected for CVE lookup' });
  }

  try {
    const params = new URLSearchParams({
      keywordSearch: normalizedKeyword,
      resultsPerPage: '5',
    });

    const res = await fetch(`${NVD_BASE}?${params}`, {
      headers: {
        'User-Agent': 'SecureScan/1.0',
        ...(process.env.NVD_API_KEY
          ? { apiKey: process.env.NVD_API_KEY }
          : {}),
      },
      next: { revalidate: 3600 },
    });

    if (!res.ok) {
      return NextResponse.json({ cves: [], findings: [] });
    }

    const data = await res.json();
    const vulnerabilities = data.vulnerabilities || [];

    const cves: CVEAnalysis['cves'] = vulnerabilities.map((item: any) => {
      const cve = item.cve;
      const cveId: string = cve.id;
      const description: string =
        cve.descriptions?.find((d: any) => d.lang === 'en')?.value ||
        'No description available.';

      // Get CVSS score (prefer v3.1 > v3.0 > v2)
      let cvssScore: number | null = null;
      const metrics = cve.metrics || {};
      if (metrics.cvssMetricV31?.length) {
        cvssScore = metrics.cvssMetricV31[0].cvssData?.baseScore ?? null;
      } else if (metrics.cvssMetricV30?.length) {
        cvssScore = metrics.cvssMetricV30[0].cvssData?.baseScore ?? null;
      } else if (metrics.cvssMetricV2?.length) {
        cvssScore = metrics.cvssMetricV2[0].cvssData?.baseScore ?? null;
      }

      return {
        cve_id: cveId,
        cvss_score: cvssScore,
        description,
        published_date: cve.published || null,
        nvd_url: `https://nvd.nist.gov/vuln/detail/${cveId}`,
      };
    });

    const findings: CVEAnalysis['findings'] = cves
      .filter((c) => c.cvss_score !== null && c.cvss_score >= 7.0)
      .map((c) => ({
        category: 'cve' as const,
        title: `CVE: ${c.cve_id} (CVSS ${c.cvss_score})`,
        severity: (c.cvss_score ?? 0) >= 9.0 ? 'critical' : 'high',
        description: c.description,
        mitigation: `Review and apply patches for ${c.cve_id}. See: ${c.nvd_url}`,
      }));

    const result: CVEAnalysis = { cves, findings };
    return NextResponse.json(result);
  } catch (err: any) {
    console.error('[cve]', err);
    return NextResponse.json(
      { error: err.message, cves: [], findings: [] },
      { status: 200 }
    );
  }
}
