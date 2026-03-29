import { NextRequest, NextResponse } from 'next/server';
import { createServerClient } from '@/lib/supabase';
import { riskLevelColor, severityColor } from '@/lib/scoring';

import { formatDate } from '@/lib/utils';

export const dynamic = 'force-dynamic';

export async function GET(req: NextRequest) {
  const scanId = req.nextUrl.searchParams.get('scanId');
  if (!scanId) return NextResponse.json({ error: 'scanId required' }, { status: 400 });

  const supabase = createServerClient();

  const [scanRes, findingsRes, cvesRes, dnsRes] = await Promise.all([
    supabase.from('scans').select('*').eq('id', scanId).single(),
    supabase.from('findings').select('*').eq('scan_id', scanId).order('severity'),
    supabase.from('cve_results').select('*').eq('scan_id', scanId).order('cvss_score', { ascending: false }),
    supabase.from('dns_records').select('*').eq('scan_id', scanId),
  ]);

  if (!scanRes.data) return NextResponse.json({ error: 'Scan not found' }, { status: 404 });

  const scan = scanRes.data;
  const findings = findingsRes.data || [];
  const cves = cvesRes.data || [];
  const dnsRecords = dnsRes.data || [];

  const riskColor = riskLevelColor(scan.risk_level);

  const severityRows = ['critical', 'high', 'medium', 'low', 'info']
    .map((sev) => {
      const count = findings.filter((f: any) => f.severity === sev).length;
      return `<tr>
        <td style="padding:6px 12px;color:${severityColor(sev)};font-weight:700;text-transform:uppercase;font-size:11px">${sev}</td>
        <td style="padding:6px 12px;font-weight:700;font-size:14px">${count}</td>
      </tr>`;
    })
    .join('');

  const findingRows = findings
    .map(
      (f: any) => `
    <tr style="border-bottom:1px solid #1e293b">
      <td style="padding:8px 12px;font-size:11px;font-weight:700;color:${severityColor(f.severity)};text-transform:uppercase;white-space:nowrap">${f.severity}</td>
      <td style="padding:8px 12px;font-size:12px;color:#e2e8f0;font-weight:600">${f.title}</td>
      <td style="padding:8px 12px;font-size:11px;color:#94a3b8">${f.description}</td>
    </tr>`
    )
    .join('');

  const cveRows = cves
    .map(
      (c: any) => `
    <tr style="border-bottom:1px solid #1e293b">
      <td style="padding:8px 12px"><a href="${c.nvd_url}" style="color:#22d3ee;font-family:monospace;font-size:12px;font-weight:700">${c.cve_id}</a></td>
      <td style="padding:8px 12px;font-size:12px;font-weight:700;color:${c.cvss_score >= 9 ? '#ef4444' : c.cvss_score >= 7 ? '#f97316' : '#f59e0b'}">${c.cvss_score ?? '—'}</td>
      <td style="padding:8px 12px;font-size:11px;color:#94a3b8">${c.description.slice(0, 120)}${c.description.length > 120 ? '…' : ''}</td>
    </tr>`
    )
    .join('');

  const dnsGrouped = dnsRecords.reduce((acc: Record<string, string[]>, r: any) => {
    if (!acc[r.type]) acc[r.type] = [];
    acc[r.type].push(r.value);
    return acc;
  }, {});

  const dnsSection = Object.entries(dnsGrouped)
    .map(
      ([type, values]) => `
    <div style="margin-bottom:8px">
      <span style="font-family:monospace;font-size:11px;font-weight:700;color:#22d3ee">${type}</span>
      ${(values as string[]).map((v) => `<div style="font-family:monospace;font-size:11px;color:#94a3b8;padding-left:16px;margin-top:2px">${v}</div>`).join('')}
    </div>`
    )
    .join('');

  const html = `<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>SecureScan Report — ${scan.domain}</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #0f172a; color: #f1f5f9; padding: 40px; }
  table { width: 100%; border-collapse: collapse; }
  @media print {
    body { padding: 20px; }
    .no-print { display: none; }
  }
</style>
</head>
<body>
<!-- Header -->
<div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:40px;padding-bottom:24px;border-bottom:1px solid #1e293b">
  <div>
    <div style="font-size:11px;color:#64748b;text-transform:uppercase;letter-spacing:2px;margin-bottom:8px">SecureScan Security Report</div>
    <div style="font-size:32px;font-weight:900;font-family:monospace;color:#f1f5f9">${scan.domain}</div>
    <div style="font-size:13px;color:#64748b;margin-top:4px">${scan.url}</div>
    <div style="font-size:12px;color:#64748b;margin-top:2px">Scanned: ${formatDate(scan.created_at)}</div>
  </div>
  <div style="text-align:right">
    <div style="font-size:64px;font-weight:900;color:${riskColor};font-family:monospace;line-height:1">${scan.overall_score ?? '—'}</div>
    <div style="font-size:11px;color:#64748b;margin-bottom:6px">/ 100</div>
    <div style="display:inline-block;padding:4px 12px;border-radius:6px;border:1px solid ${riskColor}40;background:${riskColor}20;color:${riskColor};font-weight:700;font-size:12px">${(scan.risk_level ?? 'unknown').toUpperCase()} RISK</div>
    ${scan.ssl_grade ? `<div style="margin-top:8px;font-size:12px;color:#94a3b8">SSL Grade: <strong style="color:#93c5fd">${scan.ssl_grade}</strong></div>` : ''}
  </div>
</div>

<!-- Severity Summary -->
<div style="margin-bottom:32px">
  <div style="font-size:11px;color:#64748b;text-transform:uppercase;letter-spacing:2px;margin-bottom:12px">Finding Summary</div>
  <table style="width:auto">
    <tbody>${severityRows}</tbody>
  </table>
</div>

<!-- Findings -->
${findings.length > 0 ? `
<div style="margin-bottom:32px">
  <div style="font-size:11px;color:#64748b;text-transform:uppercase;letter-spacing:2px;margin-bottom:12px">All Findings (${findings.length})</div>
  <table>
    <thead>
      <tr style="border-bottom:1px solid #334155">
        <th style="padding:8px 12px;text-align:left;font-size:11px;color:#64748b;font-weight:600">SEVERITY</th>
        <th style="padding:8px 12px;text-align:left;font-size:11px;color:#64748b;font-weight:600">TITLE</th>
        <th style="padding:8px 12px;text-align:left;font-size:11px;color:#64748b;font-weight:600">DESCRIPTION</th>
      </tr>
    </thead>
    <tbody>${findingRows}</tbody>
  </table>
</div>` : ''}

<!-- CVEs -->
${cves.length > 0 ? `
<div style="margin-bottom:32px">
  <div style="font-size:11px;color:#64748b;text-transform:uppercase;letter-spacing:2px;margin-bottom:12px">CVE Findings (${cves.length})</div>
  <table>
    <thead>
      <tr style="border-bottom:1px solid #334155">
        <th style="padding:8px 12px;text-align:left;font-size:11px;color:#64748b;font-weight:600">CVE ID</th>
        <th style="padding:8px 12px;text-align:left;font-size:11px;color:#64748b;font-weight:600">CVSS</th>
        <th style="padding:8px 12px;text-align:left;font-size:11px;color:#64748b;font-weight:600">DESCRIPTION</th>
      </tr>
    </thead>
    <tbody>${cveRows}</tbody>
  </table>
</div>` : ''}

<!-- DNS -->
${dnsRecords.length > 0 ? `
<div style="margin-bottom:32px">
  <div style="font-size:11px;color:#64748b;text-transform:uppercase;letter-spacing:2px;margin-bottom:12px">DNS Records</div>
  ${dnsSection}
</div>` : ''}

<!-- Footer -->
<div style="margin-top:40px;padding-top:16px;border-top:1px solid #1e293b;font-size:11px;color:#475569;text-align:center">
  Generated by SecureScan · ${new Date().toUTCString()}
</div>
</body>
</html>`;

  return new NextResponse(html, {
    headers: {
      'Content-Type': 'text/html; charset=utf-8',
      'Content-Disposition': `inline; filename="securescan-${scan.domain}-${scan.id.slice(0, 8)}.html"`,
    },
  });
}
