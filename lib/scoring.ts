import type { Finding, CVEResult, RiskLevel } from '@/types';

const SSL_GRADE_SCORES: Record<string, number> = {
  'A+': 100,
  A: 90,
  B: 75,
  C: 60,
  D: 40,
  F: 0,
  T: 30,
  M: 30,
};

export function calculateRiskScore(params: {
  sslGrade: string | null;
  sslAvailable: boolean;
  observatoryAvailable: boolean;
  findings: Omit<Finding, 'id' | 'scan_id'>[];
  cves: Omit<CVEResult, 'id' | 'scan_id'>[];
}): { score: number | null; riskLevel: RiskLevel } {
  const { sslGrade, sslAvailable, observatoryAvailable, findings, cves } = params;

  // Both checks are now self-hosted — they fail only when the target domain
  // itself is unreachable. If BOTH fail we have no data and return null.
  // If only one fails we score from what we have with a neutral base.
  if (!sslAvailable && !observatoryAvailable) {
    return { score: null, riskLevel: 'unknown' };
  }

  // Base score:
  // • SSL available with grade: blend grade in (A+ → 100, F → 60)
  // • SSL unavailable (target unreachable for TLS): neutral 80
  let score: number;

  if (sslAvailable && sslGrade) {
    const gradeScore = SSL_GRADE_SCORES[sslGrade] ?? 50;
    score = 60 + gradeScore * 0.4;
  } else {
    // SSL unavailable — neutral starting point, no penalty, no credit
    score = 80;
  }

  // Deduct for findings
  for (const finding of findings) {
    switch (finding.category) {
      case 'headers':
        if (finding.severity === 'critical' || finding.severity === 'high') score -= 15;
        else if (finding.severity === 'medium') score -= 8;
        else if (finding.severity === 'low') score -= 3;
        break;
      case 'dns':
        score -= 5;
        break;
      case 'ssl':
        // Only deduct SSL findings if we actually have SSL data
        if (sslAvailable) {
          if (finding.severity === 'critical') score -= 10;
          else if (finding.severity === 'high') score -= 7;
          else if (finding.severity === 'medium') score -= 4;
        }
        break;
      case 'observatory':
        if (finding.severity === 'high') score -= 8;
        else if (finding.severity === 'medium') score -= 4;
        break;
      // CVE findings are handled below via the cves array
    }
  }

  // Deduct for CVEs
  for (const cve of cves) {
    if (cve.cvss_score !== null) {
      if (cve.cvss_score >= 9.0) score -= 20;
      else if (cve.cvss_score >= 7.0) score -= 12;
      else if (cve.cvss_score >= 4.0) score -= 5;
    }
  }

  score = Math.max(0, Math.min(100, Math.round(score)));

  const riskLevel: RiskLevel =
    score >= 90 ? 'low'
    : score >= 70 ? 'medium'
    : score >= 50 ? 'high'
    : 'critical';

  return { score, riskLevel };
}

export function riskLevelColor(level: RiskLevel | null): string {
  switch (level) {
    case 'low':      return '#22c55e';
    case 'medium':   return '#f59e0b';
    case 'high':     return '#f97316';
    case 'critical': return '#ef4444';
    case 'unknown':  return '#94a3b8';
    default:         return '#6b7280';
  }
}

export function severityColor(severity: string): string {
  switch (severity) {
    case 'critical': return '#ef4444';
    case 'high':     return '#f97316';
    case 'medium':   return '#f59e0b';
    case 'low':      return '#3b82f6';
    case 'info':     return '#6b7280';
    default:         return '#6b7280';
  }
}
