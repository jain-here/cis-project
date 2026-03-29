import type { Severity } from '@/types';

export function extractDomain(url: string): string {
  try {
    const u = new URL(url.startsWith('http') ? url : `https://${url}`);
    return u.hostname.replace(/^www\./, '');
  } catch {
    return url.replace(/^(https?:\/\/)?(www\.)?/, '').split('/')[0];
  }
}

export function normalizeUrl(url: string): string {
  if (!url.startsWith('http://') && !url.startsWith('https://')) {
    return `https://${url}`;
  }
  return url;
}

export function mapHeaderSeverity(header: string): Severity {
  const critical: string[] = [];
  const high = ['strict-transport-security', 'content-security-policy'];
  const medium = ['x-frame-options', 'x-content-type-options'];
  const low = ['referrer-policy', 'permissions-policy'];

  const h = header.toLowerCase();
  if (critical.includes(h)) return 'critical';
  if (high.includes(h)) return 'high';
  if (medium.includes(h)) return 'medium';
  if (low.includes(h)) return 'low';
  return 'info';
}

export function formatDate(dateStr: string | null): string {
  if (!dateStr) return 'N/A';
  try {
    return new Date(dateStr).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
    });
  } catch {
    return dateStr;
  }
}

export function cvssColor(score: number | null): string {
  if (score === null) return 'bg-gray-500';
  if (score >= 9.0) return 'bg-red-600';
  if (score >= 7.0) return 'bg-orange-500';
  if (score >= 4.0) return 'bg-yellow-500';
  return 'bg-blue-500';
}

export function truncate(str: string, maxLen: number): string {
  if (str.length <= maxLen) return str;
  return str.slice(0, maxLen) + '…';
}
