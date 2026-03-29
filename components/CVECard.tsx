'use client';

import type { CVEResult } from '@/types';
import { cvssColor, formatDate, truncate } from '@/lib/utils';

interface CVECardProps {
  cve: CVEResult;
}

export function CVECard({ cve }: CVECardProps) {
  const colorClass = cvssColor(cve.cvss_score);

  return (
    <div className="rounded-xl border border-white/10 bg-white/5 p-4 hover:bg-white/8 transition-colors">
      <div className="flex items-start justify-between gap-3 mb-2">
        <a
          href={cve.nvd_url}
          target="_blank"
          rel="noopener noreferrer"
          className="text-sm font-mono font-bold text-cyan-400 hover:text-cyan-300 hover:underline transition-colors"
        >
          {cve.cve_id}
        </a>
        {cve.cvss_score !== null && (
          <span
            className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-bold text-white ${colorClass}`}
          >
            CVSS {cve.cvss_score.toFixed(1)}
          </span>
        )}
      </div>
      <p className="text-sm text-slate-300 leading-relaxed mb-2">
        {truncate(cve.description, 200)}
      </p>
      {cve.published_date && (
        <p className="text-xs text-slate-500">
          Published: {formatDate(cve.published_date)}
        </p>
      )}
    </div>
  );
}
