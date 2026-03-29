'use client';

import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Cell,
} from 'recharts';
import { severityColor } from '@/lib/scoring';
import type { SeverityCount } from '@/types';

interface SeverityChartProps {
  data: SeverityCount[];
}

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'];

export function SeverityChart({ data }: SeverityChartProps) {
  const sorted = SEVERITY_ORDER.map((sev) => {
    const found = data.find((d) => d.severity === sev);
    return {
      severity: sev.charAt(0).toUpperCase() + sev.slice(1),
      count: found?.count || 0,
      rawSeverity: sev,
    };
  }).filter((d) => d.count > 0);

  if (sorted.length === 0) {
    return (
      <div className="flex items-center justify-center h-48 text-slate-500 text-sm">
        No findings data available
      </div>
    );
  }

  return (
    <ResponsiveContainer width="100%" height={220}>
      <BarChart data={sorted} margin={{ top: 5, right: 10, left: -20, bottom: 5 }}>
        <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
        <XAxis
          dataKey="severity"
          tick={{ fill: '#94a3b8', fontSize: 12 }}
          axisLine={{ stroke: '#1e293b' }}
        />
        <YAxis
          tick={{ fill: '#94a3b8', fontSize: 12 }}
          axisLine={{ stroke: '#1e293b' }}
          allowDecimals={false}
        />
        <Tooltip
          contentStyle={{
            backgroundColor: '#0f172a',
            border: '1px solid #1e293b',
            borderRadius: '8px',
            color: '#f1f5f9',
          }}
          cursor={{ fill: '#ffffff08' }}
        />
        <Bar dataKey="count" radius={[4, 4, 0, 0]}>
          {sorted.map((entry) => (
            <Cell
              key={entry.rawSeverity}
              fill={severityColor(entry.rawSeverity)}
            />
          ))}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}
