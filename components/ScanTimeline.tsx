'use client';

import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  ReferenceLine,
} from 'recharts';
import { formatDate } from '@/lib/utils';
import type { ScoreHistory } from '@/types';

interface ScanTimelineProps {
  data: ScoreHistory[];
}

export function ScanTimeline({ data }: ScanTimelineProps) {
  if (data.length < 2) {
    return (
      <div className="flex items-center justify-center h-48 text-slate-500 text-sm">
        Scan the same domain multiple times to see score trends
      </div>
    );
  }

  const chartData = data.map((d) => ({
    ...d,
    dateLabel: formatDate(d.date),
  }));

  return (
    <ResponsiveContainer width="100%" height={220}>
      <LineChart data={chartData} margin={{ top: 5, right: 10, left: -20, bottom: 5 }}>
        <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
        <XAxis
          dataKey="dateLabel"
          tick={{ fill: '#94a3b8', fontSize: 11 }}
          axisLine={{ stroke: '#1e293b' }}
        />
        <YAxis
          domain={[0, 100]}
          tick={{ fill: '#94a3b8', fontSize: 12 }}
          axisLine={{ stroke: '#1e293b' }}
        />
        <Tooltip
          contentStyle={{
            backgroundColor: '#0f172a',
            border: '1px solid #1e293b',
            borderRadius: '8px',
            color: '#f1f5f9',
          }}
          formatter={(value: number) => [`${value}`, 'Risk Score']}
          cursor={{ stroke: '#334155' }}
        />
        <ReferenceLine y={90} stroke="#22c55e" strokeDasharray="3 3" label={{ value: 'Low', fill: '#22c55e', fontSize: 10 }} />
        <ReferenceLine y={70} stroke="#f59e0b" strokeDasharray="3 3" label={{ value: 'Medium', fill: '#f59e0b', fontSize: 10 }} />
        <ReferenceLine y={50} stroke="#f97316" strokeDasharray="3 3" label={{ value: 'High', fill: '#f97316', fontSize: 10 }} />
        <Line
          type="monotone"
          dataKey="score"
          stroke="#06b6d4"
          strokeWidth={2}
          dot={{ fill: '#06b6d4', r: 4 }}
          activeDot={{ r: 6, fill: '#22d3ee' }}
        />
      </LineChart>
    </ResponsiveContainer>
  );
}
