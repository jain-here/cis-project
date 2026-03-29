'use client';

import { useState, useEffect } from 'react';
import { supabase } from '@/lib/supabase';
import { formatDate } from '@/lib/utils';
import { riskLevelColor } from '@/lib/scoring';
import type { RiskLevel } from '@/types';

interface ScheduledScan {
  id: string;
  domain: string;
  url: string;
  frequency: 'daily' | 'weekly' | 'monthly';
  last_run_at: string | null;
  next_run_at: string | null;
  is_active: boolean;
  created_at: string;
}

const FREQ_LABELS = {
  daily: 'Every day',
  weekly: 'Every week',
  monthly: 'Every month',
};

export default function SchedulePage() {
  const [schedules, setSchedules] = useState<ScheduledScan[]>([]);
  const [loading, setLoading] = useState(true);
  const [url, setUrl] = useState('');
  const [frequency, setFrequency] = useState<'daily' | 'weekly' | 'monthly'>('weekly');
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    supabase
      .from('scheduled_scans')
      .select('*')
      .order('created_at', { ascending: false })
      .then(({ data }) => {
        if (data) setSchedules(data as ScheduledScan[]);
        setLoading(false);
      });
  }, []);

  function nextRunDate(freq: string): string {
    const d = new Date();
    if (freq === 'daily') d.setDate(d.getDate() + 1);
    else if (freq === 'weekly') d.setDate(d.getDate() + 7);
    else d.setMonth(d.getMonth() + 1);
    return d.toISOString();
  }

  async function handleAdd(e: React.FormEvent) {
    e.preventDefault();
    if (!url.trim()) return;
    setSaving(true);
    setError('');

    const domain = url.trim().replace(/^https?:\/\/(www\.)?/, '').split('/')[0];
    const normalizedUrl = url.startsWith('http') ? url.trim() : `https://${url.trim()}`;

    const { data, error: insertError } = await supabase
      .from('scheduled_scans')
      .insert({
        domain,
        url: normalizedUrl,
        frequency,
        next_run_at: nextRunDate(frequency),
        is_active: true,
      })
      .select()
      .single();

    if (insertError) {
      setError(insertError.message);
    } else if (data) {
      setSchedules((prev) => [data as ScheduledScan, ...prev]);
      setUrl('');
    }
    setSaving(false);
  }

  async function toggleActive(id: string, current: boolean) {
    await supabase.from('scheduled_scans').update({ is_active: !current }).eq('id', id);
    setSchedules((prev) =>
      prev.map((s) => (s.id === id ? { ...s, is_active: !current } : s))
    );
  }

  async function deleteSchedule(id: string) {
    await supabase.from('scheduled_scans').delete().eq('id', id);
    setSchedules((prev) => prev.filter((s) => s.id !== id));
  }

  return (
    <div className="max-w-4xl mx-auto px-4 py-10">
      <div className="mb-8">
        <h1 className="text-2xl font-black text-white">Scheduled Scans</h1>
        <p className="text-sm text-slate-500 mt-1">
          Automatically rescan domains on a schedule to track security changes over time
        </p>
      </div>

      {/* Add schedule form */}
      <div className="rounded-2xl border border-white/10 bg-white/5 p-6 mb-8">
        <h2 className="text-xs font-semibold text-slate-400 uppercase tracking-widest mb-4">
          Add Scheduled Scan
        </h2>
        <form onSubmit={handleAdd} className="flex gap-3 flex-wrap">
          <input
            type="text"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="Domain or URL (e.g. example.com)"
            className="flex-1 min-w-[200px] bg-white/5 border border-white/10 rounded-xl px-4 py-3 text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500/50 text-sm"
          />
          <select
            value={frequency}
            onChange={(e) => setFrequency(e.target.value as any)}
            className="bg-white/5 border border-white/10 rounded-xl px-4 py-3 text-white focus:outline-none focus:border-cyan-500/50 text-sm"
          >
            <option value="daily" className="bg-slate-900">Daily</option>
            <option value="weekly" className="bg-slate-900">Weekly</option>
            <option value="monthly" className="bg-slate-900">Monthly</option>
          </select>
          <button
            type="submit"
            disabled={saving || !url.trim()}
            className="px-6 py-3 bg-cyan-500 hover:bg-cyan-400 disabled:bg-slate-700 disabled:text-slate-500 text-black font-bold rounded-xl transition-all text-sm"
          >
            {saving ? 'Saving…' : 'Schedule'}
          </button>
        </form>
        {error && (
          <p className="text-red-400 text-xs mt-3">{error}</p>
        )}
        <p className="text-xs text-slate-600 mt-3">
          ℹ️ Scheduled scans are triggered via a cron job or external scheduler calling <code className="text-slate-400 font-mono">/api/rescan</code>. Configure your Vercel Cron or external service to call <code className="text-slate-400 font-mono">/api/cron/run-scheduled</code> at your desired interval.
        </p>
      </div>

      {/* Schedule list */}
      {loading ? (
        <div className="text-slate-500 text-sm animate-pulse">Loading schedules…</div>
      ) : schedules.length === 0 ? (
        <div className="text-center py-12 text-slate-600">
          <div className="text-3xl mb-3">⏰</div>
          <p className="text-sm">No scheduled scans yet. Add one above.</p>
        </div>
      ) : (
        <div className="rounded-2xl border border-white/10 bg-white/5 overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-white/5">
                <th className="text-left px-5 py-3 text-slate-500 font-medium">Domain</th>
                <th className="text-left px-5 py-3 text-slate-500 font-medium">Frequency</th>
                <th className="text-left px-5 py-3 text-slate-500 font-medium">Next Run</th>
                <th className="text-left px-5 py-3 text-slate-500 font-medium">Last Run</th>
                <th className="text-left px-5 py-3 text-slate-500 font-medium">Status</th>
                <th className="px-5 py-3" />
              </tr>
            </thead>
            <tbody>
              {schedules.map((s) => (
                <tr key={s.id} className="border-b border-white/5 last:border-0 hover:bg-white/3 transition-colors">
                  <td className="px-5 py-3 font-mono text-cyan-400 text-xs">{s.domain}</td>
                  <td className="px-5 py-3 text-slate-300 text-xs">{FREQ_LABELS[s.frequency]}</td>
                  <td className="px-5 py-3 text-slate-400 text-xs">{formatDate(s.next_run_at)}</td>
                  <td className="px-5 py-3 text-slate-500 text-xs">{s.last_run_at ? formatDate(s.last_run_at) : '—'}</td>
                  <td className="px-5 py-3">
                    <button
                      onClick={() => toggleActive(s.id, s.is_active)}
                      className={`text-xs px-2 py-0.5 rounded-full border font-medium transition-colors ${
                        s.is_active
                          ? 'bg-green-500/10 text-green-400 border-green-500/30 hover:bg-red-500/10 hover:text-red-400 hover:border-red-500/30'
                          : 'bg-slate-500/10 text-slate-500 border-slate-500/30 hover:bg-green-500/10 hover:text-green-400 hover:border-green-500/30'
                      }`}
                    >
                      {s.is_active ? 'Active' : 'Paused'}
                    </button>
                  </td>
                  <td className="px-5 py-3 text-right">
                    <button
                      onClick={() => deleteSchedule(s.id)}
                      className="text-xs text-slate-600 hover:text-red-400 transition-colors"
                    >
                      Delete
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
