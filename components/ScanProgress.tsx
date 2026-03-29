'use client';

import type { ScanStatus } from '@/types';

type StepKey = 'ssl' | 'headers' | 'dns' | 'observatory' | 'cve' | 'score';
type StepState = 'pending' | 'completed' | 'unavailable';

const STEPS: Array<{ key: StepKey; label: string }> = [
  { key: 'ssl', label: 'SSL Certificate Check' },
  { key: 'headers', label: 'Security Headers Analysis' },
  { key: 'dns', label: 'DNS Records Lookup' },
  { key: 'observatory', label: 'Mozilla Observatory Scan' },
  { key: 'cve', label: 'CVE Vulnerability Lookup' },
  { key: 'score', label: 'Calculating Risk Score' },
];

interface ScanProgressProps {
  status: ScanStatus;
  stepStatus?: Partial<Record<StepKey, StepState>>;
}

export function ScanProgress({ status, stepStatus = {} }: ScanProgressProps) {
  const resolvedSteps = STEPS.map((step) => ({
    ...step,
    state: stepStatus[step.key] ?? 'pending',
  }));

  const currentStep = Math.max(
    resolvedSteps.findIndex((step) => step.state === 'pending'),
    0
  );

  if (status === 'completed' || status === 'failed') {
    return null;
  }

  return (
    <div className="rounded-2xl border border-white/10 bg-white/5 p-6">
      <h3 className="text-sm font-semibold text-slate-400 uppercase tracking-widest mb-4">
        Scan Progress
      </h3>
      <div className="space-y-3">
        {resolvedSteps.map((step, i) => {
          const done = step.state === 'completed';
          const unavailable = step.state === 'unavailable';
          const active = step.state === 'pending' && i === currentStep;
          return (
            <div key={step.label} className="flex items-center gap-3">
              <div
                className={`w-5 h-5 rounded-full flex-shrink-0 flex items-center justify-center text-xs
                  ${done ? 'bg-green-500' : unavailable ? 'bg-yellow-500 text-black font-bold' : active ? 'bg-cyan-500 animate-pulse' : 'bg-slate-700'}`}
              >
                {done ? '✓' : unavailable ? '!' : active ? '…' : ''}
              </div>
              <span
                className={`text-sm ${done ? 'text-slate-400 line-through' : unavailable ? 'text-yellow-300' : active ? 'text-cyan-300 font-medium' : 'text-slate-600'}`}
              >
                {step.label}
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
}
