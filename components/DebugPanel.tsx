'use client';

import { useEffect, useState } from 'react';

type LogLevel = 'log' | 'error' | 'warn' | 'info';

interface LogEntry {
  timestamp: string;
  level: LogLevel;
  message: string;
}

export function DebugPanel() {
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [isOpen, setIsOpen] = useState(false);
  const [filter, setFilter] = useState<LogLevel | 'all'>('all');

  useEffect(() => {
    // Capture console.log
    const originalLog = console.log;
    console.log = (...args: any[]) => {
      originalLog(...args);
      const message = args.map((arg) =>
        typeof arg === 'object' ? JSON.stringify(arg, null, 2) : String(arg)
      ).join(' ');
      addLog('log', message);
    };

    // Capture console.error
    const originalError = console.error;
    console.error = (...args: any[]) => {
      originalError(...args);
      const message = args.map((arg) =>
        typeof arg === 'object' ? JSON.stringify(arg, null, 2) : String(arg)
      ).join(' ');
      addLog('error', message);
    };

    // Capture console.warn
    const originalWarn = console.warn;
    console.warn = (...args: any[]) => {
      originalWarn(...args);
      const message = args.map((arg) =>
        typeof arg === 'object' ? JSON.stringify(arg, null, 2) : String(arg)
      ).join(' ');
      addLog('warn', message);
    };

    // Capture console.info
    const originalInfo = console.info;
    console.info = (...args: any[]) => {
      originalInfo(...args);
      const message = args.map((arg) =>
        typeof arg === 'object' ? JSON.stringify(arg, null, 2) : String(arg)
      ).join(' ');
      addLog('info', message);
    };

    return () => {
      console.log = originalLog;
      console.error = originalError;
      console.warn = originalWarn;
      console.info = originalInfo;
    };
  }, []);

  const addLog = (level: LogLevel, message: string) => {
    setLogs((prev) => [
      ...prev,
      {
        timestamp: new Date().toLocaleTimeString(),
        level,
        message,
      },
    ]);
  };

  const levelColors: Record<LogLevel, string> = {
    log: 'text-slate-400',
    error: 'text-red-400',
    warn: 'text-yellow-400',
    info: 'text-blue-400',
  };

  const levelBgColors: Record<LogLevel, string> = {
    log: 'bg-slate-500/10',
    error: 'bg-red-500/10',
    warn: 'bg-yellow-500/10',
    info: 'bg-blue-500/10',
  };

  const filteredLogs = filter === 'all' ? logs : logs.filter((l) => l.level === filter);

  return (
    <div className="fixed bottom-4 right-4 z-50">
      {/* Toggle button */}
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="px-3 py-2 rounded-lg bg-slate-900/80 border border-slate-700 text-xs text-slate-300 hover:text-white transition-colors font-mono"
      >
        🐛 {logs.length} logs
      </button>

      {/* Debug panel */}
      {isOpen && (
        <div className="mt-2 w-96 rounded-lg border border-slate-700 bg-slate-900/95 p-4 max-h-[500px] flex flex-col">
          <div className="flex items-center justify-between mb-3">
            <h3 className="text-xs font-bold text-white">Debug Console</h3>
            <button
              onClick={() => setLogs([])}
              className="text-xs px-2 py-0.5 rounded bg-slate-700/50 hover:bg-slate-700 text-slate-400 transition-colors"
            >
              Clear
            </button>
          </div>

          {/* Filters */}
          <div className="flex gap-1 mb-3 flex-wrap">
            {(['all', 'log', 'error', 'warn', 'info'] as const).map((f) => (
              <button
                key={f}
                onClick={() => setFilter(f)}
                className={`text-xs px-2 py-0.5 rounded transition-colors ${
                  filter === f
                    ? 'bg-slate-700 text-white'
                    : 'bg-slate-800/50 text-slate-500 hover:text-slate-300'
                }`}
              >
                {f === 'all' ? 'All' : f.toUpperCase()}
              </button>
            ))}
          </div>

          {/* Logs */}
          <div className="overflow-y-auto flex-1 space-y-1 text-xs font-mono bg-black/20 rounded p-2">
            {filteredLogs.length === 0 ? (
              <div className="text-slate-600">No logs yet...</div>
            ) : (
              filteredLogs.map((log, i) => (
                <div
                  key={i}
                  className={`${levelBgColors[log.level]} ${levelColors[log.level]} p-1.5 rounded break-words`}
                >
                  <span className="text-slate-600">[{log.timestamp}]</span>{' '}
                  <span className="font-bold">{log.level.toUpperCase()}:</span> {log.message}
                </div>
              ))
            )}
          </div>
        </div>
      )}
    </div>
  );
}
