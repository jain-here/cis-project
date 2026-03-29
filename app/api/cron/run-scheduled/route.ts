import { NextRequest, NextResponse } from 'next/server';
import { createServerClient } from '@/lib/supabase';

export const dynamic = 'force-dynamic';

// This route is called by Vercel Cron or an external scheduler
// Add to vercel.json: { "crons": [{ "path": "/api/cron/run-scheduled", "schedule": "0 * * * *" }] }
export async function GET(req: NextRequest) {
  // Verify cron secret to prevent unauthorized calls
  const authHeader = req.headers.get('authorization');
  if (
    process.env.CRON_SECRET &&
    authHeader !== `Bearer ${process.env.CRON_SECRET}`
  ) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  const supabase = createServerClient();
  const baseUrl = process.env.NEXT_PUBLIC_APP_URL || 'http://localhost:3000';

  // Find all active scheduled scans that are due
  const { data: dueScans } = await supabase
    .from('scheduled_scans')
    .select('*')
    .eq('is_active', true)
    .lte('next_run_at', new Date().toISOString());

  if (!dueScans || dueScans.length === 0) {
    return NextResponse.json({ message: 'No scans due', ran: 0 });
  }

  const results = await Promise.allSettled(
    dueScans.map(async (schedule: any) => {
      // Trigger a new scan
      const res = await fetch(`${baseUrl}/api/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: schedule.url }),
      });
      const data = await res.json();

      if (!data.scanId) throw new Error(`Failed to scan ${schedule.domain}`);

      // Update schedule record
      const nextRun = new Date();
      if (schedule.frequency === 'daily') nextRun.setDate(nextRun.getDate() + 1);
      else if (schedule.frequency === 'weekly') nextRun.setDate(nextRun.getDate() + 7);
      else nextRun.setMonth(nextRun.getMonth() + 1);

      await supabase
        .from('scheduled_scans')
        .update({
          last_scan_id: data.scanId,
          last_run_at: new Date().toISOString(),
          next_run_at: nextRun.toISOString(),
        })
        .eq('id', schedule.id);

      return { domain: schedule.domain, scanId: data.scanId };
    })
  );

  const succeeded = results.filter((r) => r.status === 'fulfilled').length;
  const failed = results.filter((r) => r.status === 'rejected').length;

  return NextResponse.json({ ran: succeeded, failed, total: dueScans.length });
}
