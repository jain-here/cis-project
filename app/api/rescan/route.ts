import { NextRequest, NextResponse } from 'next/server';
import { createServerClient } from '@/lib/supabase';

export const dynamic = 'force-dynamic';

export async function POST(req: NextRequest) {
  const { scanId } = await req.json().catch(() => ({}));
  if (!scanId) return NextResponse.json({ error: 'scanId required' }, { status: 400 });

  const supabase = createServerClient();

  const { data: originalScan } = await supabase
    .from('scans')
    .select('url')
    .eq('id', scanId)
    .single();

  if (!originalScan) {
    return NextResponse.json({ error: 'Original scan not found' }, { status: 404 });
  }

  // Trigger a new scan with the same URL
  const baseUrl = process.env.NEXT_PUBLIC_APP_URL || 'http://localhost:3000';
  const res = await fetch(`${baseUrl}/api/scan`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url: originalScan.url }),
  });

  if (!res.ok) {
    return NextResponse.json({ error: 'Failed to start rescan' }, { status: 500 });
  }

  const data = await res.json();
  return NextResponse.json({ scanId: data.scanId });
}
