import { createClient } from '@supabase/supabase-js';

const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL!;
const supabaseAnonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!;

export const supabase = createClient(supabaseUrl, supabaseAnonKey);

// Server-side client with service role key (for API routes)
export function createServerClient() {
  const serviceKey = process.env.SUPABASE_SERVICE_KEY!;
  return createClient(supabaseUrl, serviceKey, {
    auth: { persistSession: false },
  });
}
