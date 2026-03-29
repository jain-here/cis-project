-- Phase 2 additions — run after schema.sql

-- Scheduled rescans table
CREATE TABLE IF NOT EXISTS scheduled_scans (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  domain TEXT NOT NULL,
  url TEXT NOT NULL,
  frequency TEXT NOT NULL DEFAULT 'weekly' CHECK (frequency IN ('daily', 'weekly', 'monthly')),
  last_scan_id UUID REFERENCES scans(id),
  last_run_at TIMESTAMPTZ,
  next_run_at TIMESTAMPTZ,
  is_active BOOLEAN NOT NULL DEFAULT true,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Alerts table — stores score delta notifications
CREATE TABLE IF NOT EXISTS scan_alerts (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  domain TEXT NOT NULL,
  scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  previous_score INTEGER,
  new_score INTEGER,
  delta INTEGER GENERATED ALWAYS AS (new_score - previous_score) STORED,
  risk_level TEXT,
  alerted_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_scheduled_scans_next_run ON scheduled_scans(next_run_at) WHERE is_active = true;
CREATE INDEX IF NOT EXISTS idx_scan_alerts_domain ON scan_alerts(domain);

ALTER TABLE scheduled_scans ENABLE ROW LEVEL SECURITY;
ALTER TABLE scan_alerts ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Allow public read scheduled_scans" ON scheduled_scans FOR SELECT USING (true);
CREATE POLICY "Allow service write scheduled_scans" ON scheduled_scans FOR ALL WITH CHECK (true);
CREATE POLICY "Allow public read scan_alerts" ON scan_alerts FOR SELECT USING (true);
CREATE POLICY "Allow service write scan_alerts" ON scan_alerts FOR ALL WITH CHECK (true);
