-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Scans table
CREATE TABLE IF NOT EXISTS scans (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  url TEXT NOT NULL,
  domain TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'running', 'completed', 'failed')),
  overall_score INTEGER,
  risk_level TEXT CHECK (risk_level IN ('critical', 'high', 'medium', 'low')),
  ssl_grade TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  completed_at TIMESTAMPTZ
);

-- Findings table
CREATE TABLE IF NOT EXISTS findings (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  category TEXT NOT NULL CHECK (category IN ('ssl', 'headers', 'dns', 'observatory', 'cve')),
  title TEXT NOT NULL,
  severity TEXT NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
  description TEXT NOT NULL,
  mitigation TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- CVE Results table
CREATE TABLE IF NOT EXISTS cve_results (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  cve_id TEXT NOT NULL,
  cvss_score NUMERIC(4,1),
  description TEXT NOT NULL,
  published_date TEXT,
  nvd_url TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- DNS Records table
CREATE TABLE IF NOT EXISTS dns_records (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  type TEXT NOT NULL,
  value TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_scans_domain ON scans(domain);
CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_cve_results_scan_id ON cve_results(scan_id);
CREATE INDEX IF NOT EXISTS idx_dns_records_scan_id ON dns_records(scan_id);

-- Enable Row Level Security (RLS)
ALTER TABLE scans ENABLE ROW LEVEL SECURITY;
ALTER TABLE findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE cve_results ENABLE ROW LEVEL SECURITY;
ALTER TABLE dns_records ENABLE ROW LEVEL SECURITY;

-- Public read policies (adjust for auth as needed)
CREATE POLICY "Allow public read scans" ON scans FOR SELECT USING (true);
CREATE POLICY "Allow public read findings" ON findings FOR SELECT USING (true);
CREATE POLICY "Allow public read cve_results" ON cve_results FOR SELECT USING (true);
CREATE POLICY "Allow public read dns_records" ON dns_records FOR SELECT USING (true);

-- Service role write policies
CREATE POLICY "Allow service insert scans" ON scans FOR INSERT WITH CHECK (true);
CREATE POLICY "Allow service update scans" ON scans FOR UPDATE USING (true);
CREATE POLICY "Allow service insert findings" ON findings FOR INSERT WITH CHECK (true);
CREATE POLICY "Allow service insert cve_results" ON cve_results FOR INSERT WITH CHECK (true);
CREATE POLICY "Allow service insert dns_records" ON dns_records FOR INSERT WITH CHECK (true);
