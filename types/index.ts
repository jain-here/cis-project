export type RiskLevel = 'critical' | 'high' | 'medium' | 'low' | 'unknown';
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type ScanStatus = 'pending' | 'running' | 'completed' | 'partial' | 'failed';
export type ConfidenceLevel = 'high' | 'medium' | 'low';

export interface Scan {
  id: string;
  url: string;
  domain: string;
  status: ScanStatus;
  overall_score: number | null;
  risk_level: RiskLevel | null;
  ssl_grade: string | null;
  created_at: string;
  completed_at: string | null;
  notes: string | null;  // JSON array of unavailable API reasons
}

export interface Finding {
  id: string;
  scan_id: string;
  category: 'ssl' | 'headers' | 'dns' | 'observatory' | 'cve';
  title: string;
  severity: Severity;
  description: string;
  mitigation: string | null;
  confidence?: ConfidenceLevel;
}

export interface CVEResult {
  id: string;
  scan_id: string;
  cve_id: string;
  cvss_score: number | null;
  description: string;
  published_date: string | null;
  nvd_url: string;
}

export interface DNSRecord {
  id: string;
  scan_id: string;
  type: string;
  value: string;
}

// API response shapes
export interface SSLAnalysis {
  available?: boolean;
  reason?: string;
  retryAttempts?: number;
  grade: string;
  certExpiry: string | null;
  protocols: string[];
  vulnerabilities: string[];
  findings: Omit<Finding, 'id' | 'scan_id'>[];
}

export interface HeadersAnalysis {
  headers: Record<string, string>;
  findings: Omit<Finding, 'id' | 'scan_id'>[];
}

export interface DNSAnalysis {
  records: Omit<DNSRecord, 'id' | 'scan_id'>[];
  findings: Omit<Finding, 'id' | 'scan_id'>[];
}

export interface ObservatoryAnalysis {
  available?: boolean;
  reason?: string;
  retryAttempts?: number;
  score: number | null;
  grade: string | null;
  findings: Omit<Finding, 'id' | 'scan_id'>[];
}

export interface CVEAnalysis {
  cves: Omit<CVEResult, 'id' | 'scan_id'>[];
  findings: Omit<Finding, 'id' | 'scan_id'>[];
}

export interface ScanRequest {
  url: string;
}

export interface ScanResponse {
  scanId: string;
}

export interface FinalScanResponse {
  status: 'complete' | 'partial';
  score: number | null;
  riskLevel: RiskLevel;
  confidence: ConfidenceLevel;
  findings: Omit<Finding, 'id' | 'scan_id'>[];
  meta: {
    sslAvailable: boolean;
    observatoryAvailable: boolean;
    retries: {
      ssl: number;
      observatory: number;
    };
  };
}

export interface FullScanResult {
  scan: Scan;
  findings: Finding[];
  cves: CVEResult[];
  dnsRecords: DNSRecord[];
}

export interface SeverityCount {
  severity: Severity;
  count: number;
}

export interface ScoreHistory {
  date: string;
  score: number;
  domain: string;
}
