export type RiskClassification = "low" | "medium" | "high" | "unknown";

export interface Finding {
  type: string;
  title: string;
  severity: string;
  status: string;
  evidence: string;
  explanation: string;
  why_it_matters: string;
  suggested_action: string;
  source: string;
  score_contribution?: number;
}

export interface ProviderResult {
  provider: string;
  status: string;
  threat_categories: string[];
  summary: string;
  explanation: string;
  limitations: string;
  stats: Record<string, unknown>;
  error?: string | null;
}

export interface ScanRecord {
  id: string;
  status: string;
  submitted_url: string;
  normalized_url: string;
  display_url: string;
  hostname: string;
  registrable_domain: string;
  created_at: string;
  completed_at?: string | null;
  risk_score: number;
  risk_classification: RiskClassification;
  risk: {
    score: number;
    classification: string;
    label: string;
    confidence: string;
    evidence_quality: string;
    methodology: string;
    confirmed_threat_providers: string[];
  };
  assessment: string;
  recommendations: string[];
  findings: Finding[];
  finding_count: number;
  providers: ProviderResult[];
  dns: Record<string, unknown>;
  tls: Record<string, unknown>;
  redirects: Record<string, unknown>;
  incomplete_checks: string[];
  local_only: boolean;
  limitations: string[];
}

export interface ScanSummary {
  id: string;
  display_url: string;
  hostname: string;
  risk_score: number | null;
  risk_classification: string;
  status: string;
  created_at: string;
  completed_at?: string | null;
}

export interface StatsResponse {
  total: number;
  high: number;
  medium: number;
  low: number;
  unknown: number;
  incomplete: number;
  recent: ScanSummary[];
  persistence: string;
}

export interface HealthResponse {
  status: string;
  service: string;
  version: string;
  database: { enabled: boolean; ok: boolean; mode: string };
  integrations: {
    google_safe_browsing: string;
    virustotal: string;
    external_intel_enabled: boolean;
  };
}
