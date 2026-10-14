/**
 * Type definitions for PhishGuard API communication
 */

export interface AnalyzeRequest {
  url: string;
}

export interface ThreatIntelProviderResult {
  provider: string;
  status:
    | "malicious_match"
    | "no_match_found"
    | "unknown"
    | "unavailable"
    | "error"
    | "not_configured";
  status_label: string;
  evidence: string;
  checked_at: string;
  explanation: string;
}

export interface ThreatIntelSummary {
  status: "malicious_match" | "clean_matches" | "inconclusive" | "not_configured";
  summary: string;
  configured_providers_count: number;
  total_providers_count: number;
  malicious_count: number;
}

export interface AnalyzeResponse {
  url: string;
  prediction: "legitimate" | "phishing";
  label: 1 | 0;
  probability: number;
  risk_score: number;
  model_version?: string;
  model_type?: string;
  feature_count?: number;
  phishing_probability?: number;
  analyzed_at?: string;
  features?: Record<string, any>;
  threat_intel_providers?: ThreatIntelProviderResult[];
  threat_intel_summary?: ThreatIntelSummary;
  ai_explanation?: string | null;
  ai_explanation_available?: boolean;
}

export interface HealthResponse {
  status: string;
  model: string;
  model_loaded: boolean;
}

export interface ApiError {
  message: string;
  statusCode?: number;
  detail?: string;
}

export type AnalysisStatus = "idle" | "loading" | "success" | "error";
