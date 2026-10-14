/**
 * Type definitions for PhishGuard API communication
 */

export interface AnalyzeRequest {
  url: string;
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
