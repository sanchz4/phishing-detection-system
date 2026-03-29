import { api } from './api';

export type ThreatCategory = 'safe' | 'suspicious' | 'dangerous';

export interface BankSummary {
  name: string;
  short_name: string;
  url: string;
}

export interface DetectionResult {
  id: string;
  input_value: string;
  input_type: string;
  scanned_at: string;
  risk_score: number;
  threat_category: ThreatCategory;
  confidence: number;
  confidence_level: 'low' | 'medium' | 'high';
  target_brand?: string | null;
  explanation: string;
  reasons: string[];
  explanation_items: Array<{ label: string; value: number | string; detail: string }>;
  threat_feeds: Record<string, unknown>;
  heuristics: Record<string, unknown>;
  reputation: Record<string, unknown>;
  ssl_analysis: Record<string, unknown>;
  html_analysis: Record<string, unknown>;
  brand_impersonation: Record<string, unknown>;
  content_analysis: Record<string, unknown>;
  qr_analysis: Record<string, unknown>;
  explainability: { method?: string; top_features?: Array<{ feature: string; impact: number }> };
  model_scores: Record<string, unknown>;
  raw_detector: Record<string, unknown>;
  errors: string[];
}

export interface HistoryRecord {
  id: string;
  input_value: string;
  input_type: string;
  risk_score: number;
  threat_category: ThreatCategory;
  confidence: number;
  confidence_level: string;
  scanned_at: string;
  explanation: string;
}

export async function fetchConfig() {
  const response = await api.get<{
    banks: BankSummary[];
    thresholds: Record<string, number>;
    detector_checks: string[];
    supported_inputs: string[];
  }>('/config');
  return response.data;
}

export async function fetchHealth() {
  const response = await api.get<{
    status: string;
    chrome_available: boolean;
    tensorflow_available: boolean;
    banks_configured: number;
    history_backend: string;
    explainability_available: boolean;
  }>('/health');
  return response.data;
}

export async function fetchStats() {
  const response = await api.get<{
    total_scans: number;
    dangerous_scans: number;
    suspicious_scans: number;
    safe_scans: number;
    average_risk_score: number;
    latest_scan_at?: string | null;
  }>('/stats');
  return response.data;
}

export async function analyzeInput(payload: {
  input: string;
  inputType: 'auto' | 'url' | 'email';
  comprehensive: boolean;
}) {
  const response = await api.post<{ results: DetectionResult[] }>('/analyze', {
    inputs: [payload.input],
    input_type: payload.inputType,
    comprehensive: payload.comprehensive,
  });
  return response.data.results[0];
}

export async function fetchHistory(riskLevel: string) {
  const response = await api.get<{
    items: HistoryRecord[];
    total: number;
  }>('/history', {
    params: riskLevel && riskLevel !== 'all' ? { risk_level: riskLevel } : {},
  });
  return response.data;
}

export async function clearHistory() {
  await api.delete('/history');
}
