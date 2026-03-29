import { api } from './api';

export interface BankSummary {
  name: string;
  short_name: string;
  url: string;
}

export interface DetectionResult {
  url: string;
  timestamp: string;
  is_phishing: boolean;
  confidence: number;
  target_bank?: string | null;
  target_bank_name?: string | null;
  analysis_type: string;
  errors: string[];
}

export async function fetchConfig() {
  const response = await api.get<{ banks: BankSummary[]; thresholds: Record<string, number> }>('/api/config');
  return response.data;
}

export async function fetchHealth() {
  const response = await api.get<{ status: string; chrome_available: boolean; tensorflow_available: boolean; banks_configured: number }>('/api/health');
  return response.data;
}

export async function analyzeUrls(urls: string[], comprehensive: boolean) {
  const response = await api.post<{ results: DetectionResult[] }>('/api/analyze', { urls, comprehensive });
  return response.data;
}
