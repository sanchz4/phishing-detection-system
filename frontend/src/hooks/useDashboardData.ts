import { useQuery } from '@tanstack/react-query';
import { fetchConfig, fetchHealth } from '../services/phishing';

export function useDashboardData() {
  const health = useQuery({ queryKey: ['health'], queryFn: fetchHealth });
  const config = useQuery({ queryKey: ['config'], queryFn: fetchConfig });
  return { health, config };
}
