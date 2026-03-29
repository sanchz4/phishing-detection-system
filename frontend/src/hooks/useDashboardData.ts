import { useQuery } from '@tanstack/react-query';
import { fetchConfig, fetchHealth, fetchStats } from '../services/phishing';

export function useDashboardData() {
  const health = useQuery({ queryKey: ['health'], queryFn: fetchHealth });
  const config = useQuery({ queryKey: ['config'], queryFn: fetchConfig });
  const stats = useQuery({ queryKey: ['stats'], queryFn: fetchStats });
  return { health, config, stats };
}
