import { useMutation } from '@tanstack/react-query';
import { useState } from 'react';
import { LoadingPanel } from '../components/LoadingPanel';
import { ResultTable } from '../components/ResultTable';
import { StatusCard } from '../components/StatusCard';
import { UrlForm } from '../components/UrlForm';
import { useDashboardData } from '../hooks/useDashboardData';
import { analyzeUrls, DetectionResult } from '../services/phishing';

export function HomePage() {
  const [results, setResults] = useState<DetectionResult[]>([]);
  const { health, config } = useDashboardData();
  const analyzeMutation = useMutation({
    mutationFn: ({ urls, comprehensive }: { urls: string[]; comprehensive: boolean }) =>
      analyzeUrls(urls, comprehensive),
    onSuccess: (payload) => setResults(payload.results),
  });

  async function handleSubmit(urls: string[], comprehensive: boolean) {
    if (urls.length === 0) {
      return;
    }
    await analyzeMutation.mutateAsync({ urls, comprehensive });
  }

  return (
    <div className="grid gap-8 lg:grid-cols-[1.15fr_0.85fr]">
      <section className="space-y-6">
        <UrlForm onSubmit={handleSubmit} />
        {analyzeMutation.isPending ? <LoadingPanel label="Submitting analysis request to backend..." /> : null}
        {analyzeMutation.isError ? (
          <div className="rounded-[1.5rem] border border-rose-200 bg-rose-50 p-5 text-sm text-rose-700">
            Unable to analyze the requested URLs. Please confirm the backend is running and reachable.
          </div>
        ) : null}
        <ResultTable results={results} />
      </section>

      <section className="space-y-6">
        {health.isLoading ? <LoadingPanel label="Checking backend readiness..." /> : null}
        {health.data ? (
          <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-1">
            <StatusCard title="API status" value={health.data.status} tone="safe" description="FastAPI backend is reachable and serving the dashboard." />
            <StatusCard
              title="Chrome driver"
              value={health.data.chrome_available ? 'Ready' : 'Unavailable'}
              tone={health.data.chrome_available ? 'safe' : 'warn'}
              description="Selenium-backed screenshot capture depends on this runtime."
            />
            <StatusCard
              title="Model runtime"
              value={health.data.tensorflow_available ? 'TensorFlow' : 'Fallback'}
              tone={health.data.tensorflow_available ? 'safe' : 'warn'}
              description="If TensorFlow is missing, image matching falls back to histogram-based comparison."
            />
          </div>
        ) : null}

        <div className="rounded-[1.75rem] border border-[color:var(--border)] bg-white/80 p-6 shadow-sm">
          <p className="text-sm uppercase tracking-[0.18em] text-[color:var(--muted)]">Protected banks</p>
          {config.isLoading ? (
            <div className="mt-4 text-sm text-[color:var(--muted)]">Loading bank catalog...</div>
          ) : (
            <div className="mt-4 flex flex-wrap gap-3">
              {config.data?.banks.map((bank) => (
                <span key={bank.short_name} className="rounded-full bg-slate-100 px-4 py-2 text-sm text-slate-700">
                  {bank.name}
                </span>
              ))}
            </div>
          )}
        </div>
      </section>
    </div>
  );
}
