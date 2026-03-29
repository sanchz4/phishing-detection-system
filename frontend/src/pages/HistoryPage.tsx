import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { HistoryTable } from '../components/HistoryTable';
import { Select } from '../components/ui/Select';
import { clearHistory, fetchHistory } from '../services/phishing';

export function HistoryPage() {
  const queryClient = useQueryClient();
  const [selected, setSelected] = useState('all');
  const riskOptions = [
    { label: 'All', value: 'all' },
    { label: 'Safe', value: 'safe' },
    { label: 'Suspicious', value: 'suspicious' },
    { label: 'Dangerous', value: 'dangerous' },
  ];
  const historyQuery = useQuery({
    queryKey: ['history', selected],
    queryFn: () => fetchHistory(selected),
  });
  const clearMutation = useMutation({
    mutationFn: clearHistory,
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ['history'] });
      await queryClient.invalidateQueries({ queryKey: ['stats'] });
    },
  });

  return (
    <div className="space-y-8">
      <section className="flex flex-col gap-4 rounded-[2rem] border border-cyan-400/15 bg-slate-950/60 p-6 md:flex-row md:items-center md:justify-between">
        <div>
          <p className="text-sm uppercase tracking-[0.25em] text-cyan-300">Scan History</p>
          <h1 className="mt-2 text-4xl font-semibold text-white">Review previous scan outcomes and filter by risk level.</h1>
        </div>
        <div className="flex items-center gap-3">
          <Select
            value={selected}
            onValueChange={(value) => {
              setSelected(value);
            }}
            options={riskOptions}
          />
          <button
            type="button"
            onClick={() => clearMutation.mutate()}
            className="rounded-full border border-rose-400/20 bg-rose-500/10 px-5 py-2 text-sm font-medium text-rose-200"
          >
            Clear history
          </button>
        </div>
      </section>

      {historyQuery.isLoading ? (
        <div className="rounded-[1.5rem] border border-cyan-400/15 bg-slate-950/50 p-6 text-sm text-slate-300">Loading saved scans...</div>
      ) : null}
      {historyQuery.isError ? (
        <div className="rounded-[1.5rem] border border-rose-500/20 bg-rose-500/10 p-6 text-sm text-rose-200">Unable to load scan history.</div>
      ) : null}
      {historyQuery.data ? <HistoryTable items={historyQuery.data.items} /> : null}
    </div>
  );
}
