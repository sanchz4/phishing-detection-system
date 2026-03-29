import { useMutation, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { ResultCard } from '../components/ResultCard';
import { analyzeInput } from '../services/phishing';

export function ScanPage() {
  const [input, setInput] = useState('');
  const [inputType, setInputType] = useState<'auto' | 'url' | 'email'>('auto');
  const [comprehensive, setComprehensive] = useState(true);
  const queryClient = useQueryClient();
  const mutation = useMutation({
    mutationFn: analyzeInput,
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ['history'] });
      await queryClient.invalidateQueries({ queryKey: ['stats'] });
    },
  });

  return (
    <div className="space-y-8">
      <section className="rounded-[2rem] border border-cyan-400/15 bg-slate-950/60 p-6">
        <p className="text-sm uppercase tracking-[0.3em] text-cyan-300">Main Scanner</p>
        <h1 className="mt-3 text-4xl font-semibold text-white">Analyze a suspicious URL or phishing email sample.</h1>
        <div className="mt-6 grid gap-4 md:grid-cols-[0.2fr_1fr]">
          <select
            value={inputType}
            onChange={(event) => setInputType(event.target.value as 'auto' | 'url' | 'email')}
            className="rounded-2xl border border-white/10 bg-slate-900 px-4 py-3 text-sm text-slate-100"
          >
            <option value="auto">Auto detect</option>
            <option value="url">URL</option>
            <option value="email">Email content</option>
          </select>
          <textarea
            value={input}
            onChange={(event) => setInput(event.target.value)}
            rows={8}
            placeholder="Paste a URL or email content here..."
            className="w-full rounded-[1.5rem] border border-white/10 bg-slate-950 px-4 py-4 text-sm text-slate-100 outline-none"
          />
        </div>
        <div className="mt-4 flex flex-wrap items-center gap-4">
          <label className="flex items-center gap-3 text-sm text-slate-300">
            <input type="checkbox" checked={comprehensive} onChange={(event) => setComprehensive(event.target.checked)} />
            Enable comprehensive visual and HTML analysis
          </label>
          <button
            type="button"
            onClick={() => mutation.mutate({ input, inputType, comprehensive })}
            disabled={!input.trim() || mutation.isPending}
            className="rounded-full bg-cyan-400 px-6 py-3 text-sm font-semibold text-slate-950 disabled:cursor-not-allowed disabled:opacity-60"
          >
            {mutation.isPending ? 'Analyzing...' : 'Analyze'}
          </button>
        </div>
      </section>

      {mutation.isError ? (
        <div className="rounded-[1.5rem] border border-rose-500/20 bg-rose-500/10 p-5 text-sm text-rose-200">
          The scan request failed. Check backend connectivity and try again.
        </div>
      ) : null}

      {mutation.isPending ? (
        <div className="rounded-[1.5rem] border border-cyan-400/15 bg-slate-950/50 p-6 text-sm text-slate-300">
          Running URL heuristics, content analysis, threat-feed lookups, and explainable ensemble scoring...
        </div>
      ) : null}

      {mutation.data ? <ResultCard result={mutation.data} /> : null}
    </div>
  );
}
