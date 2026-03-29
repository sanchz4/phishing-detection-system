import { DetectionResult } from '../services/phishing';

export function ResultTable({ results }: { results: DetectionResult[] }) {
  if (results.length === 0) {
    return (
      <div className="rounded-[1.5rem] border border-dashed border-slate-300 bg-white/60 p-6 text-sm text-[color:var(--muted)]">
        No analyses yet. Submit one or more URLs to see the risk summary here.
      </div>
    );
  }

  return (
    <div className="overflow-hidden rounded-[1.75rem] border border-[color:var(--border)] bg-white/80 shadow-sm">
      <table className="min-w-full divide-y divide-slate-200 text-left text-sm">
        <thead className="bg-slate-50/80">
          <tr>
            <th className="px-4 py-3 font-semibold text-slate-700">URL</th>
            <th className="px-4 py-3 font-semibold text-slate-700">Status</th>
            <th className="px-4 py-3 font-semibold text-slate-700">Confidence</th>
            <th className="px-4 py-3 font-semibold text-slate-700">Target</th>
            <th className="px-4 py-3 font-semibold text-slate-700">Flow</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-100">
          {results.map((result) => (
            <tr key={`${result.url}-${result.timestamp}`} className="align-top">
              <td className="px-4 py-4 text-slate-900">{result.url}</td>
              <td className="px-4 py-4">
                <span
                  className={
                    result.is_phishing
                      ? 'rounded-full bg-rose-100 px-3 py-1 text-xs font-semibold text-rose-700'
                      : result.confidence >= 0.4
                        ? 'rounded-full bg-amber-100 px-3 py-1 text-xs font-semibold text-amber-700'
                        : 'rounded-full bg-emerald-100 px-3 py-1 text-xs font-semibold text-emerald-700'
                  }
                >
                  {result.is_phishing ? 'Phishing' : result.confidence >= 0.4 ? 'Suspicious' : 'Legitimate'}
                </span>
              </td>
              <td className="px-4 py-4 text-slate-700">{result.confidence.toFixed(3)}</td>
              <td className="px-4 py-4 text-slate-700">{result.target_bank_name ?? 'Unknown'}</td>
              <td className="px-4 py-4 text-slate-700">{result.analysis_type}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
