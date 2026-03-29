import { HistoryRecord } from '../services/phishing';

export function HistoryTable({ items }: { items: HistoryRecord[] }) {
  if (items.length === 0) {
    return (
      <div className="rounded-[1.75rem] border border-dashed border-cyan-400/20 bg-slate-950/50 p-8 text-sm text-slate-400">
        No scan history yet. Run a scan and the latest results will appear here.
      </div>
    );
  }

  return (
    <div className="overflow-hidden rounded-[1.75rem] border border-white/10 bg-slate-950/60">
      <table className="min-w-full divide-y divide-white/10 text-left text-sm">
        <thead className="bg-white/5 text-slate-400">
          <tr>
            <th className="px-4 py-3 font-medium">Input</th>
            <th className="px-4 py-3 font-medium">Score</th>
            <th className="px-4 py-3 font-medium">Category</th>
            <th className="px-4 py-3 font-medium">Confidence</th>
            <th className="px-4 py-3 font-medium">Timestamp</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-white/5">
          {items.map((item) => (
            <tr key={item.id} className="text-slate-200">
              <td className="max-w-[460px] px-4 py-4">
                <div className="line-clamp-2">{item.input_value}</div>
                <div className="mt-1 text-xs uppercase tracking-[0.2em] text-slate-500">{item.input_type}</div>
              </td>
              <td className="px-4 py-4">{item.risk_score}</td>
              <td className="px-4 py-4 capitalize">{item.threat_category}</td>
              <td className="px-4 py-4">{Math.round(item.confidence * 100)}%</td>
              <td className="px-4 py-4">{new Date(item.scanned_at).toLocaleString()}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
