import { Progress } from './ui/Progress';

export function RiskGauge({ score }: { score: number }) {
  const tone =
    score >= 70
      ? 'from-rose-400 to-red-500'
      : score >= 40
        ? 'from-amber-300 to-orange-400'
        : 'from-emerald-300 to-cyan-400';

  return (
    <div className="rounded-3xl border border-white/10 bg-white/5 p-5">
      <div className="flex items-end justify-between gap-4">
        <div>
          <p className="text-xs uppercase tracking-[0.25em] text-slate-400">Risk Score</p>
          <p className={`mt-3 text-5xl font-semibold text-transparent bg-gradient-to-r ${tone} bg-clip-text`}>{score}</p>
        </div>
        <div className="h-24 w-24 rounded-full border border-cyan-400/20 bg-slate-950/80 p-3">
          <div className="flex h-full items-center justify-center rounded-full border border-white/10 text-sm text-slate-300">
            /100
          </div>
        </div>
      </div>
      <div className="mt-5">
        <Progress value={score} />
      </div>
    </div>
  );
}
