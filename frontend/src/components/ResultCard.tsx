import { DetectionResult } from '../services/phishing';
import { RiskGauge } from './RiskGauge';

export function ResultCard({ result }: { result: DetectionResult }) {
  const badgeClass =
    result.threat_category === 'dangerous'
      ? 'bg-rose-500/15 text-rose-300 border-rose-400/25'
      : result.threat_category === 'suspicious'
        ? 'bg-amber-500/15 text-amber-300 border-amber-400/25'
        : 'bg-emerald-500/15 text-emerald-300 border-emerald-400/25';

  return (
    <section className="grid gap-6 rounded-[2rem] border border-cyan-400/15 bg-slate-950/60 p-6 shadow-[0_18px_60px_rgba(0,0,0,0.35)] lg:grid-cols-[0.8fr_1.2fr]">
      <RiskGauge score={result.risk_score} />
      <div className="space-y-5">
        <div className="flex flex-wrap items-center gap-3">
          <span className={`rounded-full border px-4 py-2 text-sm font-medium capitalize ${badgeClass}`}>{result.threat_category}</span>
          <span className="rounded-full border border-cyan-400/20 bg-cyan-400/10 px-4 py-2 text-sm text-cyan-200">
            Confidence {Math.round(result.confidence * 100)}%
          </span>
          <span className="rounded-full border border-white/10 px-4 py-2 text-sm text-slate-300">
            {result.input_type === 'email' ? 'Email content' : 'URL scan'}
          </span>
        </div>
        <div>
          <p className="text-sm uppercase tracking-[0.22em] text-slate-400">Primary Finding</p>
          <h2 className="mt-2 text-2xl font-semibold text-white">{result.explanation}</h2>
          <p className="mt-3 text-sm leading-7 text-slate-300">
            {result.target_brand ? `Likely impersonated brand: ${result.target_brand}. ` : ''}
            Confidence level is {result.confidence_level}.
          </p>
        </div>
        <div className="grid gap-4 md:grid-cols-2">
          <div className="rounded-2xl border border-white/10 bg-white/5 p-4">
            <p className="text-sm font-medium text-cyan-300">Why it was flagged</p>
            <ul className="mt-3 space-y-2 text-sm text-slate-300">
              {result.reasons.map((reason) => (
                <li key={reason}>• {reason}</li>
              ))}
            </ul>
          </div>
          <div className="rounded-2xl border border-white/10 bg-white/5 p-4">
            <p className="text-sm font-medium text-cyan-300">Feature breakdown</p>
            <ul className="mt-3 space-y-2 text-sm text-slate-300">
              {result.explanation_items.map((item) => (
                <li key={item.label}>
                  {item.label}: <span className="text-white">{item.value}</span>
                </li>
              ))}
            </ul>
          </div>
        </div>
      </div>
    </section>
  );
}
