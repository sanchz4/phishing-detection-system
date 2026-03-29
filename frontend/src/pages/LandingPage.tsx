import { motion } from 'framer-motion';
import { Link } from 'react-router-dom';
import { useDashboardData } from '../hooks/useDashboardData';

export function LandingPage() {
  const { config, stats } = useDashboardData();
  const detectorChecks = config.data?.detector_checks ?? [
    'URL heuristics',
    'TLS certificate validation',
    'Threat-feed correlation',
    'Explainable ensemble scoring',
  ];
  const statusMessage = config.isError || stats.isError ? 'Live metrics unavailable until the backend responds.' : null;

  return (
    <div className="space-y-10">
      {statusMessage ? (
        <div className="rounded-[1.5rem] border border-amber-400/20 bg-amber-500/10 px-5 py-4 text-sm text-amber-200">
          {statusMessage}
        </div>
      ) : null}
      <section className="grid gap-8 lg:grid-cols-[1.15fr_0.85fr] lg:items-center">
        <div>
          <motion.p initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} className="text-sm uppercase tracking-[0.45em] text-cyan-300/80">
            Advanced Threat Triage
          </motion.p>
          <motion.h1
            initial={{ opacity: 0, y: 24 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.1 }}
            className="mt-5 max-w-4xl text-5xl font-semibold leading-tight text-white md:text-7xl"
          >
            Detect modern phishing, quishing, impersonation, and zero-day lure patterns.
          </motion.h1>
          <motion.p
            initial={{ opacity: 0, y: 24 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.18 }}
            className="mt-6 max-w-2xl text-lg leading-8 text-slate-300"
          >
            URL heuristics, TLS validation, HTML analysis, threat feeds, explainable ensemble scoring, and brand-lookalike checks in one security-focused workflow.
          </motion.p>
          <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.25 }} className="mt-8 flex flex-wrap gap-4">
            <Link to="/scan" className="rounded-full bg-cyan-400 px-6 py-3 text-sm font-semibold text-slate-950 shadow-[0_0_40px_rgba(34,211,238,0.35)]">
              Scan Now
            </Link>
            <Link to="/about" className="rounded-full border border-white/12 px-6 py-3 text-sm font-semibold text-white">
              Learn how it works
            </Link>
          </motion.div>
        </div>
        <div className="rounded-[2rem] border border-cyan-400/15 bg-white/5 p-6 shadow-[0_20px_70px_rgba(0,0,0,0.35)]">
          <p className="text-sm uppercase tracking-[0.25em] text-cyan-300">Checks Included</p>
          <div className="mt-5 grid gap-3">
            {detectorChecks.map((check) => (
              <div key={check} className="rounded-2xl border border-white/10 bg-slate-950/70 px-4 py-3 text-sm text-slate-200">
                {check}
              </div>
            ))}
          </div>
        </div>
      </section>

      <section className="grid gap-4 rounded-[2rem] border border-white/10 bg-white/5 p-6 md:grid-cols-4">
        <StatCard label="Threats logged" value={stats.data?.total_scans ?? 0} />
        <StatCard label="Dangerous findings" value={stats.data?.dangerous_scans ?? 0} />
        <StatCard label="Average risk" value={`${Math.round(stats.data?.average_risk_score ?? 0)} / 100`} />
        <StatCard label="Protected brands" value={config.data?.banks.length ?? 0} />
      </section>

      <section className="grid gap-6 md:grid-cols-3">
        {[
          ['Inspect', 'The engine scores URLs and email content using lexical, certificate, DNS, HTML, and threat-feed signals.'],
          ['Explain', 'Each verdict includes a risk score, category, confidence level, and feature-level explanation.'],
          ['Track', 'Every scan is written to a local SQLite history so analysts can review suspicious activity over time.'],
        ].map(([title, description], index) => (
          <motion.article
            key={title}
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.1 * index }}
            className="rounded-[1.75rem] border border-white/10 bg-slate-950/60 p-6"
          >
            <div className="flex h-10 w-10 items-center justify-center rounded-full bg-cyan-400/15 text-cyan-300">{index + 1}</div>
            <h2 className="mt-5 text-2xl font-semibold text-white">{title}</h2>
            <p className="mt-3 text-sm leading-7 text-slate-300">{description}</p>
          </motion.article>
        ))}
      </section>
    </div>
  );
}

function StatCard({ label, value }: { label: string; value: number | string }) {
  return (
    <div className="rounded-[1.5rem] border border-cyan-400/10 bg-slate-950/70 p-5">
      <p className="text-xs uppercase tracking-[0.25em] text-slate-500">{label}</p>
      <p className="mt-3 text-3xl font-semibold text-cyan-300">{value}</p>
    </div>
  );
}
