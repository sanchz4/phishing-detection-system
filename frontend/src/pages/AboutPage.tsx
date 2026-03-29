export function AboutPage() {
  return (
    <div className="grid gap-6 lg:grid-cols-[0.9fr_1.1fr]">
      <section className="rounded-[2rem] border border-cyan-400/15 bg-slate-950/60 p-6">
        <p className="text-sm uppercase tracking-[0.3em] text-cyan-300">About Phishing</p>
        <h1 className="mt-3 text-4xl font-semibold text-white">What this tool protects against.</h1>
        <p className="mt-5 text-sm leading-8 text-slate-300">
          Phishing campaigns increasingly mix lookalike domains, HTTPS abuse, credential-harvest forms, QR lures, and AI-generated content.
          This dashboard combines reputation data, content classification, threat feeds, and explainable ML scoring to help analysts triage those attacks quickly.
        </p>
      </section>
      <section className="rounded-[2rem] border border-white/10 bg-white/5 p-6">
        <div className="space-y-5 text-sm leading-8 text-slate-300">
          <div>
            <h2 className="text-xl font-semibold text-white">How it works</h2>
            <p>
              The backend analyzes URLs and email content using lexical heuristics, RDAP and DNS checks, TLS inspection, HTML parsing, brand-lookalike scoring, threat-intelligence feeds, and an explainable ensemble model.
            </p>
          </div>
          <div>
            <h2 className="text-xl font-semibold text-white">Tech stack</h2>
            <p>FastAPI, SQLite, Selenium, scikit-learn, optional SHAP, React 18, TypeScript, Tailwind CSS, Radix UI, and Framer Motion.</p>
          </div>
          <div>
            <h2 className="text-xl font-semibold text-white">Why explainability matters</h2>
            <p>Security verdicts need traceable reasons. Each scan returns weighted signals, confidence, threat category, and human-readable explanations.</p>
          </div>
        </div>
      </section>
    </div>
  );
}
