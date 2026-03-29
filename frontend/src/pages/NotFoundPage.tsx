import { Link } from 'react-router-dom';

export function NotFoundPage() {
  return (
    <div className="rounded-[2rem] border border-[color:var(--border)] bg-white/80 p-8 shadow-sm">
      <p className="text-sm uppercase tracking-[0.3em] text-[color:var(--muted)]">404</p>
      <h2 className="mt-3 text-3xl font-semibold text-[color:var(--ink)]">That route doesn’t exist.</h2>
      <p className="mt-3 text-sm leading-6 text-[color:var(--muted)]">The dashboard only exposes the main analysis view right now.</p>
      <Link to="/" className="mt-6 inline-flex rounded-full bg-[color:var(--ink)] px-5 py-3 text-sm font-semibold text-white">
        Return home
      </Link>
    </div>
  );
}
