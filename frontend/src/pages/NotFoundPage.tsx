import { Link } from 'react-router-dom';

export function NotFoundPage() {
  return (
    <div className="rounded-[2rem] border border-white/10 bg-slate-950/60 p-8 shadow-sm">
      <p className="text-sm uppercase tracking-[0.3em] text-cyan-300">404</p>
      <h2 className="mt-3 text-3xl font-semibold text-white">That route doesn’t exist.</h2>
      <p className="mt-3 text-sm leading-6 text-slate-400">The requested page isn’t part of the current dashboard navigation.</p>
      <Link to="/" className="mt-6 inline-flex rounded-full bg-cyan-400 px-5 py-3 text-sm font-semibold text-slate-950">
        Return home
      </Link>
    </div>
  );
}
