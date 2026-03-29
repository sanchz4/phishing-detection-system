import { Outlet } from 'react-router-dom';

export function AppShell() {
  return (
    <main className="min-h-screen px-4 py-8 md:px-8">
      <div className="mx-auto flex max-w-6xl flex-col gap-8">
        <header className="rounded-[2rem] border border-[color:var(--border)] bg-[color:var(--panel)] p-6 shadow-[0_30px_80px_rgba(19,33,43,0.08)] backdrop-blur">
          <p className="text-sm uppercase tracking-[0.35em] text-[color:var(--muted)]">Phishing Defense Platform</p>
          <div className="mt-4 flex flex-col gap-3 md:flex-row md:items-end md:justify-between">
            <div>
              <h1 className="max-w-2xl text-4xl font-semibold tracking-tight text-[color:var(--ink)] md:text-5xl">
                Modern bank-phishing triage with a typed API and live dashboard.
              </h1>
              <p className="mt-3 max-w-2xl text-base leading-7 text-[color:var(--muted)]">
                Analyze suspicious URLs, inspect backend readiness, and review the current bank target set from one place.
              </p>
            </div>
            <div className="rounded-3xl bg-[color:var(--accent-soft)] px-4 py-3 text-sm font-medium text-[color:var(--ink)]">
              React + Vite + Tailwind + React Query
            </div>
          </div>
        </header>
        <Outlet />
      </div>
    </main>
  );
}
