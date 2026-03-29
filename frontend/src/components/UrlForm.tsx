import { FormEvent, useState, useTransition } from 'react';

export function UrlForm({
  onSubmit,
}: {
  onSubmit: (urls: string[], comprehensive: boolean) => Promise<void>;
}) {
  const [value, setValue] = useState('');
  const [comprehensive, setComprehensive] = useState(true);
  const [isPending, startTransition] = useTransition();

  function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const urls = value
      .split('\n')
      .map((item) => item.trim())
      .filter(Boolean);
    startTransition(() => {
      void onSubmit(urls, comprehensive);
    });
  }

  return (
    <form
      onSubmit={handleSubmit}
      className="rounded-[1.75rem] border border-[color:var(--border)] bg-white/80 p-6 shadow-[0_20px_50px_rgba(19,33,43,0.08)]"
    >
      <div className="flex flex-col gap-4">
        <div>
          <label htmlFor="urls" className="text-sm font-semibold uppercase tracking-[0.18em] text-[color:var(--muted)]">
            Analyze URLs
          </label>
          <textarea
            id="urls"
            value={value}
            onChange={(event) => setValue(event.target.value)}
            rows={7}
            placeholder="https://example.com&#10;https://login-example-secure.com"
            className="mt-3 w-full rounded-[1.25rem] border border-slate-200 bg-slate-50 px-4 py-3 text-sm text-slate-900 outline-none transition focus:border-[color:var(--accent)] focus:bg-white"
          />
        </div>
        <label className="flex items-center gap-3 text-sm text-[color:var(--ink)]">
          <input
            type="checkbox"
            checked={comprehensive}
            onChange={(event) => setComprehensive(event.target.checked)}
            className="h-4 w-4 rounded border-slate-300 text-[color:var(--accent)] focus:ring-[color:var(--accent)]"
          />
          Run comprehensive crawling and HTML comparison
        </label>
        <button
          type="submit"
          disabled={isPending}
          className="inline-flex items-center justify-center rounded-full bg-[color:var(--ink)] px-5 py-3 text-sm font-semibold text-white transition hover:bg-slate-800 disabled:cursor-not-allowed disabled:opacity-60"
        >
          {isPending ? 'Analyzing...' : 'Start analysis'}
        </button>
      </div>
    </form>
  );
}
