import clsx from 'clsx';

export function StatusCard({
  title,
  value,
  tone = 'neutral',
  description,
}: {
  title: string;
  value: string;
  tone?: 'neutral' | 'safe' | 'warn';
  description: string;
}) {
  return (
    <article
      className={clsx(
        'rounded-[1.5rem] border p-5 shadow-sm backdrop-blur',
        tone === 'safe' && 'border-emerald-200 bg-emerald-50/90',
        tone === 'warn' && 'border-amber-200 bg-amber-50/90',
        tone === 'neutral' && 'border-[color:var(--border)] bg-white/75',
      )}
    >
      <p className="text-sm uppercase tracking-[0.2em] text-[color:var(--muted)]">{title}</p>
      <p className="mt-3 text-3xl font-semibold text-[color:var(--ink)]">{value}</p>
      <p className="mt-2 text-sm leading-6 text-[color:var(--muted)]">{description}</p>
    </article>
  );
}
