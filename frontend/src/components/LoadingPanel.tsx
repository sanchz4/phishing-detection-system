export function LoadingPanel({ label }: { label: string }) {
  return (
    <div className="rounded-[1.5rem] border border-[color:var(--border)] bg-white/70 p-6 shadow-sm">
      <div className="flex items-center gap-3 text-sm text-[color:var(--muted)]">
        <span className="h-3 w-3 animate-pulse rounded-full bg-[color:var(--accent)]" />
        {label}
      </div>
    </div>
  );
}
