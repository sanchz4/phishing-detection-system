export function ErrorBoundaryPage() {
  return (
    <div className="rounded-[2rem] border border-rose-500/25 bg-rose-500/10 p-8 text-rose-200 shadow-sm">
      <h2 className="text-2xl font-semibold">The dashboard hit an unexpected error.</h2>
      <p className="mt-3 text-sm leading-6">Refresh the page or return to the landing page if the current route became inconsistent.</p>
    </div>
  );
}
