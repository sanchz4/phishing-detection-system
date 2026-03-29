export function ErrorBoundaryPage() {
  return (
    <div className="rounded-[2rem] border border-rose-200 bg-rose-50 p-8 text-rose-700 shadow-sm">
      <h2 className="text-2xl font-semibold">The dashboard hit an unexpected error.</h2>
      <p className="mt-3 text-sm leading-6">Refresh the page or restart the frontend if the route state became inconsistent.</p>
    </div>
  );
}
