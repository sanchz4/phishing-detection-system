import * as ProgressPrimitive from '@radix-ui/react-progress';

export function Progress({ value }: { value: number }) {
  return (
    <ProgressPrimitive.Root className="relative h-3 w-full overflow-hidden rounded-full bg-white/10">
      <ProgressPrimitive.Indicator
        className="h-full rounded-full bg-gradient-to-r from-cyan-400 via-sky-400 to-blue-500 transition-all"
        style={{ transform: `translateX(-${100 - value}%)` }}
      />
    </ProgressPrimitive.Root>
  );
}
