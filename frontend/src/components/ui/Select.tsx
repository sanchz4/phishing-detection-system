import * as SelectPrimitive from '@radix-ui/react-select';

export function Select({
  value,
  onValueChange,
  options,
}: {
  value: string;
  onValueChange: (value: string) => void;
  options: Array<{ label: string; value: string }>;
}) {
  return (
    <SelectPrimitive.Root value={value} onValueChange={onValueChange}>
      <SelectPrimitive.Trigger className="inline-flex min-w-[180px] items-center justify-between rounded-full border border-cyan-400/20 bg-slate-900/80 px-4 py-2 text-sm text-slate-100 outline-none">
        <SelectPrimitive.Value />
        <SelectPrimitive.Icon className="text-cyan-300">▾</SelectPrimitive.Icon>
      </SelectPrimitive.Trigger>
      <SelectPrimitive.Portal>
        <SelectPrimitive.Content className="overflow-hidden rounded-2xl border border-cyan-400/20 bg-slate-950 shadow-2xl">
          <SelectPrimitive.Viewport className="p-2">
            {options.map((option) => (
              <SelectPrimitive.Item
                key={option.value}
                value={option.value}
                className="cursor-pointer rounded-xl px-3 py-2 text-sm text-slate-200 outline-none data-[highlighted]:bg-cyan-400/15"
              >
                <SelectPrimitive.ItemText>{option.label}</SelectPrimitive.ItemText>
              </SelectPrimitive.Item>
            ))}
          </SelectPrimitive.Viewport>
        </SelectPrimitive.Content>
      </SelectPrimitive.Portal>
    </SelectPrimitive.Root>
  );
}
