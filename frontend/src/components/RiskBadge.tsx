import { AlertTriangle, HelpCircle, ShieldAlert, ShieldCheck } from "lucide-react";
import { cn } from "../lib/utils";
import { classificationLabel } from "../lib/utils";

const styles: Record<string, { className: string; icon: typeof ShieldCheck }> = {
  low: { className: "bg-emerald-950 text-emerald-300 border-emerald-700", icon: ShieldCheck },
  medium: { className: "bg-amber-950 text-amber-300 border-amber-700", icon: AlertTriangle },
  high: { className: "bg-red-950 text-red-300 border-red-700", icon: ShieldAlert },
  unknown: { className: "bg-slate-800 text-slate-200 border-slate-500", icon: HelpCircle },
};

export function RiskBadge({ value, score }: { value: string; score?: number | null }) {
  const key = styles[value] ? value : "unknown";
  const Icon = styles[key].icon;
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded-full border px-3 py-1 text-xs font-medium",
        styles[key].className,
      )}
    >
      <Icon className="h-3.5 w-3.5" aria-hidden="true" />
      <span>{classificationLabel(value)}</span>
      {typeof score === "number" && <span className="font-mono text-[11px]">score {score}</span>}
    </span>
  );
}
