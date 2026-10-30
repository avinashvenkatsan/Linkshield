import { Link } from "react-router-dom";

export function Logo({ compact = false }: { compact?: boolean }) {
  return (
    <Link to="/" className="flex items-center gap-2 text-white" aria-label="LinkShield home">
      <svg viewBox="0 0 64 64" className="h-9 w-9" role="img" aria-hidden="true">
        <path
          d="M32 8L52 16V32C52 44 32 56 32 56C32 56 12 44 12 32V16L32 8Z"
          fill="#121a32"
          stroke="#3b82f6"
          strokeWidth="2.5"
        />
        <path d="M24 32C24 27.6 27.6 24 32 24H36" stroke="#22d3ee" strokeWidth="2.5" strokeLinecap="round" />
        <path d="M40 32C40 36.4 36.4 40 32 40H28" stroke="#3b82f6" strokeWidth="2.5" strokeLinecap="round" />
        <circle cx="28" cy="32" r="3" fill="#22d3ee" />
        <circle cx="36" cy="32" r="3" fill="#3b82f6" />
      </svg>
      {!compact && (
        <span className="leading-tight">
          <span className="block text-base font-semibold tracking-wide">LinkShield</span>
          <span className="block text-[11px] text-slate-400">Check Before You Click.</span>
        </span>
      )}
    </Link>
  );
}
