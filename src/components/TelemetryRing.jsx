import { motion } from "framer-motion";
import { AnimatedNumber } from "./ui.jsx";

const R = 52;
const C = 2 * Math.PI * R;
const GAP = 3; // px gap between segments

/** Donut showing the share of each IOC type, with an animated legend. */
export default function TelemetryRing({ segments }) {
  const total = segments.reduce((s, x) => s + x.value, 0);
  let offset = 0;
  const arcs = segments.map((s) => {
    const len = total ? (s.value / total) * C : 0;
    const arc = { ...s, len: Math.max(len - (len > GAP ? GAP : 0), 0), offset };
    offset += len;
    return arc;
  });

  return (
    <div className="flex flex-col items-center gap-5 sm:flex-row">
      <div className="relative h-36 w-36 shrink-0">
        <svg viewBox="0 0 140 140" className="h-full w-full -rotate-90" role="img"
          aria-label={total ? segments.filter((s) => s.value).map((s) => `${s.label}: ${s.value}`).join(", ") : "No indicators"}>
          <circle cx="70" cy="70" r={R} fill="none" stroke="rgba(255,255,255,0.06)" strokeWidth="10" />
          {arcs.map((a) => (
            <motion.circle
              key={a.key}
              cx="70" cy="70" r={R} fill="none" stroke={a.color} strokeWidth="10" strokeLinecap="round"
              style={{ filter: `drop-shadow(0 0 6px ${a.color}66)` }}
              initial={false}
              animate={{ strokeDasharray: `${a.len} ${C - a.len}`, strokeDashoffset: -a.offset, opacity: a.value ? 1 : 0 }}
              transition={{ duration: 0.8, ease: [0.22, 1, 0.36, 1] }}
            />
          ))}
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <AnimatedNumber value={total} className="text-3xl font-semibold text-white" />
          <span className="text-[10px] uppercase tracking-[0.2em] text-slate-500">IOCs</span>
        </div>
      </div>

      <ul className="grid w-full grid-cols-1 gap-2">
        {segments.map((s) => {
          const pct = total ? Math.round((s.value / total) * 100) : 0;
          return (
            <li key={s.key} className="text-xs">
              <div className="mb-1 flex items-center justify-between">
                <span className="flex items-center gap-2 text-slate-300">
                  <span className="h-2 w-2 rounded-full" style={{ background: s.color, boxShadow: `0 0 8px ${s.color}` }} />
                  {s.label}
                </span>
                <span className="tabular-nums text-slate-400">
                  <AnimatedNumber value={s.value} /> · {pct}%
                </span>
              </div>
              <div className="h-1 overflow-hidden rounded-full bg-white/[0.05]">
                <motion.div className="h-full rounded-full" style={{ background: s.color }}
                  initial={false} animate={{ width: `${pct}%` }} transition={{ duration: 0.8, ease: [0.22, 1, 0.36, 1] }} />
              </div>
            </li>
          );
        })}
      </ul>
    </div>
  );
}
