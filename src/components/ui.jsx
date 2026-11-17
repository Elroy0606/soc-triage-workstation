// Small shared UI primitives: tone badges, copy button, rolling numbers, panels.
import { animate, motion, useReducedMotion } from "framer-motion";
import { Check, Copy } from "lucide-react";
import { useEffect, useRef, useState } from "react";

export const TONES = {
  net: "text-net border-net/30 bg-net/10",
  safe: "text-safe border-safe/30 bg-safe/10",
  warn: "text-warn border-warn/30 bg-warn/10",
  risk: "text-risk border-risk/30 bg-risk/10",
  muted: "text-slate-400 border-white/10 bg-white/5",
};

export function Badge({ tone = "muted", children, className = "", title }) {
  return (
    <span
      title={title}
      className={`inline-flex items-center gap-1 whitespace-nowrap rounded-md border px-1.5 py-0.5 text-[10.5px] font-semibold uppercase tracking-wide ${TONES[tone]} ${className}`}
    >
      {children}
    </span>
  );
}

export async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    const ta = document.createElement("textarea");
    ta.value = text;
    ta.style.position = "fixed";
    ta.style.opacity = "0";
    document.body.append(ta);
    ta.select();
    const ok = document.execCommand("copy");
    ta.remove();
    return ok;
  }
}

export function CopyButton({ text, label = "Copy", className = "", showLabel = false }) {
  const [done, setDone] = useState(false);
  const timer = useRef();
  useEffect(() => () => clearTimeout(timer.current), []);
  const onClick = async () => {
    if (await copyText(text)) {
      setDone(true);
      clearTimeout(timer.current);
      timer.current = setTimeout(() => setDone(false), 1400);
    }
  };
  return (
    <button
      type="button"
      onClick={onClick}
      aria-label={done ? "Copied" : label}
      title={done ? "Copied" : label}
      className={`btn ${done ? "border-safe/40 text-safe" : ""} ${showLabel ? "" : "!px-2"} ${className}`}
    >
      {done ? <Check className="h-3.5 w-3.5" /> : <Copy className="h-3.5 w-3.5" />}
      {showLabel && <span>{done ? "Copied" : label}</span>}
      <span className="sr-only" aria-live="polite">{done ? "Copied to clipboard" : ""}</span>
    </button>
  );
}

/** Number that rolls smoothly to its new value. */
export function AnimatedNumber({ value, className = "" }) {
  const ref = useRef(null);
  const prev = useRef(0);
  const reduce = useReducedMotion();
  useEffect(() => {
    const node = ref.current;
    if (!node) return;
    if (reduce) {
      node.textContent = String(value);
      prev.current = value;
      return;
    }
    const controls = animate(prev.current, value, {
      duration: 0.7,
      ease: [0.22, 1, 0.36, 1],
      onUpdate: (v) => (node.textContent = String(Math.round(v))),
    });
    prev.current = value;
    return () => controls.stop();
  }, [value, reduce]);
  return <span ref={ref} className={`tabular-nums ${className}`}>{value}</span>;
}

export function Panel({ title, icon: Icon, actions, children, className = "", delay = 0 }) {
  return (
    <motion.section
      initial={{ opacity: 0, y: 14 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.45, delay, ease: [0.22, 1, 0.36, 1] }}
      className={`glass p-4 sm:p-5 ${className}`}
    >
      {(title || actions) && (
        <div className="mb-4 flex flex-wrap items-center justify-between gap-2">
          {title && (
            <h2 className="panel-title">
              {Icon && <Icon className="h-3.5 w-3.5 text-net" aria-hidden="true" />}
              {title}
            </h2>
          )}
          {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
        </div>
      )}
      {children}
    </motion.section>
  );
}

export function StatTile({ label, value, tone = "net", icon: Icon }) {
  const color = { net: "text-net", safe: "text-safe", warn: "text-warn", risk: "text-risk" }[tone];
  return (
    <div className="rounded-xl border border-white/[0.06] bg-white/[0.02] p-3">
      <div className="flex items-center gap-1.5 text-[11px] uppercase tracking-wider text-slate-400">
        {Icon && <Icon className={`h-3.5 w-3.5 ${color}`} aria-hidden="true" />}
        {label}
      </div>
      <AnimatedNumber value={value} className={`mt-1 block text-2xl font-semibold ${color}`} />
    </div>
  );
}

export function EmptyState({ icon: Icon, title, children }) {
  return (
    <div className="flex flex-col items-center justify-center gap-2 rounded-xl border border-dashed border-white/10 px-6 py-12 text-center">
      {Icon && <Icon className="h-8 w-8 text-slate-600" aria-hidden="true" />}
      <p className="text-sm font-medium text-slate-300">{title}</p>
      {children && <p className="max-w-sm text-xs text-slate-500">{children}</p>}
    </div>
  );
}
