import { AnimatePresence, motion } from "framer-motion";
import { Terminal as TerminalIcon } from "lucide-react";
import { useEffect, useId, useRef, useState } from "react";

/** True for ~1s after `value` changes; drives the scanning beam. */
export function useScanPulse(value, ms = 1000) {
  const [scanning, setScanning] = useState(false);
  const first = useRef(true);
  useEffect(() => {
    if (first.current) {
      first.current = false;
      return;
    }
    if (!value) return setScanning(false);
    setScanning(true);
    const t = setTimeout(() => setScanning(false), ms);
    return () => clearTimeout(t);
  }, [value, ms]);
  return scanning;
}

/** Monospace glass input with preset buttons and an animated scanning beam. */
export default function Terminal({ label, value, onChange, presets = [], placeholder, scanning, minRows = 14, footer }) {
  const id = useId();
  return (
    <div className="glass overflow-hidden">
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-white/[0.06] px-4 py-3">
        <label htmlFor={id} className="panel-title cursor-text">
          <TerminalIcon className="h-3.5 w-3.5 text-net" aria-hidden="true" />
          {label}
        </label>
        <div className="flex items-center gap-1.5" aria-hidden="true">
          <span className="h-2.5 w-2.5 rounded-full bg-risk/60" />
          <span className="h-2.5 w-2.5 rounded-full bg-warn/60" />
          <span className="h-2.5 w-2.5 rounded-full bg-safe/60" />
        </div>
      </div>

      {presets.length > 0 && (
        <div className="flex flex-wrap gap-2 border-b border-white/[0.06] px-4 py-3">
          {presets.map((p) => (
            <button key={p.label} type="button" onClick={p.onClick} title={p.hint} className={`btn ${p.primary ? "btn-primary" : ""}`}>
              {p.icon && <p.icon className="h-3.5 w-3.5" aria-hidden="true" />}
              {p.label}
            </button>
          ))}
        </div>
      )}

      <div className="relative">
        <textarea
          id={id}
          value={value}
          onChange={(e) => onChange(e.target.value)}
          placeholder={placeholder}
          spellCheck={false}
          autoComplete="off"
          rows={minRows}
          className="mono block w-full resize-y bg-transparent px-4 py-3 text-slate-200 placeholder:text-slate-600 focus:outline-none focus-visible:ring-0"
        />
        <AnimatePresence>
          {scanning && (
            <motion.div
              aria-hidden="true"
              className="pointer-events-none absolute inset-x-0 top-0 h-full overflow-hidden"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
            >
              <motion.div
                className="absolute inset-x-0 h-24 bg-gradient-to-b from-transparent via-net/[0.13] to-transparent"
                initial={{ top: "-20%" }}
                animate={{ top: "100%" }}
                transition={{ duration: 1, ease: "easeInOut" }}
              >
                <div className="absolute inset-x-0 top-1/2 h-px bg-net/70 shadow-[0_0_14px_2px_rgba(56,189,248,0.55)]" />
              </motion.div>
            </motion.div>
          )}
        </AnimatePresence>
      </div>

      <div className="flex items-center justify-between border-t border-white/[0.06] px-4 py-2 text-[11px] text-slate-500">
        <span aria-live="polite">{scanning ? <span className="text-net">Analyzing…</span> : footer}</span>
        <span className="tabular-nums">{value.length.toLocaleString()} chars</span>
      </div>
    </div>
  );
}
