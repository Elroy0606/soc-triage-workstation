import { motion } from "framer-motion";
import { useRef } from "react";

/** Accessible tablist with a shared-element pill that glides between modes. */
export default function ModeNav({ modes, active, onChange }) {
  const refs = useRef([]);

  const onKeyDown = (e, i) => {
    const dir = e.key === "ArrowRight" ? 1 : e.key === "ArrowLeft" ? -1 : 0;
    if (!dir) return;
    e.preventDefault();
    const next = (i + dir + modes.length) % modes.length;
    onChange(modes[next].id);
    refs.current[next]?.focus();
  };

  return (
    <nav aria-label="Workstation modes" className="glass mx-auto flex w-full max-w-2xl p-1.5">
      <div role="tablist" className="flex w-full gap-1">
        {modes.map((m, i) => {
          const selected = m.id === active;
          const Icon = m.icon;
          return (
            <button
              key={m.id}
              ref={(el) => (refs.current[i] = el)}
              role="tab"
              id={`tab-${m.id}`}
              aria-selected={selected}
              aria-controls={`panel-${m.id}`}
              tabIndex={selected ? 0 : -1}
              onClick={() => onChange(m.id)}
              onKeyDown={(e) => onKeyDown(e, i)}
              className={`relative flex flex-1 items-center justify-center gap-2 rounded-xl px-3 py-2.5 text-sm font-medium transition-colors ${
                selected ? "text-white" : "text-slate-400 hover:text-slate-200"
              }`}
            >
              {selected && (
                <motion.span
                  layoutId="mode-pill"
                  className="absolute inset-0 rounded-xl border border-net/30 bg-gradient-to-b from-net/20 to-net/[0.06] shadow-[0_0_24px_-6px_rgba(56,189,248,0.55)]"
                  transition={{ type: "spring", stiffness: 380, damping: 32 }}
                />
              )}
              <Icon className="relative h-4 w-4 shrink-0" aria-hidden="true" />
              <span className="relative hidden sm:inline">{m.label}</span>
              <span className="relative sm:hidden">{m.short}</span>
            </button>
          );
        })}
      </div>
    </nav>
  );
}
