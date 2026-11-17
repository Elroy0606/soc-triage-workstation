import { AnimatePresence, motion } from "framer-motion";
import { X } from "lucide-react";
import { useEffect, useId, useRef } from "react";

/** Accessible dialog: Esc closes, focus is trapped inside and restored on close. */
export default function Modal({ open, onClose, title, icon: Icon, children, wide = false }) {
  const titleId = useId();
  const box = useRef(null);
  const restore = useRef(null);

  useEffect(() => {
    if (!open) return;
    restore.current = document.activeElement;
    const t = setTimeout(() => box.current?.querySelector("input, textarea, button")?.focus(), 50);
    const onKey = (e) => {
      if (e.key === "Escape") onClose();
      if (e.key !== "Tab" || !box.current) return;
      const f = [...box.current.querySelectorAll("button, a[href], input, textarea, select, [tabindex]:not([tabindex='-1'])")];
      if (!f.length) return;
      const [first, last] = [f[0], f[f.length - 1]];
      if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
      else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
    };
    document.addEventListener("keydown", onKey);
    document.body.style.overflow = "hidden";
    return () => {
      clearTimeout(t);
      document.removeEventListener("keydown", onKey);
      document.body.style.overflow = "";
      restore.current?.focus?.();
    };
  }, [open, onClose]);

  return (
    <AnimatePresence>
      {open && (
        <motion.div className="fixed inset-0 z-50 flex items-end justify-center p-3 sm:items-center sm:p-6"
          initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}>
          <div className="absolute inset-0 bg-obsidian/70 backdrop-blur-sm" onClick={onClose} aria-hidden="true" />
          <motion.div
            ref={box}
            role="dialog"
            aria-modal="true"
            aria-labelledby={titleId}
            className={`glass relative flex max-h-[90vh] w-full flex-col !bg-[#0b1220]/90 ${wide ? "max-w-4xl" : "max-w-xl"}`}
            initial={{ opacity: 0, y: 24, scale: 0.98 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: 16, scale: 0.98 }}
            transition={{ type: "spring", stiffness: 320, damping: 30 }}
          >
            <div className="flex items-center justify-between gap-3 border-b border-white/[0.06] px-5 py-4">
              <h2 id={titleId} className="flex items-center gap-2 text-sm font-semibold text-white">
                {Icon && <Icon className="h-4 w-4 text-net" aria-hidden="true" />}
                {title}
              </h2>
              <button type="button" onClick={onClose} className="btn !px-2" aria-label="Close dialog">
                <X className="h-4 w-4" />
              </button>
            </div>
            <div className="overflow-y-auto p-5">{children}</div>
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  );
}
