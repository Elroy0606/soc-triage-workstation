import { AnimatePresence, MotionConfig, motion } from "framer-motion";
import { Binary, Lock, Mail, Radar, ShieldHalf } from "lucide-react";
import { useEffect, useState } from "react";
import Background from "./components/Background.jsx";
import ModeNav from "./components/ModeNav.jsx";
import DeobfuscatorMode from "./modes/DeobfuscatorMode.jsx";
import EmailMode from "./modes/EmailMode.jsx";
import IocMode from "./modes/IocMode.jsx";

const MODES = [
  { id: "ioc", label: "IOC Extractor", short: "IOCs", icon: Radar, component: IocMode },
  { id: "decode", label: "Deobfuscator", short: "Decode", icon: Binary, component: DeobfuscatorMode },
  { id: "email", label: "Email Headers", short: "Email", icon: Mail, component: EmailMode },
];

const fromHash = () => {
  const h = window.location.hash.slice(1);
  return MODES.some((m) => m.id === h) ? h : "ioc";
};

export default function App() {
  const [mode, setMode] = useState(fromHash);

  // Keep the mode in the URL hash so each mode can be deep-linked (e.g. /#email).
  useEffect(() => {
    const onHash = () => setMode(fromHash());
    window.addEventListener("hashchange", onHash);
    return () => window.removeEventListener("hashchange", onHash);
  }, []);
  const change = (id) => {
    setMode(id);
    history.replaceState(null, "", `#${id}`);
  };

  const Active = MODES.find((m) => m.id === mode).component;

  return (
    <MotionConfig reducedMotion="user">
      <Background />
      <a href="#workspace" className="sr-only focus:not-sr-only focus:fixed focus:left-4 focus:top-4 focus:z-50 focus:rounded-lg focus:bg-net focus:px-3 focus:py-2 focus:text-obsidian">
        Skip to workspace
      </a>
      <div className="mx-auto flex min-h-screen max-w-[1440px] flex-col px-4 pb-10 pt-6 sm:px-6 lg:px-8">
        <header className="mb-6 flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
          <div className="flex items-center gap-3">
            <div className="relative flex h-11 w-11 items-center justify-center rounded-xl border border-net/30 bg-net/10 shadow-[0_0_30px_-8px_rgba(56,189,248,0.7)]">
              <ShieldHalf className="h-5 w-5 text-net" aria-hidden="true" />
            </div>
            <div>
              <h1 className="text-lg font-semibold tracking-tight text-white sm:text-xl">Threat Triage Workstation</h1>
              <p className="text-xs text-slate-400">SOC Tier 1 · IOC enrichment · payload decoding · email forensics</p>
            </div>
          </div>
          <span className="inline-flex w-fit items-center gap-1.5 rounded-full border border-safe/25 bg-safe/[0.08] px-3 py-1 text-[11px] text-safe">
            <Lock className="h-3 w-3" aria-hidden="true" /> 100% client-side · no API keys · no uploads
          </span>
        </header>

        <ModeNav modes={MODES} active={mode} onChange={change} />

        <main id="workspace" className="mt-6 flex-1">
          <AnimatePresence mode="wait">
            <motion.div
              key={mode}
              role="tabpanel"
              id={`panel-${mode}`}
              aria-labelledby={`tab-${mode}`}
              initial={{ opacity: 0, y: 12, filter: "blur(4px)" }}
              animate={{ opacity: 1, y: 0, filter: "blur(0px)" }}
              exit={{ opacity: 0, y: -8, filter: "blur(4px)" }}
              transition={{ duration: 0.3, ease: [0.22, 1, 0.36, 1] }}
            >
              <Active />
            </motion.div>
          </AnimatePresence>
        </main>

        <footer className="mt-10 text-center text-[11px] text-slate-500">
          Built by Elroy Fernandes ·{" "}
          <a href="https://elcybersec.com" className="text-slate-400 hover:text-net">elcybersec.com</a> · Heuristics assist triage; always verify before escalating.
        </footer>
      </div>
    </MotionConfig>
  );
}
