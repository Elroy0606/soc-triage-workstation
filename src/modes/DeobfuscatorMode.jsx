import { AnimatePresence, motion } from "framer-motion";
import { ArrowDown, Binary, Braces, CheckCircle2, ExternalLink, Layers, ScanSearch, StepForward, Swords, Trash2, Wand2 } from "lucide-react";
import { useMemo, useState } from "react";
import Terminal, { useScanPulse } from "../components/Terminal.jsx";
import { Badge, CopyButton, EmptyState, Panel } from "../components/ui.jsx";
import { autoUnwrap, decodeLayer } from "../lib/decode.js";
import { attackUrl, scanMitre, segmentText } from "../lib/mitre.js";
import { PAYLOADS } from "../lib/samples.js";

function Highlighted({ text, hits, active }) {
  const segments = useMemo(() => segmentText(text, hits), [text, hits]);
  return segments.map((s, i) => {
    if (!s.ids.length) return <span key={i}>{s.text}</span>;
    const dim = active && !s.ids.includes(active);
    const high = s.severity === "high";
    return (
      <mark key={i} title={s.ids.join(", ")}
        className={`rounded px-0.5 transition ${dim ? "bg-transparent text-inherit" : high
          ? "bg-risk/20 text-risk shadow-[0_0_10px_-2px_rgba(251,113,133,0.6)]"
          : "bg-warn/15 text-warn"}`}>
        {s.text}
      </mark>
    );
  });
}

function StageCard({ stage, isLast, active, index }) {
  const hits = useMemo(() => scanMitre(stage.text), [stage.text]);
  const clean = isLast && stage.layer > 0;
  return (
    <motion.li
      initial={{ opacity: 0, y: 14 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0 }}
      transition={{ delay: index * 0.12, duration: 0.4, ease: [0.22, 1, 0.36, 1] }}
    >
      {index > 0 && (
        <div className="flex justify-center py-1.5" aria-hidden="true">
          <ArrowDown className="h-4 w-4 text-net/60" />
        </div>
      )}
      <div className={`rounded-xl border p-3.5 ${clean ? "border-safe/30 bg-safe/[0.04] shadow-[0_0_30px_-14px_rgba(52,211,153,0.6)]" : "border-white/[0.07] bg-white/[0.025]"}`}>
        <div className="mb-2 flex flex-wrap items-center gap-2">
          <span className="flex h-6 w-6 items-center justify-center rounded-md border border-white/10 bg-white/[0.04] font-mono text-[11px] text-slate-300">
            {stage.layer}
          </span>
          <Badge tone={stage.layer === 0 ? "muted" : clean ? "safe" : "net"}>{stage.method}</Badge>
          <span className="text-[11px] text-slate-500">{stage.detail}</span>
          {clean && <Badge tone="safe"><CheckCircle2 className="h-3 w-3" /> Clean output</Badge>}
          <CopyButton text={stage.text} label={`Copy layer ${stage.layer}`} className="ml-auto" />
        </div>
        <pre className={`mono max-h-56 overflow-auto whitespace-pre-wrap break-all text-[12px] ${clean ? "text-safe/90" : "text-slate-300"}`}>
          <Highlighted text={stage.text} hits={hits} active={active} />
        </pre>
      </div>
    </motion.li>
  );
}

export default function DeobfuscatorMode() {
  const [text, setText] = useState("");
  const [stages, setStages] = useState([]);
  const [active, setActive] = useState(null);
  const [runId, setRunId] = useState(0);
  const scanning = useScanPulse(runId ? `${runId}` : "", 900);

  const run = (value = text) => {
    if (!value.trim()) return;
    setStages(autoUnwrap(value));
    setActive(null);
    setRunId((n) => n + 1);
  };

  const step = () => {
    if (!text.trim()) return;
    const base = stages.length && stages[0].text === text ? stages : [{ layer: 0, method: "Input", detail: `${text.length} chars`, text }];
    const next = decodeLayer(base[base.length - 1].text);
    setStages(next ? [...base, { layer: base.length, ...next }] : base);
    setRunId((n) => n + 1);
  };

  const onChange = (v) => {
    setText(v);
    setStages([]);
    setActive(null);
  };

  // Techniques found in any stage, merged by ID.
  const techniques = useMemo(() => {
    const map = new Map();
    for (const s of stages)
      for (const h of scanMitre(s.text)) {
        const cur = map.get(h.id);
        const keywords = new Set([...(cur?.keywords ?? []), ...h.matches.map((m) => m.text)]);
        map.set(h.id, { ...h, keywords: [...keywords] });
      }
    return [...map.values()].sort((a, b) => (a.severity === b.severity ? a.id.localeCompare(b.id) : a.severity === "high" ? -1 : 1));
  }, [stages]);
  const activeTech = techniques.find((t) => t.id === active);
  const layers = Math.max(stages.length - 1, 0);
  const stuck = stages.length === 1;

  return (
    <div className="grid gap-5 lg:grid-cols-[minmax(0,5fr)_minmax(0,7fr)]">
      <div className="space-y-5">
        <Terminal
          label="Obfuscated payload"
          value={text}
          onChange={onChange}
          scanning={scanning}
          minRows={10}
          placeholder={"Paste Base64, hex, URL-encoded or char-code payloads.\nNested layers and embedded blobs (e.g. powershell -enc …) are unwrapped."}
          footer="Decoding happens locally. Nothing is executed."
          presets={[
            ...PAYLOADS.map((p) => ({ label: p.label, hint: p.hint, icon: Braces, onClick: () => { setText(p.value); run(p.value); } })),
            { label: "Clear", icon: Trash2, onClick: () => onChange("") },
          ]}
        />
        <div className="flex flex-wrap gap-2">
          <motion.button whileTap={{ scale: 0.97 }} type="button" onClick={() => run()} disabled={!text.trim()}
            className="btn btn-primary flex-1 justify-center !py-2.5 !text-sm shadow-[0_0_30px_-10px_rgba(56,189,248,0.7)]">
            <Wand2 className="h-4 w-4" /> Magic Auto-Unwrap
          </motion.button>
          <button type="button" onClick={step} disabled={!text.trim()} className="btn !py-2.5" title="Decode one more layer">
            <StepForward className="h-4 w-4" /> Step
          </button>
        </div>

        <Panel title="MITRE ATT&CK heuristics" icon={Swords} delay={0.1}>
          {techniques.length ? (
            <>
              <div className="flex flex-wrap gap-2">
                {techniques.map((t, i) => {
                  const on = active === t.id;
                  const high = t.severity === "high";
                  return (
                    <motion.button key={t.id} type="button" aria-pressed={on}
                      initial={{ opacity: 0, scale: 0.9 }} animate={{ opacity: 1, scale: 1 }} transition={{ delay: 0.05 * i }}
                      whileHover={{ y: -2 }}
                      onClick={() => setActive(on ? null : t.id)}
                      className={`rounded-lg border px-2.5 py-1.5 text-left text-xs transition ${
                        high ? "border-risk/30 bg-risk/10 text-risk" : "border-warn/30 bg-warn/10 text-warn"
                      } ${on ? "ring-2 ring-offset-2 ring-offset-obsidian " + (high ? "ring-risk/60" : "ring-warn/60") : ""} ${active && !on ? "opacity-50" : ""}`}>
                      <span className="font-mono font-semibold">{t.id}</span> <span className="opacity-90">{t.name}</span>
                    </motion.button>
                  );
                })}
              </div>
              <AnimatePresence mode="wait">
                {activeTech ? (
                  <motion.div key={activeTech.id} initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }}
                    className="mt-4 rounded-xl border border-white/[0.07] bg-white/[0.025] p-3 text-xs">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="font-mono font-semibold text-white">{activeTech.id}</span>
                      <span className="text-slate-300">{activeTech.name}</span>
                      <Badge tone="net">{activeTech.tactic}</Badge>
                    </div>
                    <p className="mt-2 text-slate-400">
                      Matched: {activeTech.keywords.map((k) => <code key={k} className="mr-1.5 rounded bg-white/[0.06] px-1 font-mono text-slate-200">{k}</code>)}
                    </p>
                    <a href={attackUrl(activeTech.id)} target="_blank" rel="noopener noreferrer"
                      className="mt-2 inline-flex items-center gap-1 text-net/80 hover:text-net hover:underline">
                      View on attack.mitre.org <ExternalLink className="h-3 w-3" />
                    </a>
                  </motion.div>
                ) : (
                  <p key="hint" className="mt-3 text-[11px] text-slate-500">Select a technique to focus its highlighted keywords. Keyword heuristics only: confirm in context before reporting.</p>
                )}
              </AnimatePresence>
            </>
          ) : (
            <p className="text-xs text-slate-500">{stages.length ? "No known technique patterns found in any layer." : "Techniques appear here after decoding."}</p>
          )}
        </Panel>
      </div>

      <Panel title="Transformation pipeline" icon={Layers} delay={0.05}
        actions={stages.length > 0 && (
          <Badge tone={stuck ? "muted" : "safe"}>{stuck ? "No encoding detected" : `${layers} layer${layers > 1 ? "s" : ""} unwrapped`}</Badge>
        )}>
        {stages.length ? (
          <ol key={runId}>
            <AnimatePresence>
              {stages.map((s, i) => (
                <StageCard key={`${runId}-${i}`} stage={s} index={i} isLast={i === stages.length - 1} active={active} />
              ))}
            </AnimatePresence>
          </ol>
        ) : (
          <EmptyState icon={Binary} title="No payload decoded yet">
            Load a preset or paste a payload, then press <b className="text-net">Magic Auto-Unwrap</b> to peel every layer, or <b>Step</b> to go one layer at a time.
          </EmptyState>
        )}
        {stages.length > 0 && (
          <p className="mt-4 flex items-center gap-1.5 text-[11px] text-slate-500">
            <ScanSearch className="h-3.5 w-3.5" /> Supported: Base64 (UTF-8 / UTF-16LE), hex (plain, \x, 0x), percent-encoding, char codes, and blobs embedded in text.
          </p>
        )}
      </Panel>
    </div>
  );
}
