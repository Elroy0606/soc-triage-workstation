import { AnimatePresence, motion } from "framer-motion";
import {
  Activity, AtSign, Crosshair, ExternalLink, FileText, Fingerprint, Globe, Link2, Mail, Network,
  Radar, ServerCog, ShieldAlert, ShieldCheck, Trash2, Download,
} from "lucide-react";
import { useCallback, useDeferredValue, useMemo, useState } from "react";
import Modal from "../components/Modal.jsx";
import TelemetryRing from "../components/TelemetryRing.jsx";
import Terminal, { useScanPulse } from "../components/Terminal.jsx";
import { Badge, CopyButton, EmptyState, Panel, StatTile } from "../components/ui.jsx";
import { extractIocs, isHash, pivots, TYPE_META } from "../lib/ioc.js";
import { buildEscalation } from "../lib/report.js";
import { C2_BEACON_LOG, PHISHING_INCIDENT } from "../lib/samples.js";

const TYPE_ICON = { ipv4: Network, domain: Globe, url: Link2, email: AtSign, md5: Fingerprint, sha1: Fingerprint, sha256: Fingerprint };
const FILTERS = [
  { id: "all", label: "All" },
  { id: "ipv4", label: "IPs" },
  { id: "domain", label: "Domains" },
  { id: "url", label: "URLs" },
  { id: "email", label: "Emails" },
  { id: "hash", label: "Hashes" },
];
const matchesFilter = (ioc, f) => f === "all" || (f === "hash" ? isHash(ioc.type) : ioc.type === f);

function valueColor(ioc, defanged) {
  if (isHash(ioc.type)) return "text-risk";
  if (ioc.type === "ipv4") return ioc.scope === "private" ? "text-safe" : ioc.scope === "external" ? "text-net" : "text-slate-300";
  return defanged ? "text-warn" : "text-slate-100";
}

function IocCard({ ioc, defanged }) {
  const Icon = TYPE_ICON[ioc.type];
  const shown = defanged ? ioc.defanged : ioc.value;
  return (
    <motion.li
      layout
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, scale: 0.97 }}
      whileHover={{ y: -2 }}
      transition={{ duration: 0.3, ease: [0.22, 1, 0.36, 1] }}
      className="group rounded-xl border border-white/[0.07] bg-white/[0.025] p-3.5 transition-colors hover:border-white/[0.14] hover:bg-white/[0.045] hover:shadow-[0_12px_30px_-16px_rgba(56,189,248,0.35)]"
    >
      <div className="flex items-start gap-3">
        <div className="mt-0.5 rounded-lg border border-white/[0.06] bg-white/[0.03] p-1.5">
          <Icon className="h-4 w-4 text-slate-400" aria-hidden="true" />
        </div>
        <div className="min-w-0 flex-1">
          <div className="mb-1.5 flex flex-wrap items-center gap-1.5">
            <Badge tone={isHash(ioc.type) ? "risk" : "muted"}>{TYPE_META[ioc.type].label}</Badge>
            {ioc.type === "ipv4" && (
              <Badge tone={ioc.scope === "private" ? "safe" : ioc.scope === "external" ? "net" : "muted"}>{ioc.label}</Badge>
            )}
            {defanged && !isHash(ioc.type) && <Badge tone="warn">Defanged</Badge>}
            {ioc.type === "domain" && (
              <span className="font-mono text-[10.5px] text-slate-500" title="Shannon entropy of the most random label">
                H={ioc.entropy.toFixed(2)}
              </span>
            )}
            {ioc.flag && (
              <Badge tone={ioc.flag.level === "high" ? "risk" : "warn"} title="Entropy above 3.8 bits/char. Heuristic only: verify before acting.">
                {ioc.flag.label}
              </Badge>
            )}
          </div>
          <p className={`mono break-all ${valueColor(ioc, defanged)}`}>{shown}</p>
          <div className="mt-2 flex flex-wrap gap-x-3 gap-y-1">
            {pivots(ioc.type, ioc.value).map(([name, href]) => (
              <a key={name} href={href} target="_blank" rel="noopener noreferrer"
                className="inline-flex items-center gap-1 text-[11.5px] text-net/80 transition hover:text-net hover:underline">
                {name}
                <ExternalLink className="h-3 w-3" aria-hidden="true" />
                <span className="sr-only">(opens in new tab, sends this indicator to {name})</span>
              </a>
            ))}
          </div>
        </div>
        <CopyButton text={shown} label={`Copy ${TYPE_META[ioc.type].label}`} />
      </div>
    </motion.li>
  );
}

function EscalationModal({ open, onClose, iocs }) {
  const [format, setFormat] = useState("markdown");
  const [title, setTitle] = useState("");
  const [notes, setNotes] = useState("");
  const report = useMemo(() => buildEscalation(iocs, { title, analystNotes: notes }), [iocs, title, notes]);
  const body = format === "markdown" ? report.markdown : report.json;
  const tone = { High: "risk", Medium: "warn", Low: "safe" }[report.priority.level];

  const download = () => {
    const blob = new Blob([body], { type: format === "markdown" ? "text/markdown" : "application/json" });
    const a = Object.assign(document.createElement("a"), {
      href: URL.createObjectURL(blob),
      download: `escalation-${new Date().toISOString().slice(0, 16).replace(/[:T]/g, "-")}.${format === "markdown" ? "md" : "json"}`,
    });
    a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 500);
  };

  return (
    <Modal open={open} onClose={onClose} title="Tier 2 Escalation Note" icon={FileText} wide>
      <div className="grid gap-4 md:grid-cols-[minmax(0,1fr)_minmax(0,1.6fr)]">
        <div className="space-y-3">
          <label className="block text-xs text-slate-400">
            Incident title
            <input value={title} onChange={(e) => setTitle(e.target.value)} placeholder="Suspicious activity: Tier 1 triage"
              className="mono mt-1 w-full rounded-lg border border-white/10 bg-white/[0.03] px-3 py-2 text-slate-200 placeholder:text-slate-600 focus:border-net/50 focus:outline-none" />
          </label>
          <label className="block text-xs text-slate-400">
            Analyst notes
            <textarea value={notes} onChange={(e) => setNotes(e.target.value)} rows={6}
              placeholder="What happened, what you checked, what the user reported…"
              className="mono mt-1 w-full resize-y rounded-lg border border-white/10 bg-white/[0.03] px-3 py-2 text-slate-200 placeholder:text-slate-600 focus:border-net/50 focus:outline-none" />
          </label>
          <div className="rounded-xl border border-white/[0.06] bg-white/[0.02] p-3 text-xs">
            <div className="mb-1.5 flex items-center gap-2 text-slate-400">
              Suggested priority <Badge tone={tone}>{report.priority.level}</Badge>
            </div>
            <ul className="list-inside list-disc space-y-0.5 text-slate-400">
              {report.priority.reasons.map((r) => <li key={r}>{r}</li>)}
            </ul>
            <p className="mt-2 text-[11px] text-slate-500">A heuristic suggestion. Adjust based on your own judgement and runbook.</p>
          </div>
        </div>

        <div className="min-w-0">
          <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
            <div role="tablist" aria-label="Output format" className="flex rounded-lg border border-white/10 bg-white/[0.03] p-0.5">
              {["markdown", "json"].map((f) => (
                <button key={f} role="tab" aria-selected={format === f} onClick={() => setFormat(f)}
                  className={`relative rounded-md px-3 py-1 text-xs font-medium ${format === f ? "text-white" : "text-slate-400"}`}>
                  {format === f && <motion.span layoutId="fmt-pill" className="absolute inset-0 rounded-md bg-net/20" />}
                  <span className="relative">{f === "markdown" ? "Markdown" : "JSON"}</span>
                </button>
              ))}
            </div>
            <div className="flex gap-2">
              <button className="btn" onClick={download}><Download className="h-3.5 w-3.5" />Download</button>
              <CopyButton text={body} label="Copy note" showLabel className="btn-primary" />
            </div>
          </div>
          <pre className="mono max-h-[55vh] overflow-auto whitespace-pre-wrap break-words rounded-xl border border-white/[0.06] bg-black/30 p-4 text-[12px] text-slate-300">
            {body}
          </pre>
        </div>
      </div>
    </Modal>
  );
}

export default function IocMode() {
  const [text, setText] = useState("");
  const [defanged, setDefanged] = useState(true);
  const [filter, setFilter] = useState("all");
  const [noteOpen, setNoteOpen] = useState(false);
  const deferred = useDeferredValue(text);
  const scanning = useScanPulse(text);
  const iocs = useMemo(() => extractIocs(deferred), [deferred]);
  const visible = iocs.filter((i) => matchesFilter(i, filter));
  const closeNote = useCallback(() => setNoteOpen(false), []);

  const count = (pred) => iocs.filter(pred).length;
  const segments = [
    { key: "ipv4", label: "IPv4", color: TYPE_META.ipv4.color, value: count((i) => i.type === "ipv4") },
    { key: "domain", label: "Domains", color: TYPE_META.domain.color, value: count((i) => i.type === "domain") },
    { key: "url", label: "URLs", color: TYPE_META.url.color, value: count((i) => i.type === "url") },
    { key: "email", label: "Emails", color: TYPE_META.email.color, value: count((i) => i.type === "email") },
    { key: "hash", label: "Hashes", color: TYPE_META.sha256.color, value: count((i) => isHash(i.type)) },
  ];

  return (
    <div className="grid gap-5 lg:grid-cols-[minmax(0,5fr)_minmax(0,7fr)]">
      <div className="space-y-5">
        <Terminal
          label="Input terminal"
          value={text}
          onChange={setText}
          scanning={scanning}
          placeholder={"Paste alerts, logs, emails or threat reports.\nDefanged input like hxxps://evil[.]com or 10[.]0[.]0[.]1 is understood."}
          footer="Runs locally. Nothing leaves your browser."
          presets={[
            { label: "Load Phishing Incident", icon: Mail, onClick: () => setText(PHISHING_INCIDENT) },
            { label: "Load C2 Beacon Log", icon: Radar, onClick: () => setText(C2_BEACON_LOG) },
            { label: "Clear", icon: Trash2, onClick: () => setText("") },
          ]}
        />
        <Panel title="Telemetry" icon={Activity} delay={0.1}>
          <TelemetryRing segments={segments} />
          <div className="mt-5 grid grid-cols-2 gap-2.5">
            <StatTile label="External IPs" icon={Crosshair} tone="net" value={count((i) => i.scope === "external")} />
            <StatTile label="Internal IPs" icon={ShieldCheck} tone="safe" value={count((i) => i.scope === "private")} />
            <StatTile label="Possible DGA" icon={ServerCog} tone="warn" value={count((i) => i.flag)} />
            <StatTile label="File hashes" icon={Fingerprint} tone="risk" value={count((i) => isHash(i.type))} />
          </div>
        </Panel>
      </div>

      <Panel
        title="Enrichment matrix"
        icon={ShieldAlert}
        delay={0.05}
        actions={
          <>
            <button type="button" role="switch" aria-checked={defanged} onClick={() => setDefanged((d) => !d)}
              className="btn" title="Toggle raw / defanged view">
              <span className={`relative h-4 w-7 rounded-full transition ${defanged ? "bg-warn/40" : "bg-white/10"}`}>
                <motion.span layout className={`absolute top-0.5 h-3 w-3 rounded-full ${defanged ? "right-0.5 bg-warn" : "left-0.5 bg-slate-400"}`} />
              </span>
              {defanged ? "Defanged" : "Raw (live)"}
            </button>
            <CopyButton text={visible.map((i) => (defanged ? i.defanged : i.value)).join("\n")} label="Copy all" showLabel />
            <button type="button" className="btn btn-primary" disabled={!iocs.length} onClick={() => setNoteOpen(true)}>
              <FileText className="h-3.5 w-3.5" /> Generate Tier 2 Escalation Note
            </button>
          </>
        }
      >
        <div className="mb-4 flex flex-wrap gap-1.5" role="group" aria-label="Filter by type">
          {FILTERS.map((f) => {
            const n = f.id === "all" ? iocs.length : count((i) => matchesFilter(i, f.id));
            return (
              <button key={f.id} type="button" aria-pressed={filter === f.id} onClick={() => setFilter(f.id)}
                className={`rounded-full border px-3 py-1 text-xs transition ${
                  filter === f.id ? "border-net/40 bg-net/15 text-net" : "border-white/10 text-slate-400 hover:text-slate-200"
                }`}>
                {f.label} <span className="ml-0.5 tabular-nums opacity-70">{n}</span>
              </button>
            );
          })}
        </div>

        {!defanged && iocs.length > 0 && (
          <p className="mb-3 rounded-lg border border-risk/25 bg-risk/[0.07] px-3 py-2 text-xs text-risk">
            Raw view: indicators are live. Don't paste them into chat or tickets un-defanged.
          </p>
        )}

        {visible.length ? (
          <ul className="grid gap-2.5 xl:grid-cols-2">
            <AnimatePresence initial={false} mode="popLayout">
              {visible.map((ioc) => <IocCard key={ioc.id} ioc={ioc} defanged={defanged} />)}
            </AnimatePresence>
          </ul>
        ) : (
          <EmptyState icon={Radar} title={iocs.length ? "No indicators of this type" : "Awaiting telemetry"}>
            Paste text into the terminal or load a preset. IPs, domains, URLs, emails and MD5/SHA-1/SHA-256 hashes are extracted, deduplicated and defanged automatically.
          </EmptyState>
        )}
      </Panel>

      <EscalationModal open={noteOpen} onClose={closeNote} iocs={iocs} />
    </div>
  );
}
