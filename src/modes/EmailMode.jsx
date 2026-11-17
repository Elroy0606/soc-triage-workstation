import { motion } from "framer-motion";
import { AlertTriangle, CheckCircle2, Clock, GitCommitVertical, MailCheck, MailWarning, Route, ShieldCheck, Trash2, UserCheck } from "lucide-react";
import { useDeferredValue, useMemo, useState } from "react";
import Terminal, { useScanPulse } from "../components/Terminal.jsx";
import { Badge, EmptyState, Panel, TONES } from "../components/ui.jsx";
import { analyzeHeaders, authTone, formatDelay } from "../lib/headers.js";
import { classifyIPv4, defang } from "../lib/ioc.js";
import { LEGIT_EMAIL, SPOOFED_EMAIL } from "../lib/samples.js";

const GLOW = {
  safe: "shadow-[0_0_40px_-12px_rgba(52,211,153,0.55)] border-safe/30",
  warn: "shadow-[0_0_40px_-12px_rgba(251,191,36,0.5)] border-warn/30",
  risk: "shadow-[0_0_40px_-12px_rgba(251,113,133,0.6)] border-risk/30",
};
const TEXT = { safe: "text-safe", warn: "text-warn", risk: "text-risk" };

function AuthCard({ name, result, index }) {
  const tone = authTone(result.status);
  return (
    <motion.div
      initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.08 * index }}
      whileHover={{ y: -2 }}
      className={`rounded-xl border bg-white/[0.025] p-4 ${GLOW[tone]}`}
    >
      <div className="flex items-center justify-between">
        <span className="text-xs font-semibold tracking-[0.14em] text-slate-400">{name}</span>
        <motion.span
          className={`h-2 w-2 rounded-full ${tone === "safe" ? "bg-safe" : tone === "warn" ? "bg-warn" : "bg-risk"}`}
          animate={{ opacity: [1, 0.35, 1] }} transition={{ duration: 2.4, repeat: Infinity }}
          aria-hidden="true"
        />
      </div>
      <p className={`mt-2 font-mono text-2xl font-semibold uppercase ${TEXT[tone]}`}>{result.status}</p>
      <p className="mt-1 line-clamp-3 break-words text-[11px] text-slate-500" title={result.detail}>{result.detail}</p>
    </motion.div>
  );
}

function AddressRow({ label, addr, highlight }) {
  return (
    <div className="grid grid-cols-[6.5rem_minmax(0,1fr)] items-baseline gap-2 py-1.5 text-xs">
      <span className="text-slate-500">{label}</span>
      {addr ? (
        <span className="min-w-0 break-all">
          {addr.display && <span className="text-slate-400">"{addr.display}" </span>}
          <span className={`font-mono ${highlight ? "text-warn" : "text-slate-200"}`}>{defang("email", addr.address)}</span>
        </span>
      ) : (
        <span className="text-slate-600">Not present</span>
      )}
    </div>
  );
}

function ipTone(ip) {
  if (!ip || !/^\d+\.\d+\.\d+\.\d+$/.test(ip)) return "net";
  const s = classifyIPv4(ip).scope;
  return s === "private" ? "safe" : s === "external" ? "net" : "muted";
}

function Timeline({ hops }) {
  if (!hops.length) return <p className="text-xs text-slate-500">No Received headers found.</p>;
  return (
    <ol className="relative ml-2">
      <motion.span
        aria-hidden="true"
        className="absolute left-[7px] top-2 w-px origin-top bg-gradient-to-b from-net/70 via-net/30 to-safe/60"
        style={{ bottom: "0.5rem" }}
        initial={{ scaleY: 0 }} animate={{ scaleY: 1 }} transition={{ duration: 0.9, ease: [0.22, 1, 0.36, 1] }}
      />
      {hops.map((h, i) => {
        const slow = h.delay != null && (h.delay > 300 || h.delay < 0);
        return (
          <motion.li key={i} className="relative pb-5 pl-8 last:pb-0"
            initial={{ opacity: 0, x: -8 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: 0.15 + i * 0.12 }}>
            <span className="absolute left-0 top-1 flex h-[15px] w-[15px] items-center justify-center rounded-full border border-net/50 bg-obsidian" aria-hidden="true">
              <span className="h-1.5 w-1.5 rounded-full bg-net shadow-[0_0_8px_2px_rgba(56,189,248,0.6)]" />
            </span>
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-xs font-semibold text-white">Hop {h.index}{i === 0 ? " · origin" : i === hops.length - 1 ? " · final" : ""}</span>
              {h.ip && <Badge tone={ipTone(h.ip)} className="normal-case">{defang(/:/.test(h.ip) ? "" : "ipv4", h.ip)}</Badge>}
              {h.with && <Badge>{h.with}</Badge>}
              {i > 0 && (
                <Badge className="normal-case" tone={slow ? "warn" : "muted"} title={h.delay < 0 ? "Negative delay: clock skew or forged header" : "Time since previous hop"}>
                  <Clock className="h-3 w-3" /> {formatDelay(h.delay)}
                </Badge>
              )}
            </div>
            <p className="mono mt-1 break-all text-[12px] text-slate-400">
              <span className="text-slate-500">from</span> {h.from ?? "?"} <span className="text-slate-500">→ by</span> <span className="text-net/90">{h.by ?? "?"}</span>
            </p>
            {h.date && <p className="mt-0.5 font-mono text-[11px] text-slate-500">{h.date}</p>}
          </motion.li>
        );
      })}
    </ol>
  );
}

export default function EmailMode() {
  const [text, setText] = useState("");
  const deferred = useDeferredValue(text);
  const scanning = useScanPulse(text);
  const a = useMemo(() => (deferred.trim() ? analyzeHeaders(deferred) : null), [deferred]);
  const parsed = a && a.headers.length > 0;

  const verdict = useMemo(() => {
    if (!parsed) return null;
    const fails = ["spf", "dkim", "dmarc"].filter((k) => authTone(a.auth[k].status) === "risk").length;
    const risky = a.alignment.findings.filter((f) => f.level === "risk").length;
    if (a.auth.dmarc.status === "fail" || fails >= 2 || risky >= 2)
      return { tone: "risk", icon: MailWarning, title: "Likely spoofed or malicious", text: `${fails} failed/missing auth check${fails === 1 ? "" : "s"}, ${a.alignment.findings.length} sender mismatch${a.alignment.findings.length === 1 ? "" : "es"}.` };
    if (fails || a.alignment.findings.length)
      return { tone: "warn", icon: AlertTriangle, title: "Needs review", text: "Some checks failed or sender fields don't line up." };
    return { tone: "safe", icon: MailCheck, title: "Authenticated and aligned", text: "SPF, DKIM and DMARC pass and sender fields are consistent. Content can still be malicious." };
  }, [a, parsed]);

  return (
    <div className="grid gap-5 lg:grid-cols-[minmax(0,5fr)_minmax(0,7fr)]">
      <div className="space-y-5">
        <Terminal
          label="Raw email headers"
          value={text}
          onChange={setText}
          scanning={scanning}
          minRows={18}
          placeholder={"Paste the full raw headers (Outlook: File → Properties → Internet headers; Gmail: Show original)."}
          footer="Parsed locally. Nothing leaves your browser."
          presets={[
            { label: "Load Spoofed Email Sample", icon: MailWarning, onClick: () => setText(SPOOFED_EMAIL) },
            { label: "Load Legit Sample", icon: MailCheck, onClick: () => setText(LEGIT_EMAIL) },
            { label: "Clear", icon: Trash2, onClick: () => setText("") },
          ]}
        />
        {parsed && (
          <Panel title="Sender alignment" icon={UserCheck} delay={0.1}>
            <div className="divide-y divide-white/[0.05]">
              <AddressRow label="From" addr={a.alignment.from} />
              <AddressRow label="Return-Path" addr={a.alignment.returnPath} highlight={a.alignment.findings.some((f) => f.title.startsWith("Return-Path"))} />
              <AddressRow label="Reply-To" addr={a.alignment.replyTo} highlight={a.alignment.findings.some((f) => f.title.startsWith("Reply-To"))} />
            </div>
            <ul className="mt-3 space-y-2">
              {a.alignment.findings.length ? (
                a.alignment.findings.map((f) => (
                  <li key={f.title} className={`rounded-lg border px-3 py-2 text-xs ${TONES[f.level]}`}>
                    <p className="flex items-center gap-1.5 font-semibold"><AlertTriangle className="h-3.5 w-3.5" />{f.title}</p>
                    <p className="mt-0.5 font-normal text-slate-400">{f.detail}</p>
                  </li>
                ))
              ) : (
                <li className={`flex items-center gap-1.5 rounded-lg border px-3 py-2 text-xs ${TONES.safe}`}>
                  <CheckCircle2 className="h-3.5 w-3.5" /> From, Return-Path and Reply-To are aligned.
                </li>
              )}
            </ul>
          </Panel>
        )}
      </div>

      <div className="space-y-5">
        {parsed ? (
          <>
            <motion.div key={verdict.title} initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }}
              className={`glass flex items-start gap-3 p-4 ${GLOW[verdict.tone]}`}>
              <verdict.icon className={`mt-0.5 h-5 w-5 shrink-0 ${TEXT[verdict.tone]}`} aria-hidden="true" />
              <div className="min-w-0">
                <p className={`text-sm font-semibold ${TEXT[verdict.tone]}`}>{verdict.title}</p>
                <p className="text-xs text-slate-400">{verdict.text}</p>
                {a.subject && <p className="mt-2 break-words text-xs text-slate-300"><span className="text-slate-500">Subject:</span> {a.subject}</p>}
              </div>
            </motion.div>

            <Panel title="Authentication" icon={ShieldCheck}>
              <div className="grid gap-3 sm:grid-cols-3">
                <AuthCard name="SPF" result={a.auth.spf} index={0} />
                <AuthCard name="DKIM" result={a.auth.dkim} index={1} />
                <AuthCard name="DMARC" result={a.auth.dmarc} index={2} />
              </div>
            </Panel>

            <Panel title="Delivery path" icon={Route} delay={0.1}
              actions={<Badge tone="net"><GitCommitVertical className="h-3 w-3" />{a.hops.length} hops</Badge>}>
              <Timeline hops={a.hops} />
              <p className="mt-4 text-[11px] text-slate-500">
                Oldest hop first. Only hops added by your own mail servers are trustworthy; earlier ones can be forged by the sender.
              </p>
            </Panel>
          </>
        ) : (
          <Panel title="Header analysis" icon={MailCheck}>
            <EmptyState icon={MailWarning} title={text.trim() ? "No headers recognised" : "Awaiting headers"}>
              Paste raw headers or load the spoofed sample to see SPF/DKIM/DMARC results, sender mismatches and the hop-by-hop delivery timeline.
            </EmptyState>
          </Panel>
        )}
      </div>
    </div>
  );
}
