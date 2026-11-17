// Lightweight MITRE ATT&CK heuristics for decoded command lines.
// These are keyword heuristics to guide triage, not detections with verdicts.

export const RULES = [
  {
    id: "T1059.001", name: "PowerShell", tactic: "Execution", severity: "high",
    patterns: [/\bpowershell(?:\.exe)?\b/gi, /\bpwsh(?:\.exe)?\b/gi, /\bIEX\b/g, /\bInvoke-Expression\b/gi],
  },
  {
    id: "T1027", name: "Obfuscated Files or Information", tactic: "Defense Evasion", severity: "high",
    patterns: [/\s-e(?:nc(?:odedcommand)?|c)?\s+[A-Za-z0-9+/=]{16,}/gi, /String\.fromCharCode/g, /\[char\]\s*\d+/gi],
  },
  {
    id: "T1140", name: "Deobfuscate/Decode Files or Information", tactic: "Defense Evasion", severity: "medium",
    patterns: [/FromBase64String/gi, /\bcertutil(?:\.exe)?\s+[-/]decode\b/gi, /\bbase64\s+(?:-d|--decode)\b/gi, /\batob\(/g],
  },
  {
    id: "T1105", name: "Ingress Tool Transfer", tactic: "Command and Control", severity: "high",
    patterns: [
      /\bcurl(?:\.exe)?\s/gi, /\bwget\s/gi, /DownloadString|DownloadFile|DownloadData/gi, /Net\.WebClient/gi,
      /\bInvoke-WebRequest\b|\biwr\s/gi, /\bcertutil(?:\.exe)?\s+[-/]urlcache\b/gi, /\bbitsadmin(?:\.exe)?\s+\/transfer\b/gi,
      /\bStart-BitsTransfer\b/gi,
    ],
  },
  {
    id: "T1547.001", name: "Boot or Logon Autostart: Registry Run Keys", tactic: "Persistence", severity: "high",
    patterns: [/\breg(?:\.exe)?\s+add\b/gi, /CurrentVersion\\Run(?:Once)?\b/gi, /\\Startup\\/gi],
  },
  {
    id: "T1053.005", name: "Scheduled Task", tactic: "Persistence", severity: "high",
    patterns: [/\bschtasks(?:\.exe)?\s+\/create\b/gi, /\bRegister-ScheduledTask\b/gi],
  },
  {
    id: "T1059.003", name: "Windows Command Shell", tactic: "Execution", severity: "medium",
    patterns: [/\bcmd(?:\.exe)?\s+\/[ck]\b/gi],
  },
  {
    id: "T1059.004", name: "Unix Shell", tactic: "Execution", severity: "medium",
    patterns: [/\|\s*(?:ba)?sh\b/g, /\bbash\s+-c\b/g, /\/bin\/(?:ba)?sh\b/g, /\bchmod\s+\+x\b/g],
  },
  {
    id: "T1059.007", name: "JavaScript", tactic: "Execution", severity: "medium",
    patterns: [/\beval\s*\(/g, /\bnew\s+ActiveXObject\b/gi, /\bWScript\.Shell\b/gi],
  },
  {
    id: "T1564.003", name: "Hidden Window", tactic: "Defense Evasion", severity: "medium",
    patterns: [/\s-w(?:indowstyle)?\s+hidden\b/gi],
  },
  {
    id: "T1562.001", name: "Impair Defenses: Disable or Modify Tools", tactic: "Defense Evasion", severity: "high",
    patterns: [/Set-MpPreference\s+-Disable\w+/gi, /Add-MpPreference\s+-Exclusion\w+/gi, /\bnetsh\s+advfirewall\s+set\b.*\boff\b/gi],
  },
  {
    id: "T1218", name: "System Binary Proxy Execution", tactic: "Defense Evasion", severity: "high",
    patterns: [/\bmshta(?:\.exe)?\b/gi, /\brundll32(?:\.exe)?\b/gi, /\bregsvr32(?:\.exe)?\b/gi],
  },
  {
    id: "T1047", name: "Windows Management Instrumentation", tactic: "Execution", severity: "medium",
    patterns: [/\bwmic(?:\.exe)?\b.*\bprocess\s+call\s+create\b/gi, /\bInvoke-WmiMethod\b/gi, /\bInvoke-CimMethod\b/gi],
  },
  {
    id: "T1003.001", name: "OS Credential Dumping: LSASS Memory", tactic: "Credential Access", severity: "high",
    patterns: [/\bmimikatz\b/gi, /sekurlsa::/gi, /\blsass(?:\.exe|\.dmp)?\b/gi, /comsvcs(?:\.dll)?.*MiniDump/gi],
  },
  {
    id: "T1490", name: "Inhibit System Recovery", tactic: "Impact", severity: "high",
    patterns: [/\bvssadmin(?:\.exe)?\s+delete\s+shadows\b/gi, /\bwbadmin(?:\.exe)?\s+delete\b/gi, /\bbcdedit\b.*recoveryenabled\s+no/gi],
  },
  {
    id: "T1070.001", name: "Indicator Removal: Clear Windows Event Logs", tactic: "Defense Evasion", severity: "high",
    patterns: [/\bwevtutil(?:\.exe)?\s+cl\b/gi, /\bClear-EventLog\b/gi],
  },
  {
    id: "T1136.001", name: "Create Account: Local Account", tactic: "Persistence", severity: "medium",
    patterns: [/\bnet(?:\.exe)?\s+user\s+\S+\s+\S+\s+\/add\b/gi, /\bNew-LocalUser\b/gi],
  },
  {
    id: "T1033", name: "System Owner/User Discovery", tactic: "Discovery", severity: "medium",
    patterns: [/\bwhoami(?:\.exe)?\b/gi],
  },
  {
    id: "T1082", name: "System Information Discovery", tactic: "Discovery", severity: "medium",
    patterns: [/\bsysteminfo(?:\.exe)?\b/gi, /\buname\s+-a\b/g],
  },
];

export const attackUrl = (id) => `https://attack.mitre.org/techniques/${id.replace(".", "/")}/`;

/**
 * Scan text. Returns [{ ...rule, matches: [{ start, end, text }] }] for rules that hit,
 * ordered high severity first.
 */
export function scanMitre(text) {
  const hits = [];
  for (const rule of RULES) {
    const matches = [];
    for (const re of rule.patterns) {
      re.lastIndex = 0;
      for (const m of text.matchAll(re)) {
        if (m[0].length) matches.push({ start: m.index, end: m.index + m[0].length, text: m[0].trim() });
      }
    }
    if (matches.length) hits.push({ ...rule, matches: matches.sort((a, b) => a.start - b.start) });
  }
  return hits.sort((a, b) => (a.severity === b.severity ? 0 : a.severity === "high" ? -1 : 1));
}

/**
 * Split text into segments for highlighting. Overlapping matches are merged;
 * each highlighted segment keeps the IDs of every technique that covers it.
 */
export function segmentText(text, hits) {
  const marks = hits.flatMap((h) => h.matches.map((m) => ({ ...m, id: h.id, severity: h.severity })));
  if (!marks.length) return [{ text, ids: [] }];
  marks.sort((a, b) => a.start - b.start || b.end - a.end);
  const merged = [];
  for (const m of marks) {
    const last = merged[merged.length - 1];
    if (last && m.start < last.end) {
      last.end = Math.max(last.end, m.end);
      if (!last.ids.includes(m.id)) last.ids.push(m.id);
      if (m.severity === "high") last.severity = "high";
    } else merged.push({ start: m.start, end: m.end, ids: [m.id], severity: m.severity });
  }
  const out = [];
  let pos = 0;
  for (const m of merged) {
    if (m.start > pos) out.push({ text: text.slice(pos, m.start), ids: [] });
    out.push({ text: text.slice(m.start, m.end), ids: m.ids, severity: m.severity });
    pos = m.end;
  }
  if (pos < text.length) out.push({ text: text.slice(pos), ids: [] });
  return out;
}
