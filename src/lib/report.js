// Tier 2 escalation note builder (Markdown for tickets, JSON for automation).
import { TYPE_META, TYPE_ORDER, isHash } from "./ioc.js";

/** Heuristic priority based on what was found. It's a suggestion, not a verdict. */
export function suggestPriority(iocs) {
  const reasons = [];
  const external = iocs.filter((i) => i.type === "ipv4" && i.scope === "external").length;
  const hashes = iocs.filter((i) => isHash(i.type)).length;
  const dga = iocs.filter((i) => i.flag).length;
  const urls = iocs.filter((i) => i.type === "url").length;
  if (hashes) reasons.push(`${hashes} file hash${hashes > 1 ? "es" : ""} to check`);
  if (dga) reasons.push(`${dga} high-entropy domain${dga > 1 ? "s" : ""} (possible DGA)`);
  if (external) reasons.push(`${external} external IP${external > 1 ? "s" : ""}`);
  if (urls) reasons.push(`${urls} URL${urls > 1 ? "s" : ""}`);
  const score = hashes * 2 + dga * 2 + external + urls;
  const level = score >= 6 ? "High" : score >= 3 ? "Medium" : "Low";
  return { level, reasons };
}

const grouped = (iocs) =>
  TYPE_ORDER.map((t) => [t, iocs.filter((i) => i.type === t)]).filter(([, list]) => list.length);

function noteFor(i) {
  if (i.type === "ipv4") return i.label;
  if (i.flag) return `${i.flag.label} (entropy ${i.entropy.toFixed(2)})`;
  return "";
}

export function buildEscalation(iocs, { title = "", analystNotes = "" } = {}) {
  const now = new Date();
  const priority = suggestPriority(iocs);
  const name = title.trim() || "Suspicious activity: Tier 1 triage";

  const md = [
    `## Tier 2 Escalation: ${name}`,
    "",
    `**Generated:** ${now.toISOString()}  `,
    `**Suggested priority:** ${priority.level}${priority.reasons.length ? ` (${priority.reasons.join(", ")})` : ""}  `,
    `**Indicators:** ${iocs.length}`,
    "",
    "### Indicators of compromise (defanged)",
    "",
  ];
  for (const [type, list] of grouped(iocs)) {
    md.push(`**${TYPE_META[type].label}**`, "", "| Indicator | Context |", "|---|---|");
    list.forEach((i) => md.push(`| \`${i.defanged}\` | ${noteFor(i) || "-"} |`));
    md.push("");
  }
  md.push(
    "### Tier 1 actions taken",
    "",
    "- [ ] Indicators checked against OSINT (VirusTotal / AbuseIPDB / URLhaus / MalwareBazaar)",
    "- [ ] SIEM searched for other hosts contacting these indicators",
    "- [ ] Affected user notified / host isolation requested if required",
    "",
    "### Analyst notes",
    "",
    analystNotes.trim() || "_None added._",
  );

  const json = {
    title: name,
    generated: now.toISOString(),
    suggested_priority: priority.level,
    priority_reasons: priority.reasons,
    indicator_count: iocs.length,
    indicators: iocs.map((i) => ({
      type: TYPE_META[i.type].label,
      value_defanged: i.defanged,
      ...(i.type === "ipv4" ? { scope: i.label } : {}),
      ...(i.type === "domain" ? { entropy: Number(i.entropy.toFixed(3)), possible_dga: !!i.flag } : {}),
    })),
    analyst_notes: analystNotes.trim(),
  };

  return { markdown: md.join("\n"), json: JSON.stringify(json, null, 2), priority };
}
