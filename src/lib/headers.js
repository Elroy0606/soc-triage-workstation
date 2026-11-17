// Raw email header parsing: authentication results, sender alignment, Received hops.

/** Unfold RFC 5322 continuation lines and return [{ name, value }] in original order. */
export function parseHeaders(raw) {
  const lines = raw.replace(/\r\n?/g, "\n").split("\n");
  const headers = [];
  for (const line of lines) {
    if (!line.trim()) {
      if (headers.length) break; // blank line ends the header block
      continue;
    }
    if (/^[ \t]/.test(line) && headers.length) {
      headers[headers.length - 1].value += " " + line.trim();
      continue;
    }
    const m = line.match(/^([!-9;-~]+):\s?(.*)$/);
    if (m) headers.push({ name: m[1], value: m[2].trim() });
  }
  return headers;
}

const all = (headers, name) => headers.filter((h) => h.name.toLowerCase() === name.toLowerCase()).map((h) => h.value);
const first = (headers, name) => all(headers, name)[0] ?? null;

/** Pull the bare address out of `"Name" <a@b.com>` or `<a@b.com>` or `a@b.com`. */
export function parseAddress(value) {
  if (!value) return null;
  // The real address is the LAST <...>; spoofers often hide a fake one inside the display name.
  const angles = [...value.matchAll(/<\s*([^<>\s]+@[^<>\s]+)\s*>/g)];
  const angle = angles.at(-1);
  const bare = value.match(/[^\s<>"',;]+@[^\s<>"',;]+/);
  const address = (angle?.[1] ?? bare?.[0] ?? "").toLowerCase();
  if (!address) return null;
  const display = angle ? value.slice(0, angle.index).replace(/^["'\s]+|["'\s]+$/g, "") : "";
  return { address, domain: address.split("@")[1], display, raw: value };
}

/** Organisational domain, approximated as the last two labels (last three for e.g. co.uk). */
export function orgDomain(domain) {
  if (!domain) return "";
  const parts = domain.toLowerCase().split(".");
  const twoLevel = /^(?:co|com|net|org|gov|ac|edu)$/.test(parts[parts.length - 2] || "") && parts.at(-1).length === 2;
  return parts.slice(twoLevel ? -3 : -2).join(".");
}

const AUTH_STATES = ["pass", "fail", "softfail", "neutral", "none", "temperror", "permerror", "policy", "bestguesspass"];

/** SPF / DKIM / DMARC from Authentication-Results, falling back to Received-SPF. */
export function parseAuth(headers) {
  const result = {
    spf: { status: "none", detail: "No SPF result found" },
    dkim: { status: "none", detail: "No DKIM signature result found" },
    dmarc: { status: "none", detail: "No DMARC result found" },
  };
  const ar = all(headers, "Authentication-Results").join("; ");
  for (const mech of ["spf", "dkim", "dmarc"]) {
    const m = ar.match(new RegExp(`\\b${mech}\\s*=\\s*([a-z]+)([^;]*)`, "i"));
    if (m && AUTH_STATES.includes(m[1].toLowerCase())) {
      result[mech] = { status: m[1].toLowerCase(), detail: m[2].replace(/\s+/g, " ").trim() || "Authentication-Results" };
    }
  }
  if (result.spf.status === "none") {
    const rs = first(headers, "Received-SPF");
    const m = rs?.match(/^([a-z]+)\b(.*)$/i);
    if (m) result.spf = { status: m[1].toLowerCase(), detail: m[2].trim() || "Received-SPF" };
  }
  return result;
}

/** Visual tone for a status: pass → safe, soft/neutral → warn, everything else → risk. */
export function authTone(status) {
  if (status === "pass" || status === "bestguesspass") return "safe";
  if (status === "softfail" || status === "neutral" || status === "temperror") return "warn";
  return "risk";
}

/** Compare From / Return-Path / Reply-To. Returns a list of findings. */
export function checkAlignment(headers) {
  const from = parseAddress(first(headers, "From"));
  const returnPath = parseAddress(first(headers, "Return-Path"));
  const replyTo = parseAddress(first(headers, "Reply-To"));
  const findings = [];

  if (from && returnPath && orgDomain(from.domain) !== orgDomain(returnPath.domain)) {
    findings.push({
      level: "risk",
      title: "Return-Path domain differs from From",
      detail: `Bounces go to ${returnPath.domain}, but the visible sender is ${from.domain}.`,
    });
  }
  if (from && replyTo && replyTo.address !== from.address) {
    const sameOrg = orgDomain(replyTo.domain) === orgDomain(from.domain);
    findings.push({
      level: sameOrg ? "warn" : "risk",
      title: sameOrg ? "Reply-To uses a different mailbox" : "Reply-To points to a different domain",
      detail: `Replies go to ${replyTo.address} instead of ${from.address}.`,
    });
  }
  if (from?.display) {
    const embedded = from.display.match(/[^\s<>"']+@[^\s<>"']+/);
    if (embedded && embedded[0].toLowerCase() !== from.address) {
      findings.push({
        level: "risk",
        title: "Display name contains a different address",
        detail: `Display name shows ${embedded[0]}, but the real sender is ${from.address}.`,
      });
    }
  }
  return { from, returnPath, replyTo, findings };
}

const IP_RE = /\b(?:\d{1,3}\.){3}\d{1,3}\b|\b[0-9a-f]{1,4}(?::[0-9a-f]{0,4}){2,7}\b/i;

/** Parse one Received header into its parts. */
export function parseReceived(value) {
  const semi = value.lastIndexOf(";");
  const body = semi >= 0 ? value.slice(0, semi) : value;
  const dateStr = semi >= 0 ? value.slice(semi + 1).replace(/\([^)]*\)/g, "").trim() : "";
  const ts = dateStr ? Date.parse(dateStr) : NaN;
  const from = body.match(/\bfrom\s+(\S+)/i)?.[1] ?? null;
  const by = body.match(/\bby\s+(\S+)/i)?.[1] ?? null;
  const withProto = body.match(/\bwith\s+(\S+)/i)?.[1] ?? null;
  // Prefer the bracketed IP of the sending host: "from host (rdns [1.2.3.4])"
  // No "from" clause means no relay IP; never report the receiving ("by") server's address.
  const fromPart = body.match(/\bfrom\s+[\s\S]*?(?=\bby\b|$)/i)?.[0] ?? "";
  const ip = fromPart.match(/\[([^\]]+)\]/)?.[1]?.replace(/^IPv6:/i, "") ?? fromPart.match(IP_RE)?.[0] ?? null;
  return { from, by, with: withProto, ip, date: dateStr, timestamp: Number.isNaN(ts) ? null : ts, raw: value };
}

/** Received hops ordered oldest → newest, with the delay since the previous hop in seconds. */
export function parseHops(headers) {
  const hops = all(headers, "Received").map(parseReceived).reverse();
  return hops.map((h, i) => {
    const prev = hops[i - 1];
    const delay = prev && h.timestamp != null && prev.timestamp != null ? Math.round((h.timestamp - prev.timestamp) / 1000) : null;
    return { ...h, index: i + 1, delay };
  });
}

export function formatDelay(sec) {
  if (sec == null) return "n/a";
  const sign = sec < 0 ? "-" : "+";
  const s = Math.abs(sec);
  if (s < 60) return `${sign}${s}s`;
  if (s < 3600) return `${sign}${Math.floor(s / 60)}m ${s % 60}s`;
  return `${sign}${Math.floor(s / 3600)}h ${Math.floor((s % 3600) / 60)}m`;
}

/** Everything the Email mode needs, in one call. */
export function analyzeHeaders(raw) {
  const headers = parseHeaders(raw);
  return {
    headers,
    subject: first(headers, "Subject"),
    date: first(headers, "Date"),
    messageId: first(headers, "Message-ID"),
    auth: parseAuth(headers),
    alignment: checkAlignment(headers),
    hops: parseHops(headers),
  };
}
