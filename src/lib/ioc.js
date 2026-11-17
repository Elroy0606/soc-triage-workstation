// IOC extraction, defanging, classification and OSINT pivots.
// Pure functions only (no DOM), so they can be unit-tested in Node.

/** Turn common defanged notations back into live form before matching. */
export function refang(s) {
  return s
    .replace(/\bh(?:xx|XX|\[xx\]|\[XX\]|\*\*)p(s?)(?=\[?:)/gi, "http$1")
    .replace(/\bfxp(?=\[?:)/gi, "ftp")
    .replace(/\[:\/\/\]|\[:\]\/\//g, "://")
    .replace(/\[\s*:\s*\]/g, ":")
    .replace(/\[\s*\/\s*\]/g, "/")
    .replace(/\[\s*(?:\.|dot)\s*\]|\(\s*(?:\.|dot)\s*\)|\{\s*(?:\.|dot)\s*\}|\\\./gi, ".")
    .replace(/\[\s*(?:@|at)\s*\]|\(\s*(?:@|at)\s*\)|\{\s*(?:@|at)\s*\}/gi, "@");
}

const DEFANGERS = {
  url: (u) =>
    u
      .replace(/^https?/i, (m) => m.replace(/tt/i, "xx"))
      .replace(/^ftp/i, "fxp")
      .replace(/\./g, "[.]"),
  domain: (d) => d.replace(/\./g, "[.]"),
  ipv4: (i) => i.replace(/\./g, "[.]"),
  email: (e) => e.replace("@", "[@]").replace(/\./g, "[.]"),
};

export const defang = (type, value) => (DEFANGERS[type] ? DEFANGERS[type](value) : value);

/** Text with every network indicator defanged (hashes are left as is). */
export function defangText(raw) {
  let t = refang(raw);
  t = t.replace(RE.url, (m) => {
    const u = trimUrl(m);
    return DEFANGERS.url(u) + m.slice(u.length);
  });
  t = t.replace(RE.email, DEFANGERS.email);
  t = t.replace(RE.ipv4, DEFANGERS.ipv4);
  t = t.replace(RE.domain, (d) => (hasKnownTld(d) ? DEFANGERS.domain(d) : d));
  return t;
}

// TLD allowlist keeps file names like "invoice.pdf" or "stage2.ps1" out of the domain list.
// .zip and .mov are real TLDs but are left out on purpose: they are almost always file names.
const TLDS = new Set(
  (
    "com net org edu gov mil int io co ai app dev xyz info biz me tv cc us uk ca au de fr it es nl be ch at se no dk fi " +
    "pl cz sk hu ro bg gr pt ie ru ua by kz cn jp kr in id my sg th vn ph hk tw br ar mx cl pe ve za ng ke eg ma tr il ir " +
    "sa ae qa pk bd lk nz online site top club shop store live tech space website pw ws tk ml ga cf gq su cyou icu buzz " +
    "rest bond sbs cfd lol fun link click work world today email cloud host digital network services support solutions page"
  ).split(" ")
);
const hasKnownTld = (d) => TLDS.has(d.split(".").pop().toLowerCase());

export const RE = {
  url: /\b(?:https?|ftp):\/\/[^\s"'<>`\][(){}|\\^]+/gi,
  email: /\b[a-z0-9._%+-]+@(?:[a-z0-9-]+\.)+[a-z]{2,24}\b/gi,
  ipv4: /(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?!\.?\d)/g,
  sha256: /\b[a-f0-9]{64}\b/gi,
  sha1: /\b[a-f0-9]{40}\b/gi,
  md5: /\b[a-f0-9]{32}\b/gi,
  domain: /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b/gi,
};

const trimUrl = (u) => u.replace(/[.,;:!?'")\]}>]+$/, "");

/** Classify an IPv4 address. Returns { scope: "private" | "special" | "external", label }. */
export function classifyIPv4(ip) {
  const [a, b] = ip.split(".").map(Number);
  if (a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168))
    return { scope: "private", label: "PRIVATE RFC1918" };
  if (a === 127) return { scope: "special", label: "LOOPBACK" };
  if (a === 169 && b === 254) return { scope: "special", label: "LINK-LOCAL" };
  if (a === 100 && b >= 64 && b <= 127) return { scope: "special", label: "CGNAT" };
  if (a >= 224 && a <= 239) return { scope: "special", label: "MULTICAST" };
  if (a === 0 || a >= 240) return { scope: "special", label: "RESERVED" };
  if ((a === 192 && b === 0) || (a === 198 && b === 51) || (a === 203 && b === 0))
    return { scope: "external", label: "EXTERNAL · DOC RANGE" };
  return { scope: "external", label: "EXTERNAL" };
}

/** Shannon entropy in bits per character. */
export function shannonEntropy(str) {
  if (!str) return 0;
  const freq = {};
  for (const ch of str) freq[ch] = (freq[ch] || 0) + 1;
  let h = 0;
  for (const n of Object.values(freq)) {
    const p = n / str.length;
    h -= p * Math.log2(p);
  }
  return h;
}

export const DGA_THRESHOLD = 3.8;
export const DGA_HIGH_THRESHOLD = 4.2;

/**
 * Entropy of the most random-looking label (TLD excluded, hyphens ignored).
 * DGA output usually sits in one long label, e.g. "qx7v2kfj9plm3tzr8w.top".
 */
export function domainEntropy(domain) {
  const labels = domain.toLowerCase().split(".").slice(0, -1);
  return labels.reduce((max, l) => Math.max(max, shannonEntropy(l.replace(/-/g, ""))), 0);
}

export function entropyFlag(entropy) {
  if (entropy > DGA_HIGH_THRESHOLD) return { level: "high", label: "Possible DGA · high entropy" };
  if (entropy > DGA_THRESHOLD) return { level: "medium", label: "Possible DGA" };
  return null;
}

export const TYPE_META = {
  ipv4: { label: "IPv4", color: "#38bdf8" },
  domain: { label: "Domain", color: "#fbbf24" },
  url: { label: "URL", color: "#fb923c" },
  email: { label: "Email", color: "#a78bfa" },
  md5: { label: "MD5", color: "#fb7185" },
  sha1: { label: "SHA-1", color: "#fb7185" },
  sha256: { label: "SHA-256", color: "#fb7185" },
};
export const TYPE_ORDER = ["ipv4", "domain", "url", "email", "sha256", "sha1", "md5"];
export const isHash = (t) => t === "md5" || t === "sha1" || t === "sha256";

/** Extract, normalise, deduplicate and annotate indicators from free text. */
export function extractIocs(rawText) {
  const text = refang(rawText);
  const found = new Map();
  const add = (type, value, extra = {}) => {
    const v = type === "ipv4" || type === "url" ? value : value.toLowerCase();
    const key = `${type}|${v}`;
    if (!found.has(key)) found.set(key, { id: key, type, value: v, defanged: defang(type, v), ...extra });
  };

  (text.match(RE.url) || []).map(trimUrl).forEach((u) => add("url", u));
  (text.match(RE.email) || []).forEach((e) => add("email", e));
  (text.match(RE.ipv4) || []).forEach((ip) => add("ipv4", ip, classifyIPv4(ip)));
  // \b boundaries mean a 64-char hash can never also match as a 32- or 40-char one.
  (text.match(RE.sha256) || []).forEach((h) => add("sha256", h));
  (text.match(RE.sha1) || []).forEach((h) => add("sha1", h));
  (text.match(RE.md5) || []).forEach((h) => add("md5", h));
  (text.match(RE.domain) || []).filter(hasKnownTld).forEach((d) => {
    const entropy = domainEntropy(d);
    add("domain", d, { entropy, flag: entropyFlag(entropy) });
  });

  return [...found.values()].sort((a, b) => TYPE_ORDER.indexOf(a.type) - TYPE_ORDER.indexOf(b.type));
}

/** One-click OSINT pivots. Nothing is fetched; links open only when the analyst clicks. */
export function pivots(type, v) {
  const e = encodeURIComponent;
  switch (type) {
    case "ipv4":
      return [
        ["VirusTotal", `https://www.virustotal.com/gui/ip-address/${e(v)}`],
        ["AbuseIPDB", `https://www.abuseipdb.com/check/${e(v)}`],
        ["Shodan", `https://www.shodan.io/host/${e(v)}`],
      ];
    case "domain":
      return [
        ["VirusTotal", `https://www.virustotal.com/gui/domain/${e(v)}`],
        ["URLhaus", `https://urlhaus.abuse.ch/browse.php?search=${e(v)}`],
        ["Shodan", `https://www.shodan.io/search?query=hostname%3A${e(v)}`],
      ];
    case "url":
      return [
        ["VirusTotal", `https://www.virustotal.com/gui/search/${e(e(v))}`],
        ["URLhaus", `https://urlhaus.abuse.ch/browse.php?search=${e(v)}`],
      ];
    case "email":
      return [["VirusTotal (domain)", `https://www.virustotal.com/gui/domain/${e(v.split("@")[1])}`]];
    case "md5":
    case "sha1":
    case "sha256":
      return [
        ["VirusTotal", `https://www.virustotal.com/gui/file/${v}`],
        ["MalwareBazaar", `https://bazaar.abuse.ch/browse.php?search=${type}%3A${v}`],
      ];
    default:
      return [];
  }
}
