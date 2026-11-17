// Recursive payload deobfuscation ("Magic Auto-Unwrap").
// Each layer tries whole-input decoders first, then looks for an encoded blob
// embedded in otherwise readable text (e.g. `powershell -enc <base64>`).

const MAX_LAYERS = 12;

/* ---------- byte helpers ---------- */
const bytesToLatin1 = (bytes) => {
  let s = "";
  for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return s;
};

/** Bytes → text. Detects UTF-16LE (what PowerShell -EncodedCommand uses) by its zero high bytes. */
function bytesToText(bytes) {
  if (bytes.length >= 4 && bytes.length % 2 === 0) {
    let zeros = 0;
    for (let i = 1; i < bytes.length; i += 2) if (bytes[i] === 0) zeros++;
    if (zeros / (bytes.length / 2) > 0.9) return { text: new TextDecoder("utf-16le").decode(bytes), charset: "UTF-16LE" };
  }
  try {
    return { text: new TextDecoder("utf-8", { fatal: true }).decode(bytes), charset: "UTF-8" };
  } catch {
    return { text: bytesToLatin1(bytes), charset: "Latin-1" };
  }
}

/** Share of characters that are printable or ordinary whitespace. */
export function printableRatio(s) {
  if (!s.length) return 0;
  let ok = 0;
  for (const ch of s) {
    const c = ch.codePointAt(0);
    if ((c >= 0x20 && c < 0x7f) || c === 9 || c === 10 || c === 13 || (c >= 0xa0 && c !== 0xfffd)) ok++;
  }
  return ok / s.length;
}
const looksReadable = (s) => s.trim().length > 0 && printableRatio(s) >= 0.92;

/* ---------- encoders (used by the sample builder and tests) ---------- */
export const encode = {
  base64Utf8: (s) => btoa(bytesToLatin1(new TextEncoder().encode(s))),
  base64Utf16le: (s) => {
    const b = new Uint8Array(s.length * 2);
    for (let i = 0; i < s.length; i++) {
      b[i * 2] = s.charCodeAt(i) & 0xff;
      b[i * 2 + 1] = s.charCodeAt(i) >> 8;
    }
    return btoa(bytesToLatin1(b));
  },
  hex: (s) => [...new TextEncoder().encode(s)].map((b) => b.toString(16).padStart(2, "0")).join(""),
  url: (s) => [...new TextEncoder().encode(s)].map((b) => "%" + b.toString(16).padStart(2, "0").toUpperCase()).join(""),
  charCodes: (s) => [...s].map((c) => c.charCodeAt(0)).join(","),
};

/* ---------- decoders ---------- */
function decodeBase64(input) {
  let s = input.replace(/\s+/g, "");
  if (s.length < 8 || !/^[A-Za-z0-9+/_-]+={0,2}$/.test(s)) return null;
  // Pure hex or pure digits are far more likely to be something else.
  if (/^[0-9a-f]+$/i.test(s)) return null;
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  s += "=".repeat((4 - (s.length % 4)) % 4);
  try {
    const bin = atob(s);
    const { text, charset } = bytesToText(Uint8Array.from(bin, (c) => c.charCodeAt(0)));
    return looksReadable(text) ? { text, detail: charset } : null;
  } catch {
    return null;
  }
}

function decodeHex(input) {
  let s = input.trim();
  let style = "plain";
  if (/^(?:\\x[0-9a-f]{2})+$/i.test(s)) style = "\\x escapes";
  else if (/^(?:0x[0-9a-f]{2}[\s,]*)+$/i.test(s)) style = "0x bytes";
  s = s.replace(/\\x|0x|[\s,:-]/gi, "");
  if (s.length < 8 || s.length % 2 || !/^[0-9a-f]+$/i.test(s)) return null;
  const bytes = Uint8Array.from(s.match(/../g), (h) => parseInt(h, 16));
  const { text, charset } = bytesToText(bytes);
  return looksReadable(text) ? { text, detail: `${style}, ${charset}` } : null;
}

function decodeUrl(input) {
  if (!/%[0-9a-f]{2}/i.test(input)) return null;
  let text;
  try {
    text = decodeURIComponent(input.replace(/\+/g, " "));
  } catch {
    // Malformed sequences: decode each valid run separately.
    text = input.replace(/(?:%[0-9a-f]{2})+/gi, (run) => {
      try {
        return decodeURIComponent(run);
      } catch {
        return run;
      }
    });
  }
  return text !== input && looksReadable(text) ? { text, detail: "percent-encoding" } : null;
}

function decodeCharCodes(input) {
  // Strip common wrappers: String.fromCharCode(...), [char]72+[char]101, [char[]](72,101)
  const nums = input.match(/\d{1,5}/g);
  const stripped = input
    .replace(/String\.fromCharCode|\[char\[\]\]|\[char\]|-join|\[string\]|[()[\]\s,;+'"]/gi, " ")
    .trim();
  if (!nums || nums.length < 4 || !/^[\d\s]+$/.test(stripped)) return null;
  const codes = nums.map(Number);
  if (codes.some((c) => c > 0xffff)) return null;
  const text = String.fromCharCode(...codes);
  return looksReadable(text) ? { text, detail: `${codes.length} char codes` } : null;
}

const WHOLE_DECODERS = [
  ["Hex", decodeHex],
  ["Char codes", decodeCharCodes],
  ["Base64", decodeBase64],
  ["URL", decodeUrl],
];

/* ---------- embedded blobs inside readable text ---------- */
const EMBEDDED = [
  ["Char codes", /(?:String\.fromCharCode\(\s*[\d\s,]+\)|(?:\[char\]\s*\d{1,5}\s*\+?\s*){4,})/gi, decodeCharCodes],
  ["Hex", /(?:\\x[0-9a-f]{2}){4,}/gi, decodeHex],
  ["Base64", /[A-Za-z0-9+/]{20,}={0,2}/g, decodeBase64],
  ["URL", /(?:%[0-9a-f]{2}[^\s%]{0,3}){3,}/gi, decodeUrl],
];

function decodeEmbedded(text) {
  for (const [method, re, fn] of EMBEDDED) {
    let hits = 0;
    let detail = "";
    const out = text.replace(re, (blob) => {
      const r = fn(blob);
      if (!r) return blob;
      hits++;
      detail = r.detail;
      return r.text;
    });
    if (hits) return { method: `${method} (embedded)`, text: out, detail: `${hits} blob${hits > 1 ? "s" : ""}, ${detail}` };
  }
  return null;
}

/** Decode one layer, or return null when nothing more can be peeled off. */
export function decodeLayer(text) {
  for (const [method, fn] of WHOLE_DECODERS) {
    const r = fn(text);
    if (r && r.text !== text) return { method, text: r.text, detail: r.detail };
  }
  const e = decodeEmbedded(text);
  return e && e.text !== text ? e : null;
}

/**
 * Peel encodings until nothing changes.
 * Returns stages: [{ layer: 0, method: "Input", text }, { layer: 1, method: "Base64", detail, text }, ...]
 */
export function autoUnwrap(input) {
  const stages = [{ layer: 0, method: "Input", detail: `${input.length} chars`, text: input }];
  const seen = new Set([input]);
  let current = input;
  for (let i = 1; i <= MAX_LAYERS; i++) {
    const r = decodeLayer(current);
    if (!r || seen.has(r.text)) break;
    seen.add(r.text);
    stages.push({ layer: i, ...r });
    current = r.text;
  }
  return stages;
}
