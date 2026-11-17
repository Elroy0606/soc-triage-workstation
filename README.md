# Threat Triage Workstation

A client-side SOC Tier 1 workstation for triaging alerts: extract and enrich IOCs, unwrap obfuscated payloads with MITRE ATT&CK mapping, and analyse email headers. Built with React, Tailwind CSS, Framer Motion and Lucide icons.

**Privacy:** 100% client-side. No backend, no API keys, no uploads. An indicator only leaves the browser when you click one of its OSINT pivot links.

## Modes

### 1. IOC Extractor & Enrichment Matrix
- Extracts and deduplicates IPv4 addresses, domains, URLs, emails and MD5 / SHA-1 / SHA-256 hashes
- Reads already-defanged input (`hxxps://`, `[.]`, `(dot)`, `[@]`, `[at]`, …)
- Tags IPs as `PRIVATE RFC1918`, `EXTERNAL`, loopback, link-local, CGNAT, multicast or reserved
- Defanged/raw toggle (`hxxps://evil[.]com`, `user[@]evil[.]com`, `10[.]0[.]0[.]1`)
- Shannon entropy per domain (most random label, TLD excluded): `Possible DGA` above 3.8 bits/char, high above 4.2
- Telemetry ring showing the mix of IOC types, plus stat tiles
- OSINT pivots: VirusTotal, AbuseIPDB, Shodan, URLhaus, MalwareBazaar
- **Tier 2 Escalation Note** with a suggested priority, Markdown and JSON output, copy or download

### 2. Recursive Payload Deobfuscator & MITRE Mapper
- **Magic Auto-Unwrap** peels nested layers until the output is readable; **Step** decodes one layer at a time
- Decoders: Base64 (UTF-8 and UTF-16LE as used by `powershell -enc`), hex (`41 42`, `\x41`, `0x41`), percent-encoding, char codes (`String.fromCharCode`, `[char]`)
- Finds encoded blobs embedded inside readable text and decodes them in place
- Keyword heuristics for 19 ATT&CK techniques (T1059.001, T1027, T1105, T1547.001, T1053.005, T1218, T1003.001, T1490, …) with inline highlights; click a technique to focus its matches

### 3. Email Header & Auth Visualizer
- SPF / DKIM / DMARC from `Authentication-Results` (falls back to `Received-SPF`)
- Flags `From` / `Return-Path` / `Reply-To` mismatches and display-name address spoofing
- Animated `Received:` hop timeline, oldest hop first, with relay IPs and the delay between hops
- An overall verdict: likely spoofed / needs review / authenticated

All samples use RFC 5737 documentation IPs, private address space, the harmless EICAR test hashes and a fictional company ("Northwind").

## Run it

```bash
npm install
npm run dev       # http://localhost:5173
npm test          # engine unit tests (Node 20+)
npm run build     # static site in dist/
```

`dist/` uses relative paths, so it can be hosted on any static host (GitHub Pages, Cloudflare Pages, a subdomain).

## Project layout

```
src/
  lib/          pure, unit-tested engines (no React)
    ioc.js        extraction, defanging, IP classification, entropy, pivots
    decode.js     recursive decoders and auto-unwrap
    mitre.js      ATT&CK keyword rules, match highlighting
    headers.js    header unfolding, auth results, alignment, Received hops
    report.js     Tier 2 escalation note (Markdown + JSON)
    samples.js    training presets
  components/   glass UI primitives, mode nav, terminal, telemetry ring, modal
  modes/        IocMode, DeobfuscatorMode, EmailMode
tests/          node:test suite for the engines
classic/        the original single-file vanilla JS version
```

## Limitations

- Entropy and ATT&CK mapping are heuristics to guide triage, not verdicts.
- Domains are only recognised when their TLD is on a built-in list (keeps `payload.exe` out). `.zip` and `.mov` are excluded on purpose.
- Organisational-domain matching for sender alignment is approximate (no Public Suffix List).
- Received hops added before your own mail servers can be forged by the sender.

## Accessibility

Keyboard-navigable tabs (arrow keys), focus-trapped dialog, visible focus rings, screen-reader labels on icon buttons, a skip link, and `prefers-reduced-motion` support.
