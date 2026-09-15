// CryptoValid — independent hash-chain verifier (Node.js, zero external deps).
// Clean-room second implementation of the SPEC (opencore/verifier.py), written to
// AGREE BYTE-FOR-BYTE with the reference, so an auditor can re-check evidence with a
// different language/runtime — proving the format is vendor-neutral, not tool-locked.
//
//   node cvverify.mjs <ledger.jsonl> [--algo sha256|sha3_256] [--pubkey <hex>]
//   node cvverify.mjs --conformance <spec/vectors_dir>
//
// Verifies: canonical hash-chain (self_hash + prev_hash linkage + sequential idx),
// and — when present — Ed25519 signatures over self_hash. stdlib crypto only.
// Honest scope: proves integrity/linkage/signature, NOT the truth of recorded facts.
import { createHash, verify as edVerify, createPublicKey } from "node:crypto";
import { readFileSync, readdirSync, existsSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const GENESIS_PREV = "0".repeat(64);
const ALGOS = ["sha256", "sha3_256"];
const ATTEST = new Set(["self_hash", "signature", "signer"]);

// --- canonical JSON: identical to Python json.dumps(sort_keys=True,
//     separators=(",",":"), ensure_ascii=True).
function pyEscape(s) {
  let out = '"';
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i), ch = s[i];
    if (ch === '"') out += '\\"';
    else if (ch === "\\") out += "\\\\";
    else if (ch === "\n") out += "\\n";
    else if (ch === "\r") out += "\\r";
    else if (ch === "\t") out += "\\t";
    else if (ch === "\b") out += "\\b";
    else if (ch === "\f") out += "\\f";
    else if (c < 0x20 || c > 0x7e) out += "\\u" + c.toString(16).padStart(4, "0");
    else out += ch;
  }
  return out + '"';
}
const cmp = (a, b) => { const A = [...a], B = [...b]; for (let i = 0; i < Math.min(A.length, B.length); i++) { const d = A[i].codePointAt(0) - B[i].codePointAt(0); if (d) return d; } return A.length - B.length; };
function canon(v) {
  if (v === null) return "null";
  if (v === true) return "true";
  if (v === false) return "false";
  if (typeof v === "number") { if (!Number.isInteger(v) || !Number.isSafeInteger(v)) throw new Error("non-portable number (float or |int|>2^53-1)"); return String(v); }
  if (typeof v === "string") return pyEscape(v);
  if (Array.isArray(v)) return "[" + v.map(canon).join(",") + "]";
  if (typeof v === "object") return "{" + Object.keys(v).sort(cmp).map((k) => pyEscape(k) + ":" + canon(v[k])).join(",") + "}";
  throw new Error("unserialisable " + typeof v);
}
function canonicalPayload(entry) {
  const d = {}; for (const k of Object.keys(entry)) if (!ATTEST.has(k)) d[k] = entry[k];
  return Buffer.from(canon(d), "utf-8");
}
function hashWith(algo, buf) { return createHash(algo === "sha3_256" ? "sha3-256" : "sha256").update(buf).digest("hex"); }

function detectAlgo(entries) {
  if (!entries.length || !("self_hash" in entries[0])) return null;
  let p; try { p = canonicalPayload(entries[0]); } catch (e) { return null; }
  for (const a of ALGOS) if (hashWith(a, p) === entries[0].self_hash) return a;
  return null;
}

// --- Ed25519 over the self_hash hex string bytes; signer = raw 32-byte pubkey hex
const SPKI = Buffer.from("302a300506032b6570032100", "hex");
function verifySig(entry, expectedPubHex) {
  const { signature, signer, self_hash } = entry;
  if (!signature || !signer || !self_hash) return { ok: false, reason: "missing signature/signer/self_hash" };
  if (expectedPubHex && signer !== expectedPubHex) return { ok: false, reason: "signer_mismatch" };
  try {
    const key = createPublicKey({ key: Buffer.concat([SPKI, Buffer.from(signer, "hex")]), format: "der", type: "spki" });
    const ok = edVerify(null, Buffer.from(self_hash, "utf-8"), key, Buffer.from(signature, "base64"));
    return ok ? { ok: true } : { ok: false, reason: "bad_signature" };
  } catch (e) { return { ok: false, reason: "verify_error" }; }
}

function hasDuplicateKeys(text) {
  const seen = []; let inStr = false, esc = false, expectKey = false, i = 0, curKey = null, readingKey = false;
  while (i < text.length) {
    const c = text[i++];
    if (inStr) {
      if (esc) {
        esc = false;
        if (readingKey) {
          if (c === "u") { const hex = text.substr(i, 4); i += 4; curKey += String.fromCharCode(parseInt(hex, 16)); }
          else curKey += ({ n: "\n", t: "\t", r: "\r", b: "\b", f: "\f", "/": "/", '"': '"' }[c] ?? c);
        }
      }
      else if (c === String.fromCharCode(92)) { esc = true; }
      else if (c === '"') { inStr = false; readingKey = false; }
      else if (readingKey) curKey += c;
      continue;
    }
    if (c === '"') { inStr = true; if (expectKey) { readingKey = true; curKey = ''; } continue; }
    if (c === '{') { seen.push(new Set()); expectKey = true; }
    else if (c === '}') { seen.pop(); expectKey = false; }
    else if (c === '[') { seen.push(null); expectKey = false; }
    else if (c === ']') { seen.pop(); expectKey = false; }
    else if (c === ':') {
      const set = seen.length ? seen[seen.length - 1] : null;
      if (curKey !== null && set) { if (set.has(curKey)) return true; set.add(curKey); }
      curKey = null; expectKey = false;
    } else if (c === ',') { expectKey = seen.length > 0 && seen[seen.length - 1] instanceof Set; }
  }
  return false;
}

// --- acceptance-profile pre-scans (linear, no parsing), same rules as verifier.py (14/09/2026):
//     nesting > MAX_JSON_DEPTH → json_too_deep; unpaired \uD800-\uDFFF escape → lone_surrogate.
export const MAX_JSON_DEPTH = 512;
export function jsonNestingDepth(text) {
  let depth = 0, max = 0, inStr = false, esc = false;
  for (const ch of text) {
    if (inStr) { if (esc) esc = false; else if (ch === "\\") esc = true; else if (ch === '"') inStr = false; }
    else if (ch === '"') inStr = true;
    else if (ch === "[" || ch === "{") { depth++; if (depth > max) max = depth; }
    else if (ch === "]" || ch === "}") depth--;
  }
  return max;
}
export function hasLoneSurrogate(text) {
  let i = 0; const n = text.length, hex = (s) => (/^[0-9a-fA-F]{4}$/.test(s) ? parseInt(s, 16) : NaN);
  while (i < n) {
    if (text[i] !== "\\") { i++; continue; }
    if (text[i + 1] === "u" && i + 5 < n) {
      const cp = hex(text.slice(i + 2, i + 6));
      if (Number.isNaN(cp)) { i += 2; continue; }   // malformed escape: the parser refuses it, not this rule
      if (cp >= 0xd800 && cp <= 0xdbff) {
        if (text.slice(i + 6, i + 8) !== "\\u") return true;
        const lo = hex(text.slice(i + 8, i + 12));
        if (!(lo >= 0xdc00 && lo <= 0xdfff)) return true;
        i += 12; continue;
      }
      if (cp >= 0xdc00 && cp <= 0xdfff) return true;
      i += 6; continue;
    }
    i += 2;
  }
  return false;
}

// Signed chain tip (15/09/2026, cryptovalid_tip.py / tip.go): same signed bytes in every language —
// {"entries":N,"kind":"cryptovalid_tip/1","ledger_id":"…","tip_sha256":"…","ts":"…"} (ledger_id = self_hash of entry 0,
// the chain's identity). With the tip and the TRUSTED log key,
// tail truncation / suffix rewrite / an unsealed append become named failures (a bare chain cannot see them).
export const TIP_KIND = "cryptovalid_tip/1";
export function tipPayload(entries, ledgerId, tipSha256, ts) {
  return Buffer.from(`{"entries":${entries},"kind":"${TIP_KIND}","ledger_id":"${ledgerId}","tip_sha256":"${tipSha256}","ts":"${ts}"}`, "utf-8");
}
const HEX64 = /^[0-9a-f]{64}$/;
export function parseInstant(s) {
  const t = String(s).trim();
  return Date.parse(/(Z|[+-]\d\d:\d\d)$/.test(t) ? t : t + "Z");   // a naive value is UTC, as in Python/Go
}
export function checkTip(entriesCount, lastSelfHash, tip, trustedPubkeyHex = null, notBefore = null, firstSelfHash = null, expectLedgerId = null) {
  if (!tip || typeof tip !== "object" || Array.isArray(tip) || tip.kind !== TIP_KIND) return { ok: false, error: "tip_invalid: not a cryptovalid_tip/1 document" };
  for (const k of ["entries", "ledger_id", "tip_sha256", "ts", "signature_hex"]) if (!(k in tip)) return { ok: false, error: `tip_invalid: tip missing field ${k}` };
  // strict types, same as Go's decoder: entries a non-negative integer, the rest strings
  if (typeof tip.entries !== "number" || !Number.isInteger(tip.entries) || tip.entries < 0) return { ok: false, error: "tip_invalid: tip entries must be a non-negative integer" };
  if (!["ledger_id", "tip_sha256", "ts", "signature_hex"].every((k) => typeof tip[k] === "string")) return { ok: false, error: "tip_invalid: tip fields must be strings" };
  // ONE timestamp profile in the three checkers: RFC 3339 with seconds and a zone (Z or ±hh:mm)
  if (!HEX64.test(tip.ledger_id) || !HEX64.test(tip.tip_sha256) || !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d{1,9})?(Z|[+-]\d\d:\d\d)$/.test(tip.ts) || Number.isNaN(parseInstant(tip.ts))) return { ok: false, error: "tip_invalid: not a cryptovalid_tip/1 document" };
  // the key inside the tip proves nothing: without the trusted log key there is NO verification (never a
  // "PASS but untrusted" an automation reads as exit 0 — council 15/09, Gemini)
  if (!trustedPubkeyHex) return { ok: false, trusted: false, error: "tip_untrusted: no trusted log key given (--trusted-pubkey); the key inside the tip cannot be trusted" };
  if (tip.log_pubkey_hex && tip.log_pubkey_hex !== trustedPubkeyHex) return { ok: false, error: "tip_invalid: tip log key differs from the trusted log key" };   // "" = absent, as in Python/Go
  let sigOk = false;
  try {
    const key = createPublicKey({ key: Buffer.concat([SPKI, Buffer.from(trustedPubkeyHex, "hex")]), format: "der", type: "spki" });
    sigOk = edVerify(null, tipPayload(Number(tip.entries), tip.ledger_id, tip.tip_sha256, tip.ts), key, Buffer.from(tip.signature_hex, "hex"));
  } catch (e) { sigOk = false; }
  if (!sigOk) return { ok: false, error: "tip_invalid: tip signature invalid" };
  const n = Number(tip.entries), trusted = Boolean(trustedPubkeyHex);
  if (expectLedgerId && tip.ledger_id !== expectLedgerId) return { ok: false, trusted, error: "ledger_id_mismatch: the tip belongs to a different ledger than the one you expect" };
  if (firstSelfHash !== null && entriesCount > 0 && tip.ledger_id !== firstSelfHash) return { ok: false, trusted, error: "tip_of_another_ledger: the tip's ledger_id is not this file's first self_hash" };
  // ROLLBACK (declared): an older genuine tip restored after a truncation passes; notBefore refuses older tips
  if (notBefore) {   // instants, not strings (council 15/09, Opus): 'Z' / '+00:00' / other offsets of the same moment agree
    const a = parseInstant(tip.ts), b = parseInstant(notBefore);
    if (Number.isNaN(b)) return { ok: false, trusted, error: "bad_not_before: --tip-not-before is not ISO-8601" };   // the verifier's error, not the tip's
    if (a < b) return { ok: false, trusted, error: `tip_rolled_back: the tip is dated ${tip.ts}, before the required ${notBefore}` };
  }
  if (entriesCount < n) return { ok: false, trusted, error: `tail_truncated: file has ${entriesCount} entries, the signed tip commits to ${n}` };
  if (entriesCount > n) return { ok: false, trusted, error: `unsealed_tail: file has ${entriesCount} entries, the signed tip commits to ${n} (appended after the last signed head)` };
  if (lastSelfHash !== tip.tip_sha256) return { ok: false, trusted, error: "tail_rewritten: same entry count but the last self_hash differs from the signed tip" };
  return { ok: true, trusted, entries: n, tip_sha256: tip.tip_sha256, ts: tip.ts };
}

export function verifyLedger(text, { algo = null, pubkey = null, tip = null, trustedPubkey = null, requireTip = false, tipNotBefore = null, expectLedgerId = null } = {}) {
  const entries = [], errors = [];
  text.split("\n").forEach((ln, i) => {
    if (!ln.trim()) return;
    let v;
    try {
      const d = jsonNestingDepth(ln); if (d > MAX_JSON_DEPTH) throw new Error(`json_too_deep: nesting ${d} exceeds ${MAX_JSON_DEPTH}`);
      if (hasLoneSurrogate(ln)) throw new Error("lone_surrogate");
      if (hasDuplicateKeys(ln)) throw new Error("duplicate_key"); v = JSON.parse(ln); } catch (e) { errors.push({ line: i, error: "json_decode:" + e.message }); return; }
    if (v && typeof v === "object" && !Array.isArray(v)) entries.push(v);
    else errors.push({ line: i, error: "not_a_json_object" });
  });
  const use = algo || detectAlgo(entries) || "sha256";
  const hashFailures = [], linkFailures = [];
  entries.forEach((e, i) => {
    if (!("self_hash" in e)) { hashFailures.push({ idx: e.idx ?? i, reason: "missing_self_hash" }); return; }
    let h; try { h = hashWith(use, canonicalPayload(e)); }
    catch (err) { hashFailures.push({ idx: e.idx ?? i, reason: "non_canonicalisable:" + err.message }); return; }
    if (h !== e.self_hash) hashFailures.push({ idx: e.idx ?? i, reason: "hash_mismatch" });
  });
  entries.forEach((e, i) => {
    const expected = i > 0 ? entries[i - 1].self_hash : GENESIS_PREV;
    if (e.prev_hash !== expected) linkFailures.push({ idx: e.idx ?? i, expected_prev: expected, actual_prev: e.prev_hash });
  });
  let idxOk = true;
  entries.forEach((e, i) => { if (e.idx !== i) { idxOk = false; errors.push({ line: i, error: `idx_mismatch: expected ${i}, got ${e.idx}` }); } });
  // zero entries = nothing verified = FAIL (2026-09-11: all four verifiers said PASS on an empty file)
  if (entries.length === 0) errors.push({ line: 0, error: "empty_ledger: zero entries, nothing to verify" });
  // signed chain tip: `tip` is the parsed document (or null); the CLI loads <ledger>.tip.json when present
  let tipCheck = null;
  if (tip !== null && !trustedPubkey) {
    // a tip is there but no trusted key: NOT checked; the verdict is the bare chain's, FAIL if required
    tipCheck = { ok: false, checked: false, error: "tip_untrusted: a signed tip is present but no trusted log key was given (--trusted-pubkey); the tail limit applies in full" };
    if (requireTip) errors.push({ line: entries.length, error: tipCheck.error });
  } else if (tip !== null) {
    const last = entries.length ? String(entries[entries.length - 1].self_hash ?? "") : "0".repeat(64);
    const first = entries.length ? String(entries[0].self_hash ?? "") : "0".repeat(64);
    tipCheck = { ...checkTip(entries.length, last, tip, trustedPubkey, tipNotBefore, first, expectLedgerId), checked: true };
    if (!tipCheck.ok) errors.push({ line: entries.length, error: tipCheck.error });
  } else if (requireTip) errors.push({ line: entries.length, error: "tip_missing: a signed chain tip is required and none was found" });
  const chainIntegrity = hashFailures.length === 0 && linkFailures.length === 0 && idxOk && errors.length === 0;

  let signatures = null;
  if (entries.some((e) => e.signature)) {
    const failures = []; let verified = 0; const signers = new Set();
    entries.forEach((e, i) => { const r = verifySig(e, pubkey); if (r.ok) { verified++; signers.add(e.signer); } else failures.push({ idx: e.idx ?? i, reason: r.reason }); });
    signatures = { all_verified: failures.length === 0, verified, failures, signers: [...signers] };
  }
  const receiptPayload = Buffer.from(canon({ algorithm: use, chain_integrity: chainIntegrity, entries: entries.length,
    hash_failures_idx: hashFailures.map((f) => f.idx), link_failures_idx: linkFailures.map((f) => f.idx),
    verdict: chainIntegrity ? "PASS" : "FAIL" }), "utf-8");
  return {
    verdict: chainIntegrity ? "PASS" : "FAIL", chain_integrity: chainIntegrity, algorithm: use,
    entries: entries.length, hash_failures_idx: hashFailures.map((f) => f.idx), link_failures_idx: linkFailures.map((f) => f.idx),
    errors, signatures, tip: tipCheck, verifier: "cvverify.mjs (independent, Node stdlib)",
    independent_receipt_sha256: createHash("sha256").update(receiptPayload).digest("hex"), // this impl's own fingerprint, NOT the reference receipt
  };
}

export function conformance(dir) {
  let conformant = true; const results = [];
  for (const f of readdirSync(dir).filter((x) => x.endsWith(".expected.json")).sort()) {
    const exp = JSON.parse(readFileSync(join(dir, f), "utf-8"));
    const got = verifyLedger(readFileSync(join(dir, exp.input), "utf-8"));
    const keys = ["verdict", "chain_integrity", "algorithm", "entries", "hash_failures_idx", "link_failures_idx"];
    const n = exp.normative;
    const ok = keys.every((k) => JSON.stringify(got[k]) === JSON.stringify(n[k]));
    if (!ok) conformant = false;
    results.push({ vector: exp.input, conform: ok, ...(ok ? {} : { expected: n, got }) });
  }
  return { conformant, vectors: results.length, results };
}

function main(argv) {
if (argv[0] === "--conformance") {
  const r = conformance(argv[1]);
  console.log(JSON.stringify(r, null, 1));
  process.exit(r.conformant ? 0 : 1);
} else if (argv[0]) {
  const algo = argv.includes("--algo") ? argv[argv.indexOf("--algo") + 1] : null;
  const pubkey = argv.includes("--pubkey") ? argv[argv.indexOf("--pubkey") + 1] : null;
  const trustedPubkey = argv.includes("--trusted-pubkey") ? argv[argv.indexOf("--trusted-pubkey") + 1] : null;
  const requireTip = argv.includes("--require-tip");
  const tipNotBefore = argv.includes("--tip-not-before") ? argv[argv.indexOf("--tip-not-before") + 1] : null;
  const expectLedgerId = argv.includes("--expect-ledger-id") ? argv[argv.indexOf("--expect-ledger-id") + 1] : null;
  let text;
  try { text = readFileSync(argv[0], "utf-8"); }
  catch (e) { console.log(JSON.stringify({ verdict: "FILE_ERROR", error: e.code || e.message }, null, 1)); process.exit(2); }
  // tip: --tip <file>, else <ledger>.tip.json if present; an unreadable/malformed tip is a failure, never silence
  let tip = null;
  const tipPath = argv.includes("--tip") ? argv[argv.indexOf("--tip") + 1] : (existsSync(argv[0] + ".tip.json") ? argv[0] + ".tip.json" : null);
  if (tipPath !== null) {
    try { tip = JSON.parse(readFileSync(tipPath, "utf-8")); if (!tip || typeof tip !== "object") throw new Error("not an object"); }
    catch (e) { tip = { kind: "unreadable:" + (e.code || e.message) }; }
  }
  const r = verifyLedger(text, { algo, pubkey, tip, trustedPubkey, requireTip, tipNotBefore, expectLedgerId });
  console.log(JSON.stringify(r, null, 1));
  process.exit(r.verdict === "PASS" ? 0 : 1);
} else {
  console.error("usage: node cvverify.mjs <ledger.jsonl> [--algo A] [--pubkey hex] [--tip f] [--trusted-pubkey hex] [--require-tip] [--tip-not-before iso] [--expect-ledger-id hex] | --conformance <vectors_dir>");
  process.exit(2);
}
}

// run the CLI only when executed directly, never on import (library discipline)
if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) main(process.argv.slice(2));
