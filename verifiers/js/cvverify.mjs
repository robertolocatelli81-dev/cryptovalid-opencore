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
const ATTEST = new Set(["self_hash", "signature", "signer", "signature_pq", "signer_pq"]); // 0.12.0: ML-DSA-65 companion fields

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
  // Object.fromEntries keeps an own "__proto__" key (d[k] = … would invoke the setter and silently DROP it: an entry with
  // that key added and its self_hash untouched verified PASS here alone — found on cra-evidence 0.3.0, 20/09/2026)
  const d = Object.fromEntries(Object.entries(entry).filter(([k]) => !ATTEST.has(k)));
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
const HEX128 = /^[0-9a-f]{128}$/, HEX6618 = /^[0-9a-f]{6618}$/;   // Ed25519 / ML-DSA-65 signatures, lowercase, no whitespace
const b64Strict = (s, n) => {   // strict standard base64 of exactly n bytes (canonical re-encoding), else null
  if (typeof s !== "string" || s.length !== Math.ceil(n / 3) * 4 || !/^[A-Za-z0-9+/]*={0,2}$/.test(s)) return null;
  const raw = Buffer.from(s, "base64"); return raw.length === n && raw.toString("base64") === s ? raw : null;
};
// The ONE timestamp profile of the three checkers, validated by HAND (review with Fable 5.1, 15/09/2026: Date.parse
// silently rolled 2026-02-30 over to March, accepted hour 24 and year 0000; Date.UTC maps years 1-99 to 1900+y).
// Returns the instant as the integer pair [epoch seconds, nanoseconds] — compared as a pair in the three checkers
// (fraction precision differs in the three standard libraries) — or null when outside the profile.
export function parseInstant(s) {
  if (typeof s !== "string") return null;
  const m = /^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.([0-9]{1,9}))?(Z|[+-][0-9]{2}:[0-9]{2})$/.exec(s);
  if (!m) return null;
  const [y, mo, d, h, mi, sec] = m.slice(1, 7).map(Number);
  if (y < 1 || y > 9999 || mo < 1 || mo > 12 || h > 23 || mi > 59 || sec > 59) return null;
  const leap = (y % 4 === 0 && y % 100 !== 0) || y % 400 === 0;
  const dim = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][mo - 1];
  if (d < 1 || d > dim) return null;
  let offSec = 0;
  if (m[8] !== "Z") { const oh = Number(m[8].slice(1, 3)), om = Number(m[8].slice(4, 6)); if (oh > 23 || om > 59) return null; offSec = (oh * 3600 + om * 60) * (m[8][0] === "-" ? -1 : 1); }
  const dt = new Date(0); dt.setUTCFullYear(y, mo - 1, d); dt.setUTCHours(h, mi, sec, 0);   // year-safe, no Date.UTC quirk
  const nanos = Number(((m[7] || "0") + "000000000").slice(0, 9));
  return [Math.floor(dt.getTime() / 1000) - offSec, nanos];
}
export function instantBefore(a, b) { return a[0] < b[0] || (a[0] === b[0] && a[1] < b[1]); }
export function checkTip(entriesCount, lastSelfHash, tip, trustedPubkeyHex = null, notBefore = null, firstSelfHash = null, expectLedgerId = null) {
  if (!tip || typeof tip !== "object" || Array.isArray(tip) || tip.kind !== TIP_KIND) return { ok: false, pq_protected: false, error: "tip_invalid: not a cryptovalid_tip/1 document" };
  for (const k of ["entries", "ledger_id", "tip_sha256", "ts", "signature_hex"]) if (!(k in tip)) return { ok: false, pq_protected: false, error: `tip_invalid: tip missing field ${k}` };
  // strict types, same as Go's decoder: entries a non-negative integer, the rest strings
  if (typeof tip.entries !== "number" || !Number.isInteger(tip.entries) || tip.entries < 0) return { ok: false, pq_protected: false, error: "tip_invalid: tip entries must be a non-negative integer" };
  if (!["ledger_id", "tip_sha256", "ts", "signature_hex"].every((k) => typeof tip[k] === "string")) return { ok: false, pq_protected: false, error: "tip_invalid: tip fields must be strings" };
  // ONE timestamp profile in the three checkers: RFC 3339 with seconds and a zone (Z or ±hh:mm)
  if (!HEX64.test(tip.ledger_id) || !HEX64.test(tip.tip_sha256) || parseInstant(tip.ts) === null) return { ok: false, pq_protected: false, error: "tip_invalid: not a cryptovalid_tip/1 document" };
  if (!HEX128.test(tip.signature_hex)) return { ok: false, pq_protected: false, error: "tip_invalid: signature_hex must be 128 lowercase hex characters" };
  // optional hybrid fields: when PRESENT they must be well-formed whoever checks them (same rule in Python/Go)
  if ("signature_pq_hex" in tip || "log_pq_pubkey_b64" in tip) {
    if (typeof tip.signature_pq_hex !== "string" || !HEX6618.test(tip.signature_pq_hex) || b64Strict(tip.log_pq_pubkey_b64, 1952) === null)
      return { ok: false, pq_protected: false, error: "tip_invalid: malformed post-quantum fields (signature_pq_hex 6618 lowercase hex, log_pq_pubkey_b64 strict base64 of 1952 bytes)" };
  }
  // the key inside the tip proves nothing: without the trusted log key there is NO verification (never a
  // "PASS but untrusted" an automation reads as exit 0 — council 15/09, Gemini)
  if (!trustedPubkeyHex) return { ok: false, pq_protected: false, trusted: false, error: "tip_untrusted: no trusted log key given (--trusted-pubkey); the key inside the tip cannot be trusted" };
  if (tip.log_pubkey_hex && tip.log_pubkey_hex !== trustedPubkeyHex) return { ok: false, pq_protected: false, error: "tip_invalid: tip log key differs from the trusted log key" };   // "" = absent, as in Python/Go
  let sigOk = false;
  try {
    const key = createPublicKey({ key: Buffer.concat([SPKI, Buffer.from(trustedPubkeyHex, "hex")]), format: "der", type: "spki" });
    sigOk = edVerify(null, tipPayload(Number(tip.entries), tip.ledger_id, tip.tip_sha256, tip.ts), key, Buffer.from(tip.signature_hex, "hex"));
  } catch (e) { sigOk = false; }
  if (!sigOk) return { ok: false, pq_protected: false, error: "tip_invalid: tip signature invalid" };
  const n = Number(tip.entries), trusted = Boolean(trustedPubkeyHex);
  if (expectLedgerId && tip.ledger_id !== expectLedgerId) return { ok: false, pq_protected: false, trusted, error: "ledger_id_mismatch: the tip belongs to a different ledger than the one you expect" };
  if (firstSelfHash !== null && entriesCount > 0 && tip.ledger_id !== firstSelfHash) return { ok: false, pq_protected: false, trusted, error: "tip_of_another_ledger: the tip's ledger_id is not this file's first self_hash" };
  // ROLLBACK (declared): an older genuine tip restored after a truncation passes; notBefore refuses older tips
  if (notBefore) {   // instants, not strings (council 15/09, Opus): 'Z' / '+00:00' / other offsets of the same moment agree
    const a = parseInstant(tip.ts), b = parseInstant(notBefore);
    if (b === null) return { ok: false, pq_protected: false, trusted, error: "bad_not_before: --tip-not-before must be YYYY-MM-DDThh:mm:ss[.f](Z|±hh:mm)" };   // the verifier's error, not the tip's
    if (instantBefore(a, b)) return { ok: false, pq_protected: false, trusted, error: `tip_rolled_back: the tip is dated ${tip.ts}, before the required ${notBefore}` };
  }
  if (entriesCount < n) return { ok: false, pq_protected: false, trusted, error: `tail_truncated: file has ${entriesCount} entries, the signed tip commits to ${n}` };
  if (entriesCount > n) return { ok: false, pq_protected: false, trusted, error: `unsealed_tail: file has ${entriesCount} entries, the signed tip commits to ${n} (appended after the last signed head)` };
  if (lastSelfHash !== tip.tip_sha256) return { ok: false, pq_protected: false, trusted, error: "tail_rewritten: same entry count but the last self_hash differs from the signed tip" };
  // hybrid tip (0.12.0): this verifier has no ML-DSA-65 (Node 22 / OpenSSL 3.5): the post-quantum layer is NOT
  // checked here — null when present (unverified, declared), false when absent. Python and Go verify it.
  const pq_protected = typeof tip.signature_pq_hex === "string" && tip.signature_pq_hex ? null : false;
  return { ok: true, trusted, entries: n, tip_sha256: tip.tip_sha256, ts: tip.ts, pq_protected,
           pq_note: pq_protected === null ? "ML-DSA-65 signature present but NOT verified by this verifier (no ML-DSA in Node): use verifier.py / cvverify (Go) with --trusted-pq-pubkey" : "Ed25519-only tip (not quantum-resistant)" };
}

export function verifyLedger(text, { algo = null, pubkey = null, tip = null, trustedPubkey = null, requireTip = false, tipNotBefore = null, expectLedgerId = null } = {}) {
  const entries = [], errors = [];
  text.split("\n").forEach((ln, i) => {
    if (!ln.replace(/[ \t\r]/g, "")) return;   // blank = ASCII space/tab/CR only (trim() took Unicode spaces) — r5
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
  // one grammar (21/09/2026, found on cra-evidence: an unknown flag, a value flag without a value or with "", a second positional
  // were silently taken as the ledger path and the constraint the operator asked for vanished): usage error, exit 2, no verdict
  const VALUE_FLAGS = new Set(["--algo", "--pubkey", "--tip", "--trusted-pubkey", "--tip-not-before", "--expect-ledger-id"]);
  const usage = () => { console.error("usage: node cvverify.mjs <ledger.jsonl> [--algo A] [--pubkey hex] [--tip f] [--trusted-pubkey hex] [--require-tip] [--tip-not-before iso] [--expect-ledger-id hex] | --conformance <vectors_dir>"); process.exit(2); };
  const opts = {};
  for (let i = 1; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--require-tip") { opts[a] = true; continue; }
    if (VALUE_FLAGS.has(a)) { const v = argv[i + 1]; if (v === undefined || v === "" || v.startsWith("-")) usage(); opts[a] = v; i++; continue; }
    usage();   // unknown flag, --flag=value form, or a second positional
  }
  if (argv[0].startsWith("-")) usage();
  const algo = opts["--algo"] ?? null;
  const pubkey = opts["--pubkey"] ?? null;
  const trustedPubkey = opts["--trusted-pubkey"] ?? null;
  const requireTip = Boolean(opts["--require-tip"]);
  const tipNotBefore = opts["--tip-not-before"] ?? null;
  const expectLedgerId = opts["--expect-ledger-id"] ?? null;
  let text;
  let bytes;
  try { bytes = readFileSync(argv[0]); }
  catch (e) { console.log(JSON.stringify({ verdict: "FILE_ERROR", error: e.code || e.message }, null, 1)); process.exit(2); }
  try { text = new TextDecoder("utf-8", { fatal: true }).decode(bytes); }   // strict: one invalid byte is a broken ledger (FAIL), never U+FFFD
  catch (e) { console.log(JSON.stringify({ verdict: "FAIL", error: "ledger is not valid UTF-8" }, null, 1)); process.exit(1); }
  // tip: --tip <file>, else <ledger>.tip.json if present; an unreadable/malformed tip is a failure, never silence
  let tip = null;
  const tipPath = opts["--tip"] !== undefined ? opts["--tip"] : (existsSync(argv[0] + ".tip.json") ? argv[0] + ".tip.json" : null);
  if (tipPath !== null) {
    try {   // the tip is a SIGNED document: the same strict profile as the entries (r5: Java was strict, JS lax)
      const raw = new TextDecoder("utf-8", { fatal: true }).decode(readFileSync(tipPath));
      const d = jsonNestingDepth(raw); if (d > MAX_JSON_DEPTH) throw new Error("json_too_deep");
      if (hasLoneSurrogate(raw)) throw new Error("lone_surrogate");
      if (hasDuplicateKeys(raw)) throw new Error("duplicate_key");
      if (/[0-9][.eE]/.test(raw.replace(/"(?:[^"\\]|\\.)*"/g, '""'))) throw new Error("float_forbidden");
      tip = JSON.parse(raw); if (!tip || typeof tip !== "object" || Array.isArray(tip)) throw new Error("not an object");
    }
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
