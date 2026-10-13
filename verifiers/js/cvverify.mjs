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
import { readFileSync, readdirSync, existsSync, fstatSync, writeSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const GENESIS_PREV = "0".repeat(64);
const ALGOS = ["sha256", "sha3_256"];
const ATTEST = new Set(["self_hash", "signature", "signer", "signature_pq", "signer_pq", "tsa_token"]); // 0.12.0: ML-DSA-65 companion fields; 0.20.2: tsa_token (SPEC §3)
// SPEC_EVIDENCE_FORMAT §2.1 (2026-10-10): the CLOSED entry schema (core + optional fields of §2), as verifier.py ENTRY_KEYS. A
// top-level key outside it is the named failure `unknown_field:<keys>` in `schema_failures`, never a silent PASS (measured
// 2026-10-11 on this verifier: an extra top-level key with self_hash recomputed over it was PASS with no trace). `data` stays free (§4).
export const ENTRY_KEYS = new Set(["idx", "ts", "data", "prev_hash", "self_hash", "signature", "signer", "tsa_token", "signature_pq", "signer_pq"]);
// the entry's top-level keys outside ENTRY_KEYS, sorted by code point (Python sorted()) — a LIST: the empty key "" is unknown too
// (the differential oracle caught the first version, which tested the joined string for truth and let `""` through silently)
export function unknownFields(entry) { return Object.keys(entry).filter((k) => !ENTRY_KEYS.has(k)).sort(cmp); }
const unknownReason = (u) => "unknown_field:" + [...u.join(",")].slice(0, 120).join("");   // cut to 120 code points like the reference

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
// strict decoding with b64Strict and HEX64 (defined below), as Python's signer._b64_strict and Java's b64Strict (audit V1 #12, 30/09/2026):
// Node's Buffer.from(s, "base64") skips junk characters and takes the URL alphabet and non-canonical padding bits
function verifySig(entry, expectedPubHex) {
  const { signature, signer, self_hash } = entry;
  if (!signature || !signer || !self_hash) return { ok: false, reason: "missing signature/signer/self_hash" };
  if (expectedPubHex && signer !== expectedPubHex) return { ok: false, reason: "signer_mismatch" };
  const rawSig = b64Strict(signature, 64);
  if (rawSig === null || typeof signer !== "string" || !HEX64.test(signer)) return { ok: false, reason: "malformed_signature_field" };
  try {
    const key = createPublicKey({ key: Buffer.concat([SPKI, Buffer.from(signer, "hex")]), format: "der", type: "spki" });
    const ok = edVerify(null, Buffer.from(self_hash, "utf-8"), key, rawSig);
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
// The ONE timestamp profile of the three checkers, validated by HAND (review of 15/09/2026: Date.parse
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
  // "PASS but untrusted" an automation reads as exit 0 — council 15/09)
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
  if (notBefore) {   // instants, not strings (council 15/09): 'Z' / '+00:00' / other offsets of the same moment agree
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

// A float LEXEME outside strings (a digit followed by ".", "e" or "E"), found by ONE linear scan that honours string escapes.
// It replaced a regex skip of strings (`"(?:[^"\\]|\\.)*"`) whose failed matches made an unterminated line of escaped
// quotes quadratic: 200 000 `\"` took 72 s (NEMESIS B2 12/10/2026). Inside an unterminated string nothing is a float: the
// line fails in JSON.parse.
export function hasFloatLexeme(t) {
  let inStr = false, esc = false;
  for (let i = 0; i < t.length; i++) {
    const c = t.charCodeAt(i);
    if (inStr) { if (esc) esc = false; else if (c === 92) esc = true; else if (c === 34) inStr = false; continue; }
    if (c === 34) { inStr = true; continue; }
    if (c >= 48 && c <= 57) { const d = t.charCodeAt(i + 1); if (d === 46 || d === 101 || d === 69) return true; }
  }
  return false;
}

export function verifyLedger(text, { algo = null, pubkey = null, tip = null, trustedPubkey = null, requireTip = false, tipNotBefore = null, expectLedgerId = null } = {}) {
  const entries = [], errors = [];
  text.split("\n").forEach((ln, i) => {
    if (!ln.replace(/[ \t\r]/g, "")) return;   // blank = ASCII space/tab/CR only (trim() took Unicode spaces) — r5
    let v;
    try {
      const d = jsonNestingDepth(ln); if (d > MAX_JSON_DEPTH) throw new Error(`json_too_deep: nesting ${d} exceeds ${MAX_JSON_DEPTH}`);
      if (hasLoneSurrogate(ln)) throw new Error("lone_surrogate");
      if (hasDuplicateKeys(ln)) throw new Error("duplicate_key");
      // a float LEXEME outside strings is out of profile even when its value is whole: JSON.parse reads 1.0 / 1e0 as the
      // integer 1, so a self_hash computed over 1 was PASS here alone (NEMESIS 12/10/2026, found on real files: idx 0.0, 1e0)
      if (hasFloatLexeme(ln)) throw new Error("float_forbidden");
      v = JSON.parse(ln);
      canon(v);   // |int| > 2^53-1 refused HERE, as a named line error (it used to throw later, uncaught: no receipt)
    } catch (e) { errors.push({ line: i, error: "json_decode:" + e.message }); return; }
    if (v && typeof v === "object" && !Array.isArray(v)) entries.push(v);
    else errors.push({ line: i, error: "not_a_json_object" });
  });
  if (algo !== null && !ALGOS.includes(algo)) throw new Error(`unsupported_algo:${algo}`);   // as hash_with in verifier.py
  const use = algo || detectAlgo(entries) || "sha256";
  // SPEC §2.1: closed entry schema — same shape and reason text as the reference's schema_failures
  const schemaFailures = [];
  entries.forEach((e, i) => { const u = unknownFields(e); if (u.length) schemaFailures.push({ idx: e.idx ?? i, reason: unknownReason(u) }); });
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
  entries.forEach((e, i) => { if (e.idx !== i) { idxOk = false; errors.push({ line: i, error: `idx_mismatch: expected ${i}, got ${Object.prototype.hasOwnProperty.call(e, "idx") ? JSON.stringify(e.idx) : "(missing)"}` }); } });
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
  const chainIntegrity = hashFailures.length === 0 && linkFailures.length === 0 && idxOk && errors.length === 0 && schemaFailures.length === 0;   // SPEC §2.1

  let signatures = null;
  if (entries.some((e) => e.signature) || pubkey) {
    const failures = []; let verified = 0; const signers = new Set();
    entries.forEach((e, i) => { const r = verifySig(e, pubkey); if (r.ok) { verified++; signers.add(e.signer); } else failures.push({ idx: e.idx ?? i, reason: r.reason }); });
    signatures = { all_verified: failures.length === 0 && entries.length > 0, verified, failures, signers: [...signers] };
  }
  // with --pubkey the caller PINNED the signer: a signature layer that does not verify fails the run, as in Java -pubkey
  // (audit V1 A16, 30/09/2026: before, a broken signature gave all_verified false but verdict PASS, exit 0)
  const pinnedSigFail = Boolean(pubkey) && !(signatures && signatures.all_verified);
  if (pinnedSigFail) errors.push({ error: "signatures_failed: the pinned signature layer does not verify" });
  const verdictPass = chainIntegrity && !pinnedSigFail;
  const receiptPayload = Buffer.from(canon({ algorithm: use, chain_integrity: chainIntegrity, entries: entries.length,
    hash_failures_idx: hashFailures.map((f) => f.idx), link_failures_idx: linkFailures.map((f) => f.idx),
    verdict: verdictPass ? "PASS" : "FAIL" }), "utf-8");
  return {
    verdict: verdictPass ? "PASS" : "FAIL", chain_integrity: chainIntegrity, algorithm: use,
    entries: entries.length, hash_failures_idx: hashFailures.map((f) => f.idx), link_failures_idx: linkFailures.map((f) => f.idx),
    errors, schema_failures: schemaFailures, signatures, tip: tipCheck, verifier: "cvverify.mjs (independent, Node stdlib)",
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

// 0.20.3: the receipt is written with process.stdout.write and the exit code is set only in its callback, after the bytes
// were taken: on an error (ENOSPC on a full disk, EPIPE when the reader is gone) the code is 74 (sysexits EX_IOERR) and
// stderr gets one line, whatever the verdict. console.log drops that error, and the exit code was the verdict's (0/1/2).
// Never process.exit() here: exit() right after a write to a PIPE dropped every byte past 64 KiB (NEMESIS 12/10/2026); the
// process ends when stdout has drained. With stdout closed (`>&-`) Node reopens fd 1 on /dev/null: that write succeeds.
const EX_IOERR = 74;
function emitReceipt(obj, code) {
  let failed = false;
  const fail = (e) => {
    if (failed) return;
    failed = true;
    process.exitCode = EX_IOERR;
    // stderr full or closed too: its error arrives as an 'error' event (an uncaught exception, exit 1, without a listener)
    process.stderr.on("error", () => { process.exitCode = EX_IOERR; });
    try { process.stderr.write(`receipt not written: ${(e && (e.code || e.message)) || e}\n`); } catch { /* the code says it */ }
  };
  const text = JSON.stringify(obj, null, 1) + "\n";
  // a REGULAR file: Node's stream does ONE writeSync there and drops the rest after a short write (`ulimit -f`: the
  // verdict's code with the receipt cut, measured 13/10/2026 on 0.20.3's first commit); written here, every byte, in a
  // loop, and EFBIG / ENOSPC is 74 (the writer of cra-evidence 0.5.1)
  let regular = false;
  try { regular = fstatSync(1).isFile(); } catch { regular = false; }
  if (regular) {
    const buf = Buffer.from(text, "utf8");
    try {
      for (let off = 0; off < buf.length;) {
        const n = writeSync(1, buf, off, buf.length - off);
        if (n <= 0) throw new Error("short write");
        off += n;
      }
      process.exitCode = code;
    } catch (e) { fail(e); }
    return;
  }
  process.exitCode = EX_IOERR;   // until the callback says every byte was taken
  process.stdout.on("error", fail);
  try {
    process.stdout.write(text, (err) => { if (err) fail(err); else if (!failed) process.exitCode = code; });
  } catch (e) { fail(e); }
}

function main(argv) {
if (argv[0] === "--conformance") {
  const r = conformance(argv[1]);
  emitReceipt(r, r.conformant ? 0 : 1);
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
  if (algo !== null && !ALGOS.includes(algo)) usage();   // only the two profiles (argparse choices in the reference): "foo" was hashed as SHA-256 and reported as "algorithm": "foo"
  const pubkey = opts["--pubkey"] ?? null;
  const trustedPubkey = opts["--trusted-pubkey"] ?? null;
  const requireTip = Boolean(opts["--require-tip"]);
  const tipNotBefore = opts["--tip-not-before"] ?? null;
  const expectLedgerId = opts["--expect-ledger-id"] ?? null;
  let text;
  let bytes;
  try { bytes = readFileSync(argv[0]); }
  catch (e) { emitReceipt({ verdict: "FILE_ERROR", error: e.code || e.message }, 2); return; }
  try { text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes); }   // strict: one invalid byte is a broken ledger (FAIL), never U+FFFD; ignoreBOM: a leading BOM stays in the text and is refused like in the five others (it was stripped: PASS, NEMESIS 12/10/2026)
  catch (e) { emitReceipt({ verdict: "FAIL", error: "ledger is not valid UTF-8" }, 1); return; }
  // tip: --tip <file>, else <ledger>.tip.json if present; an unreadable/malformed tip is a failure, never silence
  let tip = null;
  const tipPath = opts["--tip"] !== undefined ? opts["--tip"] : (existsSync(argv[0] + ".tip.json") ? argv[0] + ".tip.json" : null);
  if (tipPath !== null) {
    try {   // the tip is a SIGNED document: the same strict profile as the entries (r5: Java was strict, JS lax)
      const raw = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(readFileSync(tipPath));
      const d = jsonNestingDepth(raw); if (d > MAX_JSON_DEPTH) throw new Error("json_too_deep");
      if (hasLoneSurrogate(raw)) throw new Error("lone_surrogate");
      if (hasDuplicateKeys(raw)) throw new Error("duplicate_key");
      if (/[0-9][.eE]/.test(raw.replace(/"(?:[^"\\]|\\.)*"/g, '""'))) throw new Error("float_forbidden");
      tip = JSON.parse(raw); if (!tip || typeof tip !== "object" || Array.isArray(tip)) throw new Error("not an object");
    }
    catch (e) { tip = { kind: "unreadable:" + (e.code || e.message) }; }
  }
  const r = verifyLedger(text, { algo, pubkey, tip, trustedPubkey, requireTip, tipNotBefore, expectLedgerId });
  emitReceipt(r, r.verdict === "PASS" ? 0 : 1);   // exit code after the write is drained (see emitReceipt)
} else {
  console.error("usage: node cvverify.mjs <ledger.jsonl> [--algo A] [--pubkey hex] [--tip f] [--trusted-pubkey hex] [--require-tip] [--tip-not-before iso] [--expect-ledger-id hex] | --conformance <vectors_dir>");
  process.exit(2);
}
}

// run the CLI only when executed directly, never on import (library discipline)
if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) main(process.argv.slice(2));
