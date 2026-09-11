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
import { readFileSync, readdirSync } from "node:fs";
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

export function verifyLedger(text, { algo = null, pubkey = null } = {}) {
  const entries = [], errors = [];
  text.split("\n").forEach((ln, i) => {
    if (!ln.trim()) return;
    let v;
    try { if (hasDuplicateKeys(ln)) throw new Error("duplicate_key"); v = JSON.parse(ln); } catch (e) { errors.push({ line: i, error: "json_decode:" + e.message }); return; }
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
    errors, signatures, verifier: "cvverify.mjs (independent, Node stdlib)",
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
  let text;
  try { text = readFileSync(argv[0], "utf-8"); }
  catch (e) { console.log(JSON.stringify({ verdict: "FILE_ERROR", error: e.code || e.message }, null, 1)); process.exit(2); }
  const r = verifyLedger(text, { algo, pubkey });
  console.log(JSON.stringify(r, null, 1));
  process.exit(r.verdict === "PASS" ? 0 : 1);
} else {
  console.error("usage: node cvverify.mjs <ledger.jsonl> [--algo A] [--pubkey hex] | --conformance <vectors_dir>");
  process.exit(2);
}
}

// run the CLI only when executed directly, never on import (library discipline)
if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) main(process.argv.slice(2));
