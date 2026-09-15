// Professional test suite for the independent CryptoValid verifier.
// Runs the normative conformance vectors, positive+negative controls, an Ed25519
// signature round-trip, AND cross-checks every vector against the REFERENCE Python
// verifier (verifier.py at the repo root) as an independent oracle — so a bug that makes us
// wrongly agree with ourselves is caught by disagreement with the reference.
import { verifyLedger, conformance, jsonNestingDepth, hasLoneSurrogate, MAX_JSON_DEPTH, checkTip, tipPayload, parseInstant } from "./cvverify.mjs";
import { readFileSync, writeFileSync, mkdtempSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { createHash, generateKeyPairSync, sign as edSign } from "node:crypto";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { tmpdir } from "node:os";

const HERE = dirname(fileURLToPath(import.meta.url));
const VDIR = join(HERE, "..", "..", "spec", "vectors");
const REF = join(HERE, "..", "..", "verifier.py");
let pass = 0, fail = 0;
const ok = (name, cond, extra = "") => { if (cond) pass++; else { fail++; console.log("FAIL", name, extra); } };

// 1) conformance against the normative vectors
const conf = conformance(VDIR);
ok("conformance: all normative vectors", conf.conformant, JSON.stringify(conf.results.filter((r) => !r.conform)));

// 2) cross-oracle: same verdict/chain_integrity as the reference Python verifier
for (const f of ["valid_sha256.jsonl", "valid_sha3_256.jsonl", "bad_idx.jsonl", "broken_link.jsonl", "tampered_content.jsonl", "canonical_unicode.jsonl"]) {
  const mine = verifyLedger(readFileSync(join(VDIR, f), "utf-8"));
  let ref;
  try { ref = JSON.parse(execFileSync("python3", [REF, join(VDIR, f)], { encoding: "utf-8" })); }
  catch (e) { ref = JSON.parse(e.stdout || "{}"); }   // verifier exits nonzero on FAIL
  ok(`oracle verdict ${f}`, mine.verdict === ref.verdict, `js=${mine.verdict} py=${ref.verdict}`);
  ok(`oracle chain ${f}`, mine.chain_integrity === ref.chain_integrity);
  ok(`oracle algo ${f}`, mine.algorithm === ref.algorithm_used, `js=${mine.algorithm} py=${ref.algorithm_used}`);
  ok(`oracle entries ${f}`, mine.entries === ref.entries_count, `js=${mine.entries} py=${ref.entries_count}`);
}

// 3) positive + negative controls (the bench must be able to FAIL)
const valid = readFileSync(join(VDIR, "valid_sha256.jsonl"), "utf-8");
ok("positive: valid ledger PASS", verifyLedger(valid).verdict === "PASS");
const lines = valid.trim().split("\n").map((l) => JSON.parse(l));
const tampered = [...lines]; tampered[1] = { ...tampered[1], data: { a: 999 } };
ok("negative: tampered content FAIL", verifyLedger(tampered.map((e) => JSON.stringify(e)).join("\n")).verdict === "FAIL");
const relinked = [...lines]; relinked[1] = { ...relinked[1], prev_hash: "0".repeat(64) };
ok("negative: broken link FAIL", verifyLedger(relinked.map((e) => JSON.stringify(e)).join("\n")).verdict === "FAIL");
const reidx = [...lines]; reidx[1] = { ...reidx[1], idx: 7 };
ok("negative: bad idx FAIL", verifyLedger(reidx.map((e) => JSON.stringify(e)).join("\n")).verdict === "FAIL");
ok("negative: wrong algo FAIL", verifyLedger(valid, { algo: "sha3_256" }).verdict === "FAIL");

// 4) Ed25519 signature round-trip (build a signed entry the way the reference does)
const { publicKey, privateKey } = generateKeyPairSync("ed25519");
const pubRaw = publicKey.export({ type: "spki", format: "der" }).subarray(-32);
const signerHex = Buffer.from(pubRaw).toString("hex");
function canonHash(entry) {
  const d = {}; for (const k of Object.keys(entry).sort()) if (!["self_hash", "signature", "signer", "signature_pq", "signer_pq"].includes(k)) d[k] = entry[k];
  // reuse the module's canonical by re-verifying a whole ledger below instead of duplicating here
  return d;
}
const base = { idx: 0, ts: "2026-09-02T00:00:00Z", data: { event: "signed" }, prev_hash: "0".repeat(64) };
// compute self_hash via the module itself: build unsigned, verify to learn the hash it expects
const unsignedLine = JSON.stringify(base);
const probe = verifyLedger(JSON.stringify({ ...base, self_hash: "x" }));   // FAIL, but tells us nothing; compute directly:
const canonical = JSON.stringify(Object.fromEntries(Object.keys(base).sort().map((k) => [k, base[k]])));
const selfHash = createHash("sha256").update(Buffer.from(
  "{" + Object.keys(base).sort().map((k) => JSON.stringify(k) + ":" + JSON.stringify(base[k])).join(",") + "}", "utf-8")).digest("hex");
const sig = edSign(null, Buffer.from(selfHash, "utf-8"), privateKey).toString("base64");
const signed = { ...base, self_hash: selfHash, signature: sig, signer: signerHex };
const rSig = verifyLedger(JSON.stringify(signed));
ok("signature: valid signed ledger PASS + all_verified", rSig.verdict === "PASS" && rSig.signatures && rSig.signatures.all_verified, JSON.stringify(rSig.signatures));
const badSig = { ...signed, signature: Buffer.from("x".repeat(64)).toString("base64") };
const rBad = verifyLedger(JSON.stringify(badSig));
ok("signature: forged signature not all_verified", rBad.signatures && !rBad.signatures.all_verified);
ok("signature: pubkey pin mismatch flagged", !verifyLedger(JSON.stringify(signed), { pubkey: "00".repeat(32) }).signatures.all_verified);

// 5) robustness: never throws on garbage
for (const g of ["", "not json\n{}", "{}\n", "null\n", "[1,2]\n"]) {
  try { const r = verifyLedger(g); ok("robust: " + JSON.stringify(g).slice(0, 14), r.verdict === "FAIL" || r.verdict === "PASS"); }
  catch (e) { ok("robust: " + JSON.stringify(g).slice(0, 14), false, e.message); }
}


// Adversarial review: duplicate JSON keys must be rejected (hash malleability)
{
  const dup = '{"idx":0,"ts":"t","data":{"evil":1},"data":{"real":1},"prev_hash":"' + "0".repeat(64) + '","self_hash":"x"}';
  ok("dup-key rejected", verifyLedger(dup).verdict === "FAIL");
}

// 6) acceptance-profile pre-scans shared with Python and Go (verifiers/go/vectors.json, 14/09/2026)
{
  const vec = JSON.parse(readFileSync(join(HERE, "..", "go", "vectors.json"), "utf-8"));
  for (const r of vec.refuse) ok(`refuse: ${r.why}`, verifyLedger(r.text).verdict === "FAIL");
  ok("depth scanner ignores brackets in strings", jsonNestingDepth('{"a":"[[[["}') === 1);
  ok("depth 600 refused", verifyLedger('{"idx":0,"d":' + "[".repeat(600) + "]".repeat(600) + "}").verdict === "FAIL" && MAX_JSON_DEPTH === 512);
  ok("malformed escape is not labelled lone_surrogate", !hasLoneSurrogate('{"k":"\\uzzzz"}') && verifyLedger('{"k":"\\uzzzz"}').verdict === "FAIL");
  ok("lone surrogate scanner", hasLoneSurrogate('{"k":"\\ud800"}') && hasLoneSurrogate('{"k":"\\udc00"}') && !hasLoneSurrogate('{"k":"\\ud83d\\ude00"}') && !hasLoneSurrogate('{"k":"\\\\ud800"}'));
  const mk = (raw) => { const e = { idx: 0, ts: "t", prev_hash: "0".repeat(64), data: JSON.parse(raw) }; const d = { ...e }; e.self_hash = createHash("sha256").update(Buffer.from(canonRef(d))).digest("hex"); return e; };
  const canonRef = (o) => execFileSync("python3", ["-c", "import json,sys; print(json.dumps(json.load(sys.stdin), sort_keys=True, separators=(',',':')), end='')"], { input: JSON.stringify(o), encoding: "utf-8" });
  ok("valid pair still PASS", verifyLedger(JSON.stringify(mk('{"k":"\\ud83d\\ude00"}'))).verdict === "PASS");
  const lone = JSON.stringify(mk('{"k":"\\ud800"}'));   // JSON.stringify keeps \ud800 as an escape
  ok("lone surrogate ledger FAIL (was PASS before 14/09)", verifyLedger(lone).verdict === "FAIL");
}

// 7) signed chain tip (15/09/2026): the tail limit moves. Positive control first: the bare chain PASSES on a
//    truncated file; with the tip and the trusted key it is a named FAIL. Cross-language: a tip signed by the
//    Python reference must verify here (same signed bytes).
{
  const canonRef = (o) => execFileSync("python3", ["-c", "import json,sys; print(json.dumps(json.load(sys.stdin), sort_keys=True, separators=(',',':')), end='')"], { input: JSON.stringify(o), encoding: "utf-8" });
  const chain = []; let prev = "0".repeat(64);
  for (let i = 0; i < 6; i++) { const e = { idx: i, ts: "t", prev_hash: prev, data: { i } }; e.self_hash = createHash("sha256").update(Buffer.from(canonRef({ ...e }))).digest("hex"); prev = e.self_hash; chain.push(e); }
  const text = (n) => chain.slice(0, n).map((e) => JSON.stringify(e)).join("\n") + "\n";
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const pkHex = publicKey.export({ type: "spki", format: "der" }).subarray(12).toString("hex");
  const sign = (entries, tip, ts, lid = chain[0].self_hash) => ({ kind: "cryptovalid_tip/1", entries, ledger_id: lid, tip_sha256: tip, ts, log_pubkey_hex: pkHex, signature_hex: edSign(null, tipPayload(entries, lid, tip, ts), privateKey).toString("hex") });
  const tip = sign(6, chain[5].self_hash, "2026-09-15T07:00:00+00:00");
  ok("tip payload bytes = Python oracle", tipPayload(3, "cd".repeat(32), "ab".repeat(32), "T").toString() === '{"entries":3,"kind":"cryptovalid_tip/1","ledger_id":"' + "cd".repeat(32) + '","tip_sha256":"' + "ab".repeat(32) + '","ts":"T"}');
  ok("tip: another ledger's tip named", verifyLedger(text(6), { tip: sign(6, chain[5].self_hash, "2026-09-15T07:00:00Z", "ef".repeat(32)), trustedPubkey: pkHex }).errors.some((e) => e.error.startsWith("tip_of_another_ledger")));
  ok("tip: expected ledger id enforced", verifyLedger(text(6), { tip, trustedPubkey: pkHex, expectLedgerId: "ef".repeat(32) }).errors.some((e) => e.error.startsWith("ledger_id_mismatch")) && verifyLedger(text(6), { tip, trustedPubkey: pkHex, expectLedgerId: chain[0].self_hash }).verdict === "PASS");
  ok("tip: intact PASS trusted", (() => { const r = verifyLedger(text(6), { tip, trustedPubkey: pkHex }); return r.verdict === "PASS" && r.tip.ok && r.tip.trusted; })());
  ok("positive control: bare chain PASSES on truncated file", verifyLedger(text(5)).verdict === "PASS");
  ok("tip: truncation named", verifyLedger(text(5), { tip, trustedPubkey: pkHex }).errors.some((e) => e.error.startsWith("tail_truncated")));
  ok("tip: unsealed append named", verifyLedger(text(6) + JSON.stringify({ ...chain[5], idx: 6, prev_hash: chain[5].self_hash }) + "\n", { tip, trustedPubkey: pkHex }).errors.some((e) => e.error.startsWith("unsealed_tail") || e.error.startsWith("hash")));
  ok("tip: rewritten tail named", verifyLedger(text(6), { tip: sign(6, "11".repeat(32), "2026-09-15T07:00:00Z"), trustedPubkey: pkHex }).errors.some((e) => e.error.startsWith("tail_rewritten")));
  ok("tip: non-hex / quoted fields refused before signing", verifyLedger(text(6), { tip: { ...tip, ts: 'a"b' }, trustedPubkey: pkHex }).errors.some((e) => e.error.startsWith("tip_invalid")));
  ok("tip: foreign key refused", verifyLedger(text(6), { tip, trustedPubkey: "22".repeat(32) }).errors.some((e) => e.error.startsWith("tip_invalid")));
  ok("tip: tampered field refused", verifyLedger(text(6), { tip: { ...tip, entries: 5 }, trustedPubkey: pkHex }).errors.some((e) => e.error.startsWith("tip_invalid")));
  ok("tip: no trusted key → tip NOT checked, chain verdict only", (() => { const r = verifyLedger(text(6), { tip }); return r.verdict === "PASS" && r.tip.checked === false && r.tip.error.startsWith("tip_untrusted"); })());
  ok("tip: no trusted key + required → FAIL (never fail-open)", verifyLedger(text(5), { tip: sign(5, chain[4].self_hash, "2026-09-15T07:00:00Z"), requireTip: true }).verdict === "FAIL");
  ok("tip: not-before compares instants (Z / +00:00 / +02:00)", ["2026-09-15T07:00:00Z", "2026-09-15T07:00:00+00:00", "2026-09-15T09:00:00+02:00", "2026-09-15T06:59:59.5Z"].every((s) => verifyLedger(text(6), { tip, trustedPubkey: pkHex, tipNotBefore: s }).verdict === "PASS") && verifyLedger(text(6), { tip, trustedPubkey: pkHex, tipNotBefore: "2026-09-15T07:00:01Z" }).verdict === "FAIL");
  ok("tip: not-before follows the same profile (date-only / naive → bad_not_before)", ["2026-09-15", "2026-09-15T07:00:00", "x"].every((s) => verifyLedger(text(6), { tip, trustedPubkey: pkHex, tipNotBefore: s }).errors.some((e) => e.error.startsWith("bad_not_before"))));
  ok("tip: ASCII digits only (Arabic-Indic / fullwidth → tip_invalid)", ["٢٠٢٦-٠٩-١٥T10:00:00Z", "２０２６-０９-１５T１０:２５:００Z"].every((ts) => verifyLedger(text(6), { tip: sign(6, chain[5].self_hash, ts), trustedPubkey: pkHex }).errors.some((e) => e.error.startsWith("tip_invalid"))));
  ok("tip: instant = integer pair, year-safe (no Date.UTC 1900+ quirk)", JSON.stringify(parseInstant("2026-09-15T10:00:00.0001Z")) === "[1789466400,100000]" && JSON.stringify(parseInstant("0050-06-15T12:00:00Z")) === "[-60574996800,0]");
  ok("tip: ordering at sub-ms / sub-µs / year<100 boundaries agrees with Python", [["2026-09-15T10:00:00.0001Z", "2026-09-15T10:00:00.0004Z", "FAIL"], ["2026-09-15T10:00:00.0000001Z", "2026-09-15T10:00:00.0000004Z", "FAIL"], ["2026-09-15T10:00:00.0000004Z", "2026-09-15T10:00:00.0000001Z", "PASS"], ["0050-06-15T12:00:00Z", "0100-01-01T00:00:00Z", "FAIL"]].every(([ts, nb, ex]) => verifyLedger(text(6), { tip: sign(6, chain[5].self_hash, ts), trustedPubkey: pkHex, tipNotBefore: nb }).verdict === ex));
  ok("tip: value-layer profile by hand (Feb 30, hour 24, year 0000, comma, 10-digit fraction, +24:00 → tip_invalid)", ["2026-02-30T10:25:00Z", "2026-09-15T24:00:00Z", "0000-01-01T00:00:00Z", "2026-09-15T10:25:00,5Z", "2026-09-15T10:25:00.1234567890Z", "2026-09-15T10:25:00+24:00", "2026-09-15T10:25:60Z"].every((ts) => verifyLedger(text(6), { tip: sign(6, chain[5].self_hash, ts), trustedPubkey: pkHex }).errors.some((e) => e.error.startsWith("tip_invalid"))) && ["2024-02-29T23:59:59Z", "2026-09-15T10:00:00.1234Z"].every((ts) => verifyLedger(text(6), { tip: sign(6, chain[5].self_hash, ts), trustedPubkey: pkHex }).verdict === "PASS"));
  ok("tip: required but missing", verifyLedger(text(6), { requireTip: true }).errors.some((e) => e.error.startsWith("tip_missing")));
  ok("tip: garbage document refused", verifyLedger(text(6), { tip: [1, 2], trustedPubkey: pkHex }).verdict === "FAIL");
  ok("tip: strict integer entries (Go agrees)", ["6", 6.5, true].every((b) => verifyLedger(text(6), { tip: { ...tip, entries: b }, trustedPubkey: pkHex }).errors.some((e) => e.error.includes("integer"))));
  ok("tip: rollback passes (declared) and is refused with tipNotBefore", verifyLedger(text(6), { tip, trustedPubkey: pkHex }).verdict === "PASS" && verifyLedger(text(6), { tip, trustedPubkey: pkHex, tipNotBefore: "2026-09-15T09:00:00+00:00" }).errors.some((e) => e.error.startsWith("tip_rolled_back")));
  // cross-language: Python signs, JS verifies (python cryptography needed)
  try {
    execFileSync("python3", ["-c", "import cryptography"]);
    const dir = mkdtempSync(join(tmpdir(), "cvtip-")); const led = join(dir, "l.jsonl"); const key = join(dir, "k");
    writeFileSync(led, text(6));
    const pk = JSON.parse(execFileSync("python3", ["-c", `import sys; sys.path.insert(0, ${JSON.stringify(join(HERE, "..", ".."))}); import signer, json; print(json.dumps(signer.keygen(${JSON.stringify(key)})))`], { encoding: "utf-8" })).public_key_hex;
    execFileSync("python3", [join(HERE, "..", "..", "cryptovalid_tip.py"), "sign", led, key]);
    const pyTip = JSON.parse(readFileSync(led + ".tip.json", "utf-8"));
    ok("cross: Python-signed tip verifies in JS", verifyLedger(text(6), { tip: pyTip, trustedPubkey: pk }).verdict === "PASS");
    ok("cross: JS sees truncation against the Python tip", verifyLedger(text(4), { tip: pyTip, trustedPubkey: pk }).errors.some((e) => e.error.startsWith("tail_truncated")));
    ok("cli: <ledger>.tip.json picked up + --require-tip", (() => { try { execFileSync("node", [join(HERE, "cvverify.mjs"), led, "--trusted-pubkey", pk, "--require-tip"], { stdio: "pipe" }); return true; } catch { return false; } })());
  } catch (e) { console.log("  (cross-language tip check skipped: " + e.message.split("\n")[0] + ")"); }
}

console.log(`\ncvverify test: ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
