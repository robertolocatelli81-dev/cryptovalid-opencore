// Professional test suite for the independent CryptoValid verifier.
// Runs the normative conformance vectors, positive+negative controls, an Ed25519
// signature round-trip, AND cross-checks every vector against the REFERENCE Python
// verifier (opencore/verifier.py) as an independent oracle — so a bug that makes us
// wrongly agree with ourselves is caught by disagreement with the reference.
import { verifyLedger, conformance } from "./cvverify.mjs";
import { readFileSync, writeFileSync, mkdtempSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { createHash, generateKeyPairSync, sign as edSign } from "node:crypto";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { tmpdir } from "node:os";

const HERE = dirname(fileURLToPath(import.meta.url));
const VDIR = join(HERE, "..", "..", "opencore", "spec", "vectors");
const REF = join(HERE, "..", "..", "opencore", "verifier.py");
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
  const d = {}; for (const k of Object.keys(entry).sort()) if (!["self_hash", "signature", "signer"].includes(k)) d[k] = entry[k];
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

console.log(`\ncvverify test: ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
