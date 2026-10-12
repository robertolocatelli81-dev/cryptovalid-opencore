// cvverify — CLI wrapper. Usage: cvverify <ledger.jsonl> [--algo sha256|sha3_256] [--pubkey hex]
import Foundation
import CryptoValidVerify

let usageText = "usage: cvverify <ledger.jsonl> [--algo sha256|sha3_256] [--pubkey hex]\n"
func usage() -> Never { FileHandle.standardError.write(usageText.data(using: .utf8)!); exit(2) }

// One grammar with the other verifiers (21/09/2026, differential_oracle.py CLI cases): the ledger path first; an
// unknown flag, a value flag without a value, with "" or with a value starting with "-", a second positional = usage
// error, exit 2, no verdict — never a verdict with the constraint dropped. `--algo` takes only the two profiles
// (verifier.py's argparse choices); a repeated flag keeps its last value, as in Python, JS and Rust.
let args = Array(CommandLine.arguments.dropFirst())
guard let path = args.first, path.unicodeScalars.first != "-" else { usage() }   // scalar test: hasPrefix compares graphemes
var algo: String? = nil, pubkey: String? = nil
var k = 1
while k < args.count {
    let flag = args[k]
    guard scalarEqual(flag, "--algo") || scalarEqual(flag, "--pubkey"), k + 1 < args.count else { usage() }
    let v = args[k + 1]
    if v.unicodeScalars.first == nil || v.unicodeScalars.first == "-" { usage() }
    if scalarEqual(flag, "--algo") {
        guard scalarEqual(v, "sha256") || scalarEqual(v, "sha3_256") else { usage() }
        algo = v
    } else {
        pubkey = v
    }
    k += 2
}
guard let data = FileManager.default.contents(atPath: path) else {
    print("{\"verdict\":\"FILE_ERROR\"}"); exit(2)
}
// bytes, not String(contentsOfFile:): a file that is not UTF-8 is read, then FAILs with a named error (as Rust, JS, Go,
// Java); it used to be FILE_ERROR
let r = CryptoValidVerifier.verify(ledgerBytes: [UInt8](data), algo: algo, expectedPubkeyHex: pubkey)
let enc = JSONEncoder(); enc.outputFormatting = [.prettyPrinted, .sortedKeys]
print(String(data: try! enc.encode(r), encoding: .utf8)!)
exit(r.verdict == "PASS" ? 0 : 1)
