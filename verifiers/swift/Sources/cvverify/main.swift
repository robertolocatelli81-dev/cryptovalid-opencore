// cvverify — CLI wrapper. Usage: cvverify <ledger.jsonl> [--algo sha256|sha3_256] [--pubkey hex]
import Foundation
import CryptoValidVerify

let args = Array(CommandLine.arguments.dropFirst())
guard let path = args.first, !path.hasPrefix("--") else {
    FileHandle.standardError.write("usage: cvverify <ledger.jsonl> [--algo A] [--pubkey hex]\n".data(using: .utf8)!)
    exit(2)
}
func opt(_ name: String) -> String? { if let i = args.firstIndex(of: name), i + 1 < args.count { return args[i+1] }; return nil }
guard let text = try? String(contentsOfFile: path, encoding: .utf8) else {
    print("{\"verdict\":\"FILE_ERROR\"}"); exit(2)
}
let r = CryptoValidVerifier.verify(ledgerText: text, algo: opt("--algo"), expectedPubkeyHex: opt("--pubkey"))
let enc = JSONEncoder(); enc.outputFormatting = [.prettyPrinted, .sortedKeys]
print(String(data: try! enc.encode(r), encoding: .utf8)!)
exit(r.verdict == "PASS" ? 0 : 1)
