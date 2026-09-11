// CryptoValid hash-chain verifier for Apple platforms. SHA-256 and Ed25519 from the
// system CryptoKit; SHA3-256 from the bundled Keccak. Same verdict/fields as the
// reference and the JS/Java verifiers (shared conformance vectors).
import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto   // swift-crypto: API-compatible with CryptoKit (SHA256, Curve25519.Signing)
#endif

public struct VerifyResult: Codable, Equatable {
    public var verdict: String
    public var chain_integrity: Bool
    public var algorithm: String
    public var entries: Int
    public var hash_failures_idx: [Int]
    public var link_failures_idx: [Int]
    public var signatures_all_verified: Bool?
}

public enum CryptoValidVerifier {
    static let GENESIS = String(repeating: "0", count: 64)
    static let ATTEST: Set<String> = ["self_hash", "signature", "signer"]

    static func canonicalPayload(_ entry: [String: JSONValue]) -> [UInt8] {
        var d = entry; for k in ATTEST { d.removeValue(forKey: k) }
        return Array(Canonical.encode(.object(d)).utf8)
    }
    static func hashWith(_ algo: String, _ bytes: [UInt8]) -> String {
        if algo == "sha3_256" { return SHA3_256.hex(bytes) }
        return SHA256.hash(data: Data(bytes)).map { String(format: "%02x", $0) }.joined()
    }
    static func detectAlgo(_ entries: [[String: JSONValue]]) -> String? {
        guard let e0 = entries.first, case .string(let sh)? = e0["self_hash"] else { return nil }
        let p = canonicalPayload(e0)
        for a in ["sha256", "sha3_256"] where hashWith(a, p) == sh { return a }
        return nil
    }
    static func str(_ v: JSONValue?) -> String? { if case .string(let s)? = v { return s }; return nil }
    static func intVal(_ v: JSONValue?) -> Int64? { if case .int(let n)? = v { return n }; return nil }

    public static func verify(ledgerText: String, algo: String? = nil, expectedPubkeyHex: String? = nil) -> VerifyResult {
        var entries: [[String: JSONValue]] = []
        var parseErrors = 0
        for line in ledgerText.split(separator: "\n", omittingEmptySubsequences: false) {
            let t = line.trimmingCharacters(in: .whitespaces)
            if t.isEmpty { continue }
            if let v = try? JSONParser.parse(t), case .object(let o) = v { entries.append(o) } else { parseErrors += 1 }
        }
        let use = algo ?? detectAlgo(entries) ?? "sha256"
        var hashFail: [Int] = [], linkFail: [Int] = []
        for (i, e) in entries.enumerated() {
            guard let sh = str(e["self_hash"]) else { hashFail.append(Int(intVal(e["idx"]) ?? Int64(i))); continue }
            if hashWith(use, canonicalPayload(e)) != sh { hashFail.append(Int(intVal(e["idx"]) ?? Int64(i))) }
        }
        for (i, e) in entries.enumerated() {
            let expected = i > 0 ? (str(entries[i-1]["self_hash"]) ?? "") : GENESIS
            if str(e["prev_hash"]) != expected { linkFail.append(Int(intVal(e["idx"]) ?? Int64(i))) }
        }
        var idxOk = true
        for (i, e) in entries.enumerated() where intVal(e["idx"]) != Int64(i) { idxOk = false }
        // zero entries = nothing verified = FAIL (2026-09-11: all four verifiers said PASS on an empty file)
        let chain = hashFail.isEmpty && linkFail.isEmpty && idxOk && parseErrors == 0 && !entries.isEmpty

        var sigAll: Bool? = nil
        if entries.contains(where: { $0["signature"] != nil }) {
            var allOk = true
            for e in entries {
                guard let sig = str(e["signature"]), let signer = str(e["signer"]), let sh = str(e["self_hash"]),
                      let sigData = Data(base64Encoded: sig), let pubData = hexToData(signer),
                      let pub = try? Curve25519.Signing.PublicKey(rawRepresentation: pubData) else { allOk = false; continue }
                if let exp = expectedPubkeyHex, signer != exp { allOk = false; continue }
                if !pub.isValidSignature(sigData, for: Data(sh.utf8)) { allOk = false }
            }
            sigAll = allOk
        }
        return VerifyResult(verdict: chain ? "PASS" : "FAIL", chain_integrity: chain, algorithm: use,
                            entries: entries.count, hash_failures_idx: hashFail, link_failures_idx: linkFail,
                            signatures_all_verified: sigAll)
    }
    static func hexToData(_ h: String) -> Data? {
        guard h.count % 2 == 0 else { return nil }
        var out = Data(); var idx = h.startIndex
        while idx < h.endIndex {
            let next = h.index(idx, offsetBy: 2)
            guard let b = UInt8(h[idx..<next], radix: 16) else { return nil }
            out.append(b); idx = next
        }
        return out
    }
}
