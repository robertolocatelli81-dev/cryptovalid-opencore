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
    /// entries whose top level carries a key outside ENTRY_KEYS (SPEC §2.1)
    public var schema_failures_idx: [Int]
    public var signatures_all_verified: Bool?
    /// 0.21.0: entries carrying an ML-DSA-65 layer, which this verifier does not check (nil, omitted, when there is none)
    public var pq_not_checked: Int? = nil
    /// set when the input could not be read as a ledger at all (e.g. not UTF-8); nil otherwise (omitted from the JSON)
    public var error: String? = nil
}

public enum CryptoValidVerifier {
    static let GENESIS = String(repeating: "0", count: 64)
    static let ATTEST: Set<String> = ["self_hash", "signature", "signer", "signature_pq", "signer_pq", "tsa_token"] // 0.12.0: ML-DSA-65 companion; 0.20.2: tsa_token (SPEC §3)
    // SPEC_EVIDENCE_FORMAT §2.1 (2026-10-10): the CLOSED entry schema (core + optional fields of §2), as verifier.py ENTRY_KEYS.
    // An entry with a top-level key outside it is a schema failure and the verdict is FAIL, never a silent PASS. `data` stays free (§4).
    public static let ENTRY_KEYS: Set<JSONKey> = ["idx", "ts", "data", "prev_hash", "self_hash", "signature", "signer", "tsa_token", "signature_pq", "signer_pq"]
    /// The entry's top-level keys outside ENTRY_KEYS, in code-point order (the order Python's sorted() gives).
    public static func unknownFields(_ entry: [JSONKey: JSONValue]) -> [String] {
        entry.keys.filter { !ENTRY_KEYS.contains($0) }.sorted().map { $0.string }   // JSONKey: scalar-exact, code-point order
    }

    /// The bytes of the file at `path`, read to its end through a file handle: a regular file, a FIFO or a process
    /// substitution (`cvverify <(cat ledger)`) alike, as the Python, JS, Go, Java and Rust verifiers read them; nil when it
    /// cannot be opened or read (missing, a directory, no permission). `FileManager.contents(atPath:)`, used until 0.20.1,
    /// answered nil on a FIFO on Linux (FILE_ERROR, exit 2; NEMESIS 12/10/2026, the same in 0.20.0).
    public static func readLedgerFile(atPath path: String) -> [UInt8]? {
        guard let h = FileHandle(forReadingAtPath: path) else { return nil }
        defer { try? h.close() }
        do { return [UInt8](try h.readToEnd() ?? Data()) } catch { return nil }   // nil from readToEnd = no bytes (empty file)
    }

    static func canonicalPayload(_ entry: [JSONKey: JSONValue]) -> [UInt8] {
        var d = entry; for k in ATTEST { d.removeValue(forKey: JSONKey(k)) }
        return Array(Canonical.encode(.object(d)).utf8)
    }
    static func hashWith(_ algo: String, _ bytes: [UInt8]) -> String {
        if algo == "sha3_256" { return SHA3_256.hex(bytes) }
        return SHA256.hash(data: Data(bytes)).map { String(format: "%02x", $0) }.joined()
    }
    static func detectAlgo(_ entries: [[JSONKey: JSONValue]]) -> String? {
        guard let e0 = entries.first, case .string(let sh)? = e0["self_hash"] else { return nil }
        let p = canonicalPayload(e0)
        for a in ["sha256", "sha3_256"] where scalarEqual(hashWith(a, p), sh) { return a }
        return nil
    }
    static func str(_ v: JSONValue?) -> String? { if case .string(let s)? = v { return s }; return nil }
    static func intVal(_ v: JSONValue?) -> Int64? { if case .int(let n)? = v { return n }; return nil }

    /// The ledger's lines (council 16/09 r5, one line rule in every verifier): LF is the ONLY separator — split on the
    /// scalar U+000A, never on Swift Characters ("\r\n" is one grapheme, which kept CRLF lines unsplit) — and each
    /// line is trimmed of ASCII space / tab / CR only (a line holding nothing else is blank and skipped; U+00A0 is not
    /// blank, a lone CR inside a line is data).
    public static func ledgerLines(_ text: String) -> [String] {
        var out: [String] = []
        var cur: [Unicode.Scalar] = []
        func flush() {
            var a = 0, b = cur.count
            func blank(_ c: Unicode.Scalar) -> Bool { c == " " || c == "\t" || c == "\r" }
            while a < b, blank(cur[a]) { a += 1 }
            while b > a, blank(cur[b - 1]) { b -= 1 }
            if a < b { out.append(String(String.UnicodeScalarView(cur[a..<b]))) }
            cur.removeAll(keepingCapacity: true)
        }
        for c in text.unicodeScalars { if c == "\n" { flush() } else { cur.append(c) } }
        flush()
        return out
    }

    /// The file's bytes: a ledger is UTF-8 (SPEC §1, §3: "MUST NOT contain non-UTF-8 bytes"). Bytes that are not valid
    /// UTF-8 are a FAIL verdict with a named error — never a file error (the file was read) and never a lossy decode.
    public static func verify(ledgerBytes: [UInt8], algo: String? = nil, expectedPubkeyHex: String? = nil) -> VerifyResult {
        let text = String(decoding: ledgerBytes, as: UTF8.self)   // invalid sequences become U+FFFD here, so the
        guard text.utf8.elementsEqual(ledgerBytes) else {          // round trip differs exactly when the bytes are not UTF-8
            return VerifyResult(verdict: "FAIL", chain_integrity: false, algorithm: algo ?? "sha256", entries: 0,
                                hash_failures_idx: [], link_failures_idx: [], schema_failures_idx: [],
                                signatures_all_verified: nil, error: "ledger is not valid UTF-8")
        }
        return verify(ledgerText: text, algo: algo, expectedPubkeyHex: expectedPubkeyHex)
    }

    public static func verify(ledgerText: String, algo: String? = nil, expectedPubkeyHex: String? = nil) -> VerifyResult {
        var entries: [[JSONKey: JSONValue]] = []
        var parseErrors = 0
        for t in ledgerLines(ledgerText) {
            if let v = try? JSONParser.parse(t), case .object(let o) = v { entries.append(o) } else { parseErrors += 1 }
        }
        let use = algo ?? detectAlgo(entries) ?? "sha256"
        var hashFail: [Int] = [], linkFail: [Int] = [], schemaFail: [Int] = []
        for (i, e) in entries.enumerated() where !unknownFields(e).isEmpty {   // SPEC §2.1: closed entry schema, never silence
            schemaFail.append(Int(intVal(e["idx"]) ?? Int64(i)))
        }
        for (i, e) in entries.enumerated() {
            guard let sh = str(e["self_hash"]) else { hashFail.append(Int(intVal(e["idx"]) ?? Int64(i))); continue }
            if !scalarEqual(hashWith(use, canonicalPayload(e)), sh) { hashFail.append(Int(intVal(e["idx"]) ?? Int64(i))) }
        }
        for (i, e) in entries.enumerated() {
            let expected = i > 0 ? (str(entries[i-1]["self_hash"]) ?? "") : GENESIS
            if !(str(e["prev_hash"]).map { scalarEqual($0, expected) } ?? false) { linkFail.append(Int(intVal(e["idx"]) ?? Int64(i))) }
        }
        var idxOk = true
        for (i, e) in entries.enumerated() where intVal(e["idx"]) != Int64(i) { idxOk = false }
        // zero entries = nothing verified = FAIL (2026-09-11: all four verifiers said PASS on an empty file)
        let chain = hashFail.isEmpty && linkFail.isEmpty && idxOk && parseErrors == 0 && schemaFail.isEmpty && !entries.isEmpty   // SPEC §2.1

        var sigAll: Bool? = nil
        // --pubkey is a CONSTRAINT (JS, Go, Java and signer.py: every entry signed by that key, else FAIL): with a key given
        // the layer is checked even when no entry is signed, and its result enters the verdict (NEMESIS 12/10/2026: a wrong
        // key, an unsigned or a partly signed ledger was PASS, exit 0, here alone). 0.21.0 (SPEC v0.4 §5 step 5, signature
        // profile): the layer is any of the four signature fields in any entry (until 0.20.3 only "signature"), and a layer
        // that does not verify is a FAIL without a key too (until 0.20.3 informational).
        let sigFields: [JSONKey] = ["signature", "signer", "signature_pq", "signer_pq"]
        let layer = entries.contains(where: { e in sigFields.contains(where: { e[$0] != nil }) })
        var keyCache: [Data: String?] = [:]
        if expectedPubkeyHex != nil || layer {
            var allOk = true
            for e in entries {
                guard let sig = str(e["signature"]), let signer = str(e["signer"]), let sh = str(e["self_hash"]),
                      let sigData = b64Strict(sig, 64), let pubData = hex64(signer),
                      let pub = try? Curve25519.Signing.PublicKey(rawRepresentation: pubData) else { allOk = false; continue }
                if let exp = expectedPubkeyHex, !scalarEqual(signer, exp) { allOk = false; continue }
                // 0.21.0: a key or an R of small order, a key of mixed order or not decodable is refused (Ed25519Order.swift)
                if keyCache[pubData] == nil { keyCache[pubData] = .some(Ed25519Order.keyProblem(Array(pubData))) }
                if keyCache[pubData]! != nil || Ed25519Order.rProblem(Array(sigData)) != nil { allOk = false; continue }
                if !pub.isValidSignature(sigData, for: Data(sh.utf8)) { allOk = false }
            }
            sigAll = allOk
        }
        let pqCount = entries.filter { $0["signature_pq"] != nil || $0["signer_pq"] != nil }.count
        let pass = chain && (expectedPubkeyHex == nil ? !(layer && sigAll != true) : sigAll == true)
        return VerifyResult(verdict: pass ? "PASS" : "FAIL", chain_integrity: chain, algorithm: use,
                            entries: entries.count, hash_failures_idx: hashFail, link_failures_idx: linkFail,
                            schema_failures_idx: schemaFail, signatures_all_verified: sigAll,
                            pq_not_checked: pqCount > 0 ? pqCount : nil)
    }
    /// signer: exactly 64 LOWERCASE ASCII hex digits (Python signer._HEX64, JS/Java HEX64; audit V1 #12, 30/09/2026).
    /// UInt8(_:radix:) took "+f" and uppercase, so a lax hex is refused here before any key is built.
    static func hex64(_ h: String) -> Data? {
        let u = Array(h.unicodeScalars)
        guard u.count == 64 else { return nil }
        var out = Data(); var k = 0
        func nib(_ c: Unicode.Scalar) -> UInt8? {
            switch c.value {
            case 0x30...0x39: return UInt8(c.value - 0x30)
            case 0x61...0x66: return UInt8(c.value - 0x61 + 10)
            default: return nil
            }
        }
        while k < 64 {
            guard let hi = nib(u[k]), let lo = nib(u[k + 1]) else { return nil }
            out.append(hi << 4 | lo); k += 2
        }
        return out
    }
    /// signature: strict standard base64 of exactly n bytes whose canonical re-encoding is the input (Python
    /// signer._b64_strict, JS/Java b64Strict): no whitespace, no URL alphabet, no non-canonical padding bits.
    static func b64Strict(_ s: String, _ n: Int) -> Data? {
        guard s.unicodeScalars.count == ((n + 2) / 3) * 4,
              s.unicodeScalars.allSatisfy({ $0.isASCII && (CharacterSet.alphanumerics.contains($0) || $0 == "+" || $0 == "/" || $0 == "=") }),
              let raw = Data(base64Encoded: s), raw.count == n, scalarEqual(raw.base64EncodedString(), s) else { return nil }
        return raw
    }
}
