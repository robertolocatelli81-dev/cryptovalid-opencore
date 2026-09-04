// Conformance + control tests for the Apple/Swift verifier. Loads the SAME normative
// vectors used by the Python reference and the JS verifier (bundled as resources) and
// asserts the verdict, chain_integrity, algorithm, entries and failing indices match.
// Run on macOS/Linux(with swift-crypto): `swift test`.
import XCTest
@testable import CryptoValidVerify

final class ConformanceTests: XCTestCase {
    struct Normative: Codable {
        let algorithm: String; let chain_integrity: Bool; let entries: Int
        let hash_failures_idx: [Int]; let link_failures_idx: [Int]; let verdict: String
    }
    struct Expected: Codable { let input: String; let normative: Normative }

    func vectorsDir() throws -> URL {
        let base = Bundle.module.resourceURL!.appendingPathComponent("Vectors")
        return base
    }

    func testNormativeVectors() throws {
        let dir = try vectorsDir()
        let files = try FileManager.default.contentsOfDirectory(at: dir, includingPropertiesForKeys: nil)
            .filter { $0.lastPathComponent.hasSuffix(".expected.json") }
        XCTAssertGreaterThanOrEqual(files.count, 6, "expected vectors present")
        for exp in files.sorted(by: { $0.lastPathComponent < $1.lastPathComponent }) {
            let e = try JSONDecoder().decode(Expected.self, from: Data(contentsOf: exp))
            let ledger = try String(contentsOf: dir.appendingPathComponent(e.input), encoding: .utf8)
            let r = CryptoValidVerifier.verify(ledgerText: ledger)
            XCTAssertEqual(r.verdict, e.normative.verdict, e.input)
            XCTAssertEqual(r.chain_integrity, e.normative.chain_integrity, e.input)
            XCTAssertEqual(r.algorithm, e.normative.algorithm, e.input)
            XCTAssertEqual(r.entries, e.normative.entries, e.input)
            XCTAssertEqual(r.hash_failures_idx, e.normative.hash_failures_idx, e.input)
            XCTAssertEqual(r.link_failures_idx, e.normative.link_failures_idx, e.input)
        }
    }

    func testControls() throws {
        // the bench must be able to fail: a tampered ledger must NOT pass
        let dir = try vectorsDir()
        let good = try String(contentsOf: dir.appendingPathComponent("valid_sha256.jsonl"), encoding: .utf8)
        XCTAssertEqual(CryptoValidVerifier.verify(ledgerText: good).verdict, "PASS")
        // robust tamper: rename prev_hash in a line so linkage recompute fails (works on any vector)
        let broken = good.replacingOccurrences(of: "prev_hash", with: "prev_hAsh", range: good.range(of: "prev_hash"))
        XCTAssertEqual(CryptoValidVerifier.verify(ledgerText: broken).verdict, "FAIL")
        // content tamper: flip a byte inside the first self_hash -> hash recompute fails
        if let r = good.range(of: "\"self_hash\": \"") {
            var chars = Array(good)
            let idx = good.distance(from: good.startIndex, to: r.upperBound)
            chars[idx] = chars[idx] == "a" ? "b" : "a"
            XCTAssertEqual(CryptoValidVerifier.verify(ledgerText: String(chars)).verdict, "FAIL")
        }
        XCTAssertEqual(CryptoValidVerifier.verify(ledgerText: good, algo: "sha3_256").verdict, "FAIL")
        XCTAssertEqual(CryptoValidVerifier.verify(ledgerText: "null\n[1,2]\nnot json").verdict, "FAIL")
    }

    func testKeccakKnownAnswer() {
        // FIPS 202 SHA3-256("") and ("abc")
        XCTAssertEqual(SHA3_256.hex(""), "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a")
        XCTAssertEqual(SHA3_256.hex("abc"), "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532")
    }


    func testDuplicateKeysRejected() {
        let dup = "{\"idx\":0,\"ts\":\"t\",\"data\":{\"evil\":1},\"data\":{\"real\":1},\"prev_hash\":\"" + String(repeating: "0", count: 64) + "\",\"self_hash\":\"x\"}"
        XCTAssertEqual(CryptoValidVerifier.verify(ledgerText: dup).verdict, "FAIL")
    }

    func testCanonicalMatchesPython() {
        // {"key":"café"} → ASCII-escaped, exactly like json.dumps(ensure_ascii=True)
        let v = JSONValue.object(["key": .string("café")])
        XCTAssertEqual(Canonical.encode(v), "{\"key\":\"caf\\u00e9\"}")
    }
}
