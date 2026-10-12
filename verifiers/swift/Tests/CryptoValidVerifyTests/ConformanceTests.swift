// Conformance + control tests for the Apple/Swift verifier. Loads the SAME normative
// vectors used by the Python reference and the JS verifier (bundled as resources) and
// asserts the verdict, chain_integrity, algorithm, entries and failing indices match.
// Run on macOS/Linux(with swift-crypto): `swift test`.
import XCTest
@testable import CryptoValidVerify
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto   // swift-crypto on Linux: SHA256 for the test's own hash of the entry
#endif

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


    func testClosedEntrySchemaSpec21() {
        // SPEC §2.1 (2026-10-10): a top-level key nobody defined is a schema failure (idx named), never a silent PASS;
        // the same key inside data (SPEC §4) and an optional key of §2 stay PASS. self_hash recomputed OVER the key.
        func entry(_ extraKey: String?, _ dataJSON: String) -> String {
            let extra = extraKey.map { ",\"\($0)\":\"x\"" } ?? ""
            let body = "{\"data\":\(dataJSON),\"idx\":0,\"prev_hash\":\"\(String(repeating: "0", count: 64))\",\"ts\":\"t\"\(extra)}"
            let v = try! JSONParser.parse(body)
            let h = SHA256.hash(data: Data(Canonical.encode(v).utf8)).map { String(format: "%02x", $0) }.joined()
            return "{\"data\":\(dataJSON),\"idx\":0,\"prev_hash\":\"\(String(repeating: "0", count: 64))\",\"self_hash\":\"\(h)\",\"ts\":\"t\"\(extra)}\n"
        }
        XCTAssertEqual(CryptoValidVerifier.verify(ledgerText: entry(nil, "{\"i\":0}")).verdict, "PASS")   // positive control
        for key in ["x_unknown_2026", "__proto__", "Idx", ""] {
            let r = CryptoValidVerifier.verify(ledgerText: entry(key, "{\"i\":0}"))
            XCTAssertEqual(r.verdict, "FAIL", key)
            XCTAssertEqual(r.schema_failures_idx, [0], key)
            XCTAssertEqual(r.hash_failures_idx, [], key)
        }
        // tsa_token is an attestation outside the canonical form since 0.20.2 (SPEC §3): attached after hashing it PASSES;
        // hashed as content (the 0.20.1 rule, which made a token over self_hash impossible) it is a hash failure
        var attached = entry(nil, "{\"i\":0}"); attached.removeLast(2); attached += ",\"tsa_token\":\"x\"}\n"
        let opt = CryptoValidVerifier.verify(ledgerText: attached)
        XCTAssertEqual(opt.verdict, "PASS"); XCTAssertEqual(opt.schema_failures_idx, [])
        let inside = CryptoValidVerifier.verify(ledgerText: entry("tsa_token", "{\"i\":0}"))
        XCTAssertEqual(inside.verdict, "FAIL"); XCTAssertEqual(inside.hash_failures_idx, [0]); XCTAssertEqual(inside.schema_failures_idx, [])
        let inData = CryptoValidVerifier.verify(ledgerText: entry(nil, "{\"x_unknown_2026\":\"payload\"}"))
        XCTAssertEqual(inData.verdict, "PASS"); XCTAssertEqual(inData.schema_failures_idx, [])
    }

    func testReadLedgerFileFifoDirectoryEmpty() throws {
        // 12/10/2026: the CLI read the ledger with FileManager.contents(atPath:), nil on a FIFO on Linux, so
        // `cvverify <(cat ledger)` was FILE_ERROR, exit 2, while the other five verifiers read it. A FIFO is read to its
        // end; a directory and a missing path stay unreadable (nil = FILE_ERROR); an empty file is zero bytes, not nil.
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("cvv-fifo-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let body = "{\"data\":{\"i\":0},\"idx\":0,\"prev_hash\":\"\(String(repeating: "0", count: 64))\",\"ts\":\"t\"}"
        let h = SHA256.hash(data: Data(Canonical.encode(try JSONParser.parse(body)).utf8)).map { String(format: "%02x", $0) }.joined()
        let line = "{\"data\":{\"i\":0},\"idx\":0,\"prev_hash\":\"\(String(repeating: "0", count: 64))\",\"self_hash\":\"\(h)\",\"ts\":\"t\"}\n"
        let regular = dir.appendingPathComponent("l.jsonl").path
        XCTAssertTrue(FileManager.default.createFile(atPath: regular, contents: Data(line.utf8)))
        XCTAssertEqual(CryptoValidVerifier.readLedgerFile(atPath: regular), Array(line.utf8))   // positive control
        signal(SIGPIPE, SIG_IGN)   // a reader that closes early must fail an assertion here, not kill the test process
        let fifo = dir.appendingPathComponent("p.fifo").path
        XCTAssertEqual(mkfifo(fifo, 0o600), 0)
        let writer = Thread {   // opening a FIFO for writing blocks until the reader opens it
            if let w = FileHandle(forWritingAtPath: fifo) { w.write(Data(line.utf8)); try? w.close() }
        }
        writer.start()
        let got = CryptoValidVerifier.readLedgerFile(atPath: fifo)
        XCTAssertEqual(got, Array(line.utf8))
        XCTAssertEqual(CryptoValidVerifier.verify(ledgerBytes: got ?? [], algo: nil, expectedPubkeyHex: nil).verdict, "PASS")
        XCTAssertNil(CryptoValidVerifier.readLedgerFile(atPath: dir.path))                       // a directory
        XCTAssertNil(CryptoValidVerifier.readLedgerFile(atPath: dir.appendingPathComponent("missing").path))
        let empty = dir.appendingPathComponent("e.jsonl").path
        XCTAssertTrue(FileManager.default.createFile(atPath: empty, contents: Data()))
        XCTAssertEqual(CryptoValidVerifier.readLedgerFile(atPath: empty), [])
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
