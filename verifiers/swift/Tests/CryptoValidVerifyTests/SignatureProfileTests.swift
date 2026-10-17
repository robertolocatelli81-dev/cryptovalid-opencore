// 0.21.0 (SPEC v0.4 §5 step 5): the signature-profile vectors (a copy of spec/vectors/signatures in Vectors/signatures).
// Without a key a signature layer that does not verify is a FAIL; keys and R values of small or mixed order are refused
// (Ed25519Order.swift). Swift reports a boolean, so the verdict and signatures_all_verified are checked, not the reasons.
import XCTest
@testable import CryptoValidVerify
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

final class SignatureProfileTests: XCTestCase {
    struct Profile: Codable { let verdict: String }
    struct Normative: Codable { let chain_integrity: Bool }
    struct Expected: Codable { let input: String; let normative: Normative; let signature_profile: Profile }

    func testSignatureProfileVectors() throws {
        let dir = Bundle.module.resourceURL!.appendingPathComponent("Vectors").appendingPathComponent("signatures")
        let files = try FileManager.default.contentsOfDirectory(at: dir, includingPropertiesForKeys: nil)
            .filter { $0.lastPathComponent.hasSuffix(".expected.json") }
        XCTAssertGreaterThanOrEqual(files.count, 21, "signature vectors present")
        for f in files.sorted(by: { $0.lastPathComponent < $1.lastPathComponent }) {
            let e = try JSONDecoder().decode(Expected.self, from: Data(contentsOf: f))
            let r = CryptoValidVerifier.verify(ledgerText: try String(contentsOf: dir.appendingPathComponent(e.input), encoding: .utf8))
            XCTAssertEqual(r.verdict, e.signature_profile.verdict, e.input)
            XCTAssertEqual(r.chain_integrity, e.normative.chain_integrity, e.input)
            XCTAssertEqual(r.signatures_all_verified, e.signature_profile.verdict == "PASS", e.input)
        }
    }

    func testEd25519OrderPositiveControl() throws {
        // 64 keys made by the library are of prime order and their signatures pass the R check
        for i in 0..<64 {
            var seed = [UInt8](repeating: 0, count: 32); seed[0] = UInt8(i); seed[1] = 0x5a
            let sk = try Curve25519.Signing.PrivateKey(rawRepresentation: seed)
            let sig = try sk.signature(for: Data("m".utf8))
            XCTAssertNil(Ed25519Order.keyProblem(Array(sk.publicKey.rawRepresentation)), "key \(i)")
            XCTAssertNil(Ed25519Order.rProblem(Array(sig)), "sig \(i)")
        }
        // the eight points of small order (canonical encodings) are refused as keys and as R
        let small = ["0100000000000000000000000000000000000000000000000000000000000000",
                     "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
                     "0000000000000000000000000000000000000000000000000000000000000000",
                     "0000000000000000000000000000000000000000000000000000000000000080",
                     "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
                     "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
                     "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
                     "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa"]
        for h in small {
            let b = Array(CryptoValidVerifier.hex64(h)!)
            XCTAssertEqual(Ed25519Order.keyProblem(b), "small_order_key", h)
            XCTAssertEqual(Ed25519Order.rProblem(b + [UInt8](repeating: 0, count: 32)), "small_order_r", h)
        }
        // x = 0 with the sign bit set (RFC 8032 5.1.3 step 4), y >= p, a y with no x: not decodable, named as such
        let notPoints = ["0100000000000000000000000000000000000000000000000000000000000080",
                         "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                         "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
                         "0200000000000000000000000000000000000000000000000000000000000000"]
        for h in notPoints {
            XCTAssertEqual(Ed25519Order.keyProblem(Array(CryptoValidVerifier.hex64(h)!)), "key_not_decodable", h)
        }
    }

    func testPQLayerIsCounted() throws {
        let dir = Bundle.module.resourceURL!.appendingPathComponent("Vectors").appendingPathComponent("signatures")
        let text = try String(contentsOf: dir.appendingPathComponent("signed_valid.jsonl"), encoding: .utf8)
        let hy = text.split(separator: "\n").map { $0.dropLast() + ",\"signature_pq\":\"AAAA\",\"signer_pq\":\"AAAA\"}" }.joined(separator: "\n")
        let r = CryptoValidVerifier.verify(ledgerText: hy)
        XCTAssertEqual(r.verdict, "PASS"); XCTAssertEqual(r.pq_not_checked, 3)
        XCTAssertNil(CryptoValidVerifier.verify(ledgerText: text).pq_not_checked)
    }
}
