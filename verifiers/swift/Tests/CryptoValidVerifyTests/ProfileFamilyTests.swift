// Acceptance-profile rules, tested by FAMILY and generatively (12/10/2026). Each family is the rule the reference
// (verifier.py) and the JS / Go / Java / Rust verifiers already apply, and that this verifier did not: the differential
// oracle measured 12 divergences (a valid surrogate pair refused; `+10`, `010` and a raw tab accepted; CRLF refused;
// FILE_ERROR on non-UTF-8 bytes; five CLI forms answered with a verdict instead of a usage error).
//
// The expected self_hash is computed from a canonical text written HERE in Python's json.dumps style (sort_keys,
// compact, ensure_ascii), never by this package's parser or encoder, so a parser bug cannot make its own test pass.
// Only APIs that also exist in the code before the change are used (verify(ledgerText:), JSONParser, the cvverify
// binary): the same tests run on the old code fail at run time, family by family (the positive control).
import XCTest
import Foundation
@testable import CryptoValidVerify
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

/// Deterministic generator (SplitMix64): the same cases on every run.
struct SplitMix64 {
    var state: UInt64
    mutating func next() -> UInt64 {
        state &+= 0x9E3779B97F4A7C15
        var z = state
        z = (z ^ (z >> 30)) &* 0xBF58476D1CE4E5B9
        z = (z ^ (z >> 27)) &* 0x94D049BB133111EB
        return z ^ (z >> 31)
    }
    mutating func below(_ n: UInt64) -> UInt64 { next() % n }
}

final class ProfileFamilyTests: XCTestCase {
    static let Z = String(repeating: "0", count: 64)

    func sha(_ s: String) -> String { SHA256.hash(data: Data(s.utf8)).map { String(format: "%02x", $0) }.joined() }

    /// Python's json.dumps(ensure_ascii=True) of a string, written independently of Canonical.escape.
    func py(_ s: String) -> String {
        var o = "\""
        for u in s.unicodeScalars {
            switch u.value {
            case 0x22: o += "\\\""
            case 0x5C: o += "\\\\"
            case 0x0A: o += "\\n"
            case 0x0D: o += "\\r"
            case 0x09: o += "\\t"
            case 0x08: o += "\\b"
            case 0x0C: o += "\\f"
            case 0x20...0x7E: o.unicodeScalars.append(u)
            default:
                if u.value > 0xFFFF {
                    let v = u.value - 0x10000
                    o += String(format: "\\u%04x\\u%04x", 0xD800 + (v >> 10), 0xDC00 + (v & 0x3FF))
                } else { o += String(format: "\\u%04x", u.value) }
            }
        }
        return o + "\""
    }

    /// One entry: `canonData` is the canonical text the hash commits to, `rawData` what the line carries.
    func entry(_ idx: Int, _ prev: String, canon canonData: String, raw rawData: String) -> (line: String, hash: String) {
        let h = sha("{\"data\":\(canonData),\"idx\":\(idx),\"prev_hash\":\"\(prev)\",\"ts\":\"t\"}")
        return ("{\"idx\":\(idx),\"ts\":\"t\",\"data\":\(rawData),\"prev_hash\":\"\(prev)\",\"self_hash\":\"\(h)\"}", h)
    }
    func one(canon: String, raw: String) -> String { entry(0, Self.Z, canon: canon, raw: raw).line }
    func chain(_ n: Int) -> [String] {
        var out: [String] = [], prev = Self.Z
        for i in 0..<n { let e = entry(i, prev, canon: "{\"i\":\(i)}", raw: "{\"i\":\(i)}"); out.append(e.line); prev = e.hash }
        return out
    }
    func verdict(_ text: String) -> String { CryptoValidVerifier.verify(ledgerText: text).verdict }

    // MARK: numbers — RFC 8259 integers only: -?(0|[1-9][0-9]*), |n| <= 2^53-1; no '+', no leading zero, no float

    func testNumberFamily() {
        var r = SplitMix64(state: 20261012)
        var ns: [Int64] = [0, 1, -1, 7, 10, -10, 9_007_199_254_740_991, -9_007_199_254_740_991]
        for _ in 0..<200 { ns.append(Int64(bitPattern: r.next()) % 9_007_199_254_740_992) }
        for n in ns {
            let s = String(n), canon = "{\"n\":\(s)}"
            XCTAssertEqual(verdict(one(canon: canon, raw: canon)), "PASS", "canonical \(s)")   // control: the rule must not over-reject
            let mag = String(n.magnitude), sign = n < 0 ? "-" : ""
            var bad = ["\(sign)0\(mag)", "\(sign)00\(mag)", "\(s)+", "+-\(mag)", "-+\(mag)", "--\(mag)", "\(s)-"]
            if n >= 0 { bad += ["+\(mag)", "+0\(mag)"] }
            for b in bad {
                XCTAssertEqual(verdict(one(canon: canon, raw: "{\"n\":\(b)}")), "FAIL", "non-canonical number \(b) for \(s)")
            }
        }
        XCTAssertEqual(verdict(one(canon: "{\"n\":0}", raw: "{\"n\":-0}")), "PASS", "-0 is the integer 0 (Python int('-0'))")
        for b in ["-00", "+0", "00", "-", "+", "9007199254740992", "-9007199254740992", "10000000000000000000",
                  "1.0", "1.", ".5", "1e1", "1E1", "-0.0", "1e+1", "0x10", "1_0"] {
            XCTAssertEqual(verdict(one(canon: "{\"n\":0}", raw: "{\"n\":\(b)}")), "FAIL", b)
        }
        // out of range, hashed over the number AS WRITTEN: only the range rule can refuse these (the cases above hash 0);
        // Int64.min must be refused without a trap (abs(Int64.min) overflows: the code before 12/10/2026 trapped, SIGILL on Linux)
        for b in ["9007199254740992", "-9007199254740992", "9223372036854775807", "-9223372036854775808", "-9223372036854775809"] {
            XCTAssertEqual(verdict(one(canon: "{\"n\":\(b)}", raw: "{\"n\":\(b)}")), "FAIL", "out of range \(b)")
        }
    }

    // MARK: raw control characters — U+0000..U+001F never raw inside a string (value or key); escaped they pass

    func testRawControlCharacterFamily() {
        for c in UInt32(0)..<0x20 {
            let ch = String(UnicodeScalar(c)!)
            let canon = "{\"k\":\(py("a" + ch + "b"))}"
            XCTAssertEqual(verdict(one(canon: canon, raw: canon)), "PASS", "escaped U+\(String(c, radix: 16))")   // control
            XCTAssertEqual(verdict(one(canon: canon, raw: "{\"k\":\"a\(ch)b\"}")), "FAIL", "raw U+\(String(c, radix: 16)) in a value")
            let kcanon = "{\(py("k" + ch)):1}"
            XCTAssertEqual(verdict(one(canon: kcanon, raw: "{\"k\(ch)\":1}")), "FAIL", "raw U+\(String(c, radix: 16)) in a key")
        }
        // DEL (U+007F) and C1 controls are not in the RFC 8259 range: raw is legal, Python escapes them in the hash
        for c: UInt32 in [0x7F, 0x80, 0x9F] {
            let ch = String(UnicodeScalar(c)!)
            XCTAssertEqual(verdict(one(canon: "{\"k\":\(py(ch))}", raw: "{\"k\":\"\(ch)\"}")), "PASS", "raw U+\(String(c, radix: 16))")
        }
    }

    // MARK: \u escapes and UTF-16 surrogates — exactly four ASCII hex digits; a high surrogate needs a low one at once

    func testUnicodeEscapeFamily() {
        var r = SplitMix64(state: 41)
        for _ in 0..<300 {
            var cp = UInt32(r.below(0x10000))
            if (0xD800...0xDFFF).contains(cp) { cp = 0x41 }
            let canon = "{\"k\":\(py(String(UnicodeScalar(cp)!)))}"
            let lower = String(format: "\\u%04x", cp), upper = String(format: "\\u%04X", cp)
            XCTAssertEqual(verdict(one(canon: canon, raw: "{\"k\":\"\(lower)\"}")), "PASS", lower)
            XCTAssertEqual(verdict(one(canon: canon, raw: "{\"k\":\"\(upper)\"}")), "PASS", upper)
            // one digit replaced by something that is not an ASCII hex digit (fullwidth, Arabic-Indic, sign, space)
            let pos = Int(r.below(4))
            for junk in ["g", "G", "+", "-", " ", "\u{FF24}", "\u{0663}", "x"] {
                var d = Array(String(format: "%04x", cp)); d[pos] = Character(junk)
                // the hash commits to what a LAX decoder reads (UInt32(_:radix:) takes "+41"; others dropped): only the
                // rule, not a hash mismatch, can make this FAIL
                let lax = UInt32(String(d), radix: 16).flatMap { UnicodeScalar($0) }.map { String($0) } ?? ""
                XCTAssertEqual(verdict(one(canon: "{\"k\":\(py(lax))}", raw: "{\"k\":\"\\u\(String(d))\"}")), "FAIL", "\\u\(String(d))")
            }
        }
        for short in ["\\u", "\\u1", "\\u12", "\\u123"] {
            XCTAssertEqual(verdict(one(canon: "{\"k\":\"x\"}", raw: "{\"k\":\"\(short)\"}")), "FAIL", short)
        }
    }

    func testSurrogateFamily() {
        var r = SplitMix64(state: 7)
        var cps: [UInt32] = [0x10000, 0x1F600, 0x10FFFF, 0x1D11E]
        for _ in 0..<200 { cps.append(0x10000 + UInt32(r.below(0x100000))) }
        for cp in cps {
            let v = cp - 0x10000, hi = 0xD800 + (v >> 10), lo = 0xDC00 + (v & 0x3FF)
            let canon = "{\"k\":\(py(String(UnicodeScalar(cp)!)))}"
            for fmt in ["\\u%04x\\u%04x", "\\u%04X\\u%04X", "\\u%04x\\u%04X"] {
                let pair = String(format: fmt, hi, lo)
                XCTAssertEqual(verdict(one(canon: canon, raw: "{\"k\":\"\(pair)\"}")), "PASS", pair)
            }
            XCTAssertEqual(verdict(one(canon: canon, raw: "{\"k\":\"\(String(UnicodeScalar(cp)!))\"}")), "PASS", "raw U+\(String(cp, radix: 16))")
            let H = String(format: "\\u%04x", hi), L = String(format: "\\u%04x", lo)
            // (raw text, what a decoder that DROPS the unpaired escape reads): the hash commits to the latter, so only the
            // rule can make the line FAIL
            for (bad, dropped) in [(H, ""), (L, ""), ("\(L)\(H)", ""), ("\(H)x", "x"), ("\(H)\(H)", ""), ("\(H)\\u0041", "A"),
                                   ("\(H)\\n", "\n"), ("x\(L)", "x"), ("\(H) \(L)", " ")] {
                XCTAssertEqual(verdict(one(canon: "{\"k\":\(py(dropped))}", raw: "{\"k\":\"\(bad)\"}")), "FAIL", bad)
                XCTAssertEqual(verdict(one(canon: "{\(py(dropped)):1}", raw: "{\"\(bad)\":1}")), "FAIL", "key \(bad)")
            }
        }
        // a high surrogate followed by an escape that is NOT \u, then the four hex digits of a low one: never a pair. The
        // hash commits to the pair a decoder that only looks for the backslash would build
        for cp: UInt32 in [0x10000, 0x1F600, 0x10FFFF] {
            let v = cp - 0x10000, hi = 0xD800 + (v >> 10), lo = 0xDC00 + (v & 0x3FF)
            let canon = "{\"k\":\(py(String(UnicodeScalar(cp)!)))}"
            for esc in ["\\\\", "\\/", "\\n", "\\\"", "\\t", "\\b"] {
                let raw = String(format: "\\u%04x", hi) + esc + String(format: "%04x", lo)
                XCTAssertEqual(verdict(one(canon: canon, raw: "{\"k\":\"\(raw)\"}")), "FAIL", raw)
            }
        }
    }

    // MARK: lines — LF is the only separator; blank = ASCII space/tab/CR only; graphemes never decide

    func testLineEndingFamily() {
        let c = chain(3)
        for sep in ["\n", "\r\n", " \n", "\t\r\n", "\r\r\n", "\n\n", "\n \t\r\n", "\r\n\r\n"] {
            XCTAssertEqual(verdict(c.joined(separator: sep)), "PASS", "separator \(sep.debugDescription)")
            XCTAssertEqual(verdict(c.joined(separator: sep) + sep), "PASS", "trailing \(sep.debugDescription)")
            XCTAssertEqual(verdict(sep + c.joined(separator: sep)), "PASS", "leading \(sep.debugDescription)")
        }
        XCTAssertEqual(verdict(c[0] + "\n" + c[1] + "\r\n" + c[2] + "\r"), "PASS", "mixed LF / CRLF / trailing CR")
        for sep in ["\r", "\u{0085}", "\u{2028}", "\u{2029}", "\u{000B}", "\u{000C}", "\u{00A0}\n"] {
            XCTAssertEqual(verdict(c.joined(separator: sep)), "FAIL", "not a separator: \(sep.debugDescription)")
        }
        for blank in ["\u{00A0}", "\u{2003}", "\u{FEFF}", "\u{000B}"] {
            XCTAssertEqual(verdict(blank + "\n" + c.joined(separator: "\n")), "FAIL", "not blank: \(blank.debugDescription)")
        }
    }

    func testGraphemeAndKeyEqualityFamily() {
        // keys the reference keeps apart (Python compares str by code point; Swift String == is canonical equivalence)
        for (a, b) in [("\u{E9}", "e\u{301}"), ("K", "\u{212A}"), ("\u{C5}", "\u{212B}"), ("\u{3A9}", "\u{2126}"), ("\u{1E69}", "s\u{323}\u{307}")] {
            let canonKeys = [a, b].sorted { $0.unicodeScalars.map { $0.value }.lexicographicallyPrecedes($1.unicodeScalars.map { $0.value }) }
            let canon = "{\(py(canonKeys[0])):1,\(py(canonKeys[1])):2}"
            let raw = "{\"\(canonKeys[0])\":1,\"\(canonKeys[1])\":2}"
            XCTAssertEqual(verdict(one(canon: canon, raw: raw)), "PASS", "distinct keys \(a.unicodeScalars.map { $0.value }) / \(b.unicodeScalars.map { $0.value })")
            XCTAssertEqual(verdict(one(canon: canon, raw: canon)), "PASS", "distinct escaped keys")
        }
        // a combining mark right after a structural quote (one grapheme with it): still a quote
        for mark in ["\u{301}", "\u{20DD}", "\u{FE0F}", "\u{200D}"] {
            let canon = "{\"k\":\(py(mark + "x"))}"
            XCTAssertEqual(verdict(one(canon: canon, raw: "{\"k\":\"\(mark)x\"}")), "PASS", "mark \(mark.unicodeScalars.first!.value) after a quote")
            let kc = "{\(py(mark)):1}"
            XCTAssertEqual(verdict(one(canon: kc, raw: "{\"\(mark)\":1}")), "PASS", "key made of a mark")
        }
        // real duplicates stay refused, escaped or not
        XCTAssertEqual(verdict(one(canon: "{\"a\":1}", raw: "{\"a\":1,\"\\u0061\":2}")), "FAIL")
        XCTAssertEqual(verdict(one(canon: "{\"\\u00e9\":1}", raw: "{\"\u{E9}\":1,\"\\u00e9\":2}")), "FAIL")
    }

    // MARK: whitespace between tokens — JSON whitespace is space, tab, CR (LF ends the line); nothing else

    func testWhitespaceBetweenTokensFamily() {
        let canon = "{\"k\":[1,2]}"
        let at = ["{%@\"k\":[1,2]}", "{\"k\"%@:[1,2]}", "{\"k\":%@[1,2]}", "{\"k\":[%@1,2]}", "{\"k\":[1%@,2]}", "{\"k\":[1,2]%@}"]
        func line(_ ws: String, _ tpl: String) -> String { one(canon: canon, raw: tpl.replacingOccurrences(of: "%@", with: ws)) }
        for tpl in at {
            for ws in [" ", "\t", "\r", " \t\r "] { XCTAssertEqual(verdict(line(ws, tpl)), "PASS", "\(ws.debugDescription) in \(tpl)") }   // control
            for ws in ["\u{0C}", "\u{0B}", "\u{00}", "\u{A0}", "\u{85}", "\u{2028}", "\u{3000}", "\u{FEFF}", "\u{200B}", "\u{1680}"] {
                XCTAssertEqual(verdict(line(ws, tpl)), "FAIL", "U+\(String(ws.unicodeScalars.first!.value, radix: 16)) in \(tpl)")
            }
        }
    }

    // MARK: nesting — MAX_JSON_DEPTH = 512 for the whole line (the entry object is level 1)

    func testDepthFamily() {
        for (levels, want) in [(510, "PASS"), (511, "PASS"), (512, "FAIL"), (600, "FAIL"), (2000, "FAIL")] {   // line = levels + 1
            for (open, close) in [("{\"x\":", "}"), ("[", "]")] {
                var canon = "1"
                for _ in 0..<(levels - 1) { canon = open + canon + close }
                canon = "{\"x\":" + canon + "}"
                XCTAssertEqual(verdict(one(canon: canon, raw: canon)), want, "data nested \(levels) with \(open)")
            }
        }
        // the bound is on DEPTH, not on the number of containers: 600 siblings, and two branches 500 deep, are in profile
        let siblings = [String](repeating: "[]", count: 600).joined(separator: ","), objs = [String](repeating: "{}", count: 600).joined(separator: ",")
        var branch = "1"
        for _ in 0..<500 { branch = "[" + branch + "]" }
        for canon in ["{\"x\":[\(siblings)]}", "{\"x\":[\(objs)]}", "{\"x\":[\(branch),\(branch)]}"] {
            XCTAssertEqual(verdict(one(canon: canon, raw: canon)), "PASS", "many containers, shallow")
        }
    }

    // MARK: Ed25519 fields — strict like signer.py: signature = canonical base64 of 64 bytes, signer = 64 lowercase hex

    func testSignatureFieldStrictness() throws {
        var key = Curve25519.Signing.PrivateKey()
        while key.publicKey.rawRepresentation.first! >= 0x10 { key = Curve25519.Signing.PrivateKey() }   // for the "+X" form
        let pkHex = key.publicKey.rawRepresentation.map { String(format: "%02x", $0) }.joined()
        let e = entry(0, Self.Z, canon: "{\"i\":0}", raw: "{\"i\":0}")
        let sig = try key.signature(for: Data(e.hash.utf8))
        let b64 = sig.base64EncodedString()
        func signed(_ s: String, _ signer: String) -> String {
            String(e.line.dropLast()) + ",\"signature\":\"\(s)\",\"signer\":\"\(signer)\"}"
        }
        let good = CryptoValidVerifier.verify(ledgerText: signed(b64, pkHex))
        XCTAssertEqual(good.verdict, "PASS"); XCTAssertEqual(good.signatures_all_verified, true)   // control
        XCTAssertEqual(CryptoValidVerifier.verify(ledgerText: signed(b64, pkHex), expectedPubkeyHex: pkHex).signatures_all_verified, true)
        let plusHex = "+" + pkHex.dropFirst()        // first byte < 0x10: "0X" -> "+X" is the same byte for UInt8(_:radix:)
        var b = Array(b64); let last = b.count - 3   // 64 bytes = 86 chars + "==": the last data char carries 4 zero bits
        let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")
        let pos = alphabet.firstIndex(of: b[last])!
        b[last] = alphabet[(pos & ~0xF) | ((pos + 1) & 0xF)]
        let nonCanonical = String(b)
        let cases: [(String, String, String)] = [
            (b64, pkHex.uppercased(), "uppercase signer"), (b64, plusHex, "signer with '+'"), (b64, " " + pkHex.dropFirst(), "signer with a space"),
            (b64, pkHex + "00", "signer 33 bytes"), (b64, String(pkHex.dropLast(2)), "signer 31 bytes"),
            (nonCanonical, pkHex, "non-canonical padding bits"), (String(b64.dropLast(2)), pkHex, "no padding"),
            (b64.replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_"), pkHex, "URL alphabet"),
            (" " + b64, pkHex, "leading space"), (b64 + "\n", pkHex, "trailing newline escaped"),
        ]
        // --pubkey is a constraint on the VERDICT (JS, Go, Java, signer.py): wrong key, unsigned, partly signed = FAIL
        let other = Curve25519.Signing.PrivateKey().publicKey.rawRepresentation.map { String(format: "%02x", $0) }.joined()
        let wrong = CryptoValidVerifier.verify(ledgerText: signed(b64, pkHex), expectedPubkeyHex: other)
        XCTAssertEqual(wrong.verdict, "FAIL"); XCTAssertEqual(wrong.chain_integrity, true); XCTAssertEqual(wrong.signatures_all_verified, false)
        let unsignedPinned = CryptoValidVerifier.verify(ledgerText: e.line, expectedPubkeyHex: pkHex)
        XCTAssertEqual(unsignedPinned.verdict, "FAIL", "unsigned + --pubkey")
        XCTAssertEqual(unsignedPinned.signatures_all_verified, false, "unsigned + --pubkey: the layer is checked, as JS all_verified false")
        XCTAssertEqual(CryptoValidVerifier.verify(ledgerText: e.line).verdict, "PASS", "unsigned, no key: control")
        XCTAssertEqual(CryptoValidVerifier.verify(ledgerText: signed(b64, pkHex), expectedPubkeyHex: pkHex).verdict, "PASS", "right key: control")
        for (s, signer, why) in cases where !(s == b64 && signer == pkHex) {
            let text = signed(s.replacingOccurrences(of: "\n", with: "\\n"), signer)
            let r = CryptoValidVerifier.verify(ledgerText: text)
            XCTAssertEqual(r.signatures_all_verified, false, why)
            // 0.21.0 (SPEC v0.4 §5 step 5): without --pubkey a layer that does not verify is a FAIL (until 0.20.3 informational)
            XCTAssertEqual(r.verdict, "FAIL", "\(why): a signature layer that does not verify, no key")
            XCTAssertEqual(r.chain_integrity, true, why)
        }
    }
}

// MARK: - the cvverify binary: bytes that are not UTF-8, and the CLI grammar

final class CLIFamilyTests: XCTestCase {
    /// The cvverify executable next to the test bundle (`swift test` builds it), or $CVVERIFY_BIN. Absent = a FAILED
    /// test, never a skip: a missing binary must not turn into a green suite.
    func binary() throws -> URL {
        if let p = ProcessInfo.processInfo.environment["CVVERIFY_BIN"] { return URL(fileURLWithPath: p) }
        let u = Bundle.module.bundleURL.deletingLastPathComponent().appendingPathComponent("cvverify")
        guard FileManager.default.isExecutableFile(atPath: u.path) else { XCTFail("cvverify not built at \(u.path)"); throw CocoaError(.fileNoSuchFile) }
        return u
    }
    func run(_ args: [String]) throws -> (code: Int32, out: String) {
        let p = Process(); p.executableURL = try binary(); p.arguments = args
        let o = Pipe(); p.standardOutput = o; p.standardError = Pipe()
        try p.run(); let data = o.fileHandleForReading.readDataToEndOfFile(); p.waitUntilExit()
        return (p.terminationStatus, String(decoding: data, as: UTF8.self))
    }
    func write(_ bytes: [UInt8]) throws -> String {
        let u = FileManager.default.temporaryDirectory.appendingPathComponent("cvverify-\(UUID().uuidString).jsonl")
        try Data(bytes).write(to: u); addTeardownBlock { try? FileManager.default.removeItem(at: u) }
        return u.path
    }
    func verdict(_ out: String) -> String? {
        guard let o = try? JSONSerialization.jsonObject(with: Data(out.utf8)) as? [String: Any] else { return nil }
        return o["verdict"] as? String
    }
    func validEntry(_ value: String, raw: String? = nil) -> [UInt8] {
        let canon = "{\"data\":{\"k\":\(value)},\"idx\":0,\"prev_hash\":\"\(String(repeating: "0", count: 64))\",\"ts\":\"t\"}"
        let h = SHA256.hash(data: Data(canon.utf8)).map { String(format: "%02x", $0) }.joined()
        return Array("{\"idx\":0,\"ts\":\"t\",\"data\":{\"k\":\(raw ?? value)},\"prev_hash\":\"\(String(repeating: "0", count: 64))\",\"self_hash\":\"\(h)\"}\n".utf8)
    }

    func testNonUTF8BytesAreFAILNotFileError() throws {
        let base = validEntry("\"\\u00e9\"")
        let ok = try run([try write(base)])
        XCTAssertEqual(ok.code, 0); XCTAssertEqual(verdict(ok.out), "PASS")                           // control
        let raw = try run([try write(validEntry("\"\\u00e9\\ud83d\\ude00\"", raw: "\"\u{E9}\u{1F600}\""))])   // raw multibyte UTF-8
        XCTAssertEqual(raw.code, 0); XCTAssertEqual(verdict(raw.out), "PASS")                         // control
        let invalid: [[UInt8]] = [[0xFF], [0xFE], [0x80], [0xBF], [0xC0, 0x80], [0xC1, 0xBF], [0xE0, 0x80, 0x80], [0xED, 0xA0, 0x80],
                                  [0xED, 0xBF, 0xBF], [0xF4, 0x90, 0x80, 0x80], [0xF5, 0x80, 0x80, 0x80], [0xE2, 0x82], [0xF0, 0x9F, 0x98], [0xC3]]
        let positions = [0, 1, 8, base.count / 2, base.count - 2, base.count - 1, base.count]   // start, key, value, end, after LF
        for seq in invalid {
            for p in positions {
                var b = base; b.insert(contentsOf: seq, at: p)
                let r = try run([try write(b)])
                XCTAssertEqual(r.code, 1, "bytes \(seq) at \(p)")
                XCTAssertEqual(verdict(r.out), "FAIL", "bytes \(seq) at \(p)")
            }
        }
        // a value whose self_hash was computed over U+FFFD, the byte 0xFF where it stood: a lossy decoder would say PASS
        let fffd = validEntry("\"\\ufffd\""); var lossy = fffd
        let marker = Array("\\ufffd".utf8)
        if let at = (0...(lossy.count - marker.count)).first(where: { Array(lossy[$0..<$0 + marker.count]) == marker }) {
            lossy.replaceSubrange(at..<at + marker.count, with: [0xFF])
        }
        let r = try run([try write(lossy)])
        XCTAssertEqual(r.code, 1); XCTAssertEqual(verdict(r.out), "FAIL")
        // a truncated sequence that decodes to ONE U+FFFD of the same byte length (3): a length check cannot see it, only
        // the byte-for-byte round trip can
        for seq: [UInt8] in [[0xF0, 0x9F, 0x98], [0xF4, 0x8F, 0xBF], [0xF0, 0x90, 0x80], [0xE2, 0x82]] {
            var t = fffd
            if let at = (0...(t.count - marker.count)).first(where: { Array(t[$0..<$0 + marker.count]) == marker }) {
                t.replaceSubrange(at..<at + marker.count, with: seq)
            }
            let rr = try run([try write(t)])
            XCTAssertEqual(rr.code, 1, "bytes \(seq) hashed as U+FFFD"); XCTAssertEqual(verdict(rr.out), "FAIL", "bytes \(seq) hashed as U+FFFD")
        }
        // a UTF-8 BOM is not JSON whitespace (Python: "Unexpected UTF-8 BOM")
        let bom = try run([try write([0xEF, 0xBB, 0xBF] + base)])
        XCTAssertEqual(bom.code, 1); XCTAssertEqual(verdict(bom.out), "FAIL")
    }

    /// 0.20.3: a receipt that is not written whole is exit 74 with one stderr line, whatever the verdict. On 0.20.2 the
    /// CLI used print + exit: /dev/full and a closed stdout exited with the verdict's code (0/1) and nothing said, a
    /// reader gone was a SIGPIPE death (141 in a shell). Real processes: stdout on /dev/full (ENOSPC), on a pipe whose
    /// read end is closed before the start (EPIPE), and closed (`exec >&-`, EBADF: Swift does not reopen fd 1).
    func testReceiptNotWrittenIsExit74() throws {
        let valid = try write(validEntry("1"))
        var tampered = validEntry("1"); tampered[tampered.count - 3] = UInt8(ascii: "0") == tampered[tampered.count - 3] ? UInt8(ascii: "1") : UInt8(ascii: "0")
        let invalid = try write(tampered)
        let missing = FileManager.default.temporaryDirectory.appendingPathComponent("cvverify-missing-\(UUID().uuidString)").path
        for (path, code) in [(valid, Int32(0)), (invalid, Int32(1)), (missing, Int32(2))] {
            let ctl = try run([path])
            XCTAssertEqual(ctl.code, code, "control \(path)"); XCTAssertNotNil(verdict(ctl.out), "control \(path)")
            for mode in ["devfull", "epipe", "closed"] {
                let p = Process(); let e = Pipe()
                if mode == "closed" {
                    p.executableURL = URL(fileURLWithPath: "/bin/sh")
                    p.arguments = ["-c", "exec \"$0\" \"$1\" >&-", try binary().path, path]
                } else {
                    p.executableURL = try binary(); p.arguments = [path]
                }
                if mode == "devfull" {
                    // macOS has no /dev/full: that mode is Linux only (the CI's macOS job runs the other two)
                    guard let full = FileHandle(forWritingAtPath: "/dev/full") else { continue }
                    p.standardOutput = full
                } else if mode == "epipe" {
                    let o = Pipe(); try o.fileHandleForReading.close(); p.standardOutput = o
                }
                p.standardError = e
                try p.run()
                let err = String(decoding: e.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
                p.waitUntilExit()
                XCTAssertEqual(p.terminationReason, .exit, "\(mode) \(path): killed by a signal")
                XCTAssertEqual(p.terminationStatus, 74, "\(mode) \(path): stderr \(err)")
                XCTAssertTrue(err.hasPrefix("receipt not written: "), "\(mode) \(path): stderr \(err)")
            }
            // stderr full too: nowhere to say why, the exit is still 74 (FileHandle.write trapped here: SIGILL); Linux only
            let q = Process(); q.executableURL = try binary(); q.arguments = [path]
            guard let o2 = FileHandle(forWritingAtPath: "/dev/full"), let e2 = FileHandle(forWritingAtPath: "/dev/full") else { continue }
            q.standardOutput = o2; q.standardError = e2
            try q.run(); q.waitUntilExit()
            XCTAssertEqual(q.terminationReason, .exit, "stdout+stderr full \(path): killed by a signal")
            XCTAssertEqual(q.terminationStatus, 74, "stdout+stderr full \(path)")
        }
    }

    func testCLIGrammarFamily() throws {
        let v = try write(validEntry("1"))
        for good in [[v], [v, "--algo", "sha256"], [v, "--algo", "sha3_256", "--algo", "sha256"], [v, "--pubkey", "ab"],
                     [v, "--algo", "sha256", "--pubkey", "ab"]] {
            let r = try run(good)
            XCTAssertEqual(r.code, (good.contains("sha3_256") && good.last == "sha3_256") || good.contains("--pubkey") ? 1 : 0, "\(good)")   // --pubkey on an unsigned ledger: a verdict, FAIL
            XCTAssertNotNil(verdict(r.out), "\(good)")
        }
        var usageForms: [[String]] = [[], ["--algo", "sha256"], ["-"], ["--"], [v, v], [v, "x"], [v, "-"], [v, "--"],
                                      [v, "--algo=sha256"], [v, "--ALGO", "sha256"], [v, "--alg", "sha256"], [v, "-algo", "sha256"]]
        for flag in ["--algo", "--pubkey"] {
            usageForms += [[v, flag], [v, flag, ""], [v, flag, "-x"], [v, flag, "--algo"], [v, flag, "--pubkey"]]
        }
        for algo in ["foo", "SHA256", "sha3-256", "sha256 ", "sha512", "md5"] { usageForms.append([v, "--algo", algo]) }
        for unknown in ["--no-such-flag", "--trusted-pubkey", "--tip", "--quiet", "-h", "--help", "--json", "-x"] {
            usageForms += [[v, unknown], [v, unknown, "ab"]]
        }
        for form in usageForms {
            let r = try run(form)
            XCTAssertEqual(r.code, 2, "usage expected for \(form)")
            XCTAssertNil(verdict(r.out), "no verdict for \(form)")
        }
    }

    /// bash -c `script` with $0 = the binary, $1… = args; (status, terminated by a signal?, stdout, stderr)
    func shell(_ script: String, _ args: [String]) throws -> (code: Int32, signaled: Bool, out: String, err: String) {
        let p = Process(); p.executableURL = URL(fileURLWithPath: "/bin/bash")
        p.arguments = ["-c", script, try binary().path] + args
        let o = Pipe(), e = Pipe(); p.standardOutput = o; p.standardError = e
        try p.run()
        let od = o.fileHandleForReading.readDataToEndOfFile(), ed = e.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        return (p.terminationStatus, p.terminationReason == .uncaughtSignal, String(decoding: od, as: UTF8.self), String(decoding: ed, as: UTF8.self))
    }

    /// 0.20.3 (13/10): usage with stderr full or closed keeps exit 2 (FileHandle.write trapped: SIGILL, 132), nothing on stdout
    func testUsageWithStderrLostIsExit2() throws {
        // macOS has no /dev/full (a redirection to it fails in the shell, exit 1): that case is Linux only
        for redirect in (FileManager.default.fileExists(atPath: "/dev/full") ? ["2>/dev/full", "2>&-"] : ["2>&-"]) {
            for args in [[String](), ["x.jsonl", "--bogus"]] {
                let r = try shell("exec \"$0\" \"$@\" \(redirect)", args)
                XCTAssertFalse(r.signaled, "usage \(args) \(redirect): killed by a signal")
                XCTAssertEqual(r.code, 2, "usage \(args) \(redirect)")
                XCTAssertEqual(r.out, "", "usage \(args) \(redirect): stdout")
            }
        }
    }

    /// 0.20.3 (13/10): a regular file that stops growing (bash `ulimit -f 1` with 24 bytes left, `ulimit -f 0`) is exit 74
    /// with one line (SIGXFSZ killed the process before: no exit code). The case with 24 bytes left runs on Linux only: on
    /// the macOS CI runner (13/10/2026, run 38403932117) it exited 0 with nothing on stderr, while `ulimit -f 0` gave 74.
    /// 0.21.0, read in the XNU source, not measured on a Mac (bsd/vfs/vfs_vnops.c vn_write, xnu-12377.1.9, commit f6217f89):
    /// XNU compares RLIMIT_FSIZE with the OFFSET of the descriptor, not with the end of the file, also under O_APPEND
    /// (VNOP_WRITE moves to the end afterwards); `>>` opens at offset 0, so 0 + 194 bytes of receipt <= 1024 passes and the
    /// receipt is appended WHOLE past the limit: exit 0 is right there. A write that crosses the limit from that offset is
    /// shortened, and the next one, at the end of the file, is EFBIG: 74 (testFileSizeLimitMacOS asserts both on macOS)
    func testFileSizeLimitIsExit74() throws {
        let v = try write(validEntry("1"))
        #if os(Linux)
        let cases = [(1, 1000), (0, 0)]
        #else
        let cases = [(0, 0)]
        #endif
        for (blocks, prefill) in cases {
            let f = try write(Array(repeating: UInt8(ascii: "x"), count: prefill))
            let r = try shell("ulimit -f \(blocks); exec \"$0\" \"$1\" >>\"$2\"", [v, f])
            XCTAssertFalse(r.signaled, "ulimit -f \(blocks): killed by a signal")
            XCTAssertEqual(r.code, 74, "ulimit -f \(blocks): stderr \(r.err)")
            XCTAssertTrue(r.err.hasPrefix("receipt not written: "), "ulimit -f \(blocks): \(r.err)")
        }
    }

    #if os(macOS)
    /// 0.21.0: the expectation derived from XNU's vn_write (see above), asserted where it applies: appended to 1000 bytes
    /// under `ulimit -f 1` (1024 bytes in bash), exit 0 and the receipt whole after the 1000 bytes.
    func testFileSizeLimitMacOS() throws {
        let v = try write(validEntry("1"))
        let whole = try run([v])
        let f = try write(Array(repeating: UInt8(ascii: "x"), count: 1000))
        let a = try shell("ulimit -f 1; exec \"$0\" \"$1\" >>\"$2\"", [v, f])
        XCTAssertFalse(a.signaled); XCTAssertEqual(a.code, 0, a.err)
        let got = try Data(contentsOf: URL(fileURLWithPath: f))
        XCTAssertEqual(got.count, 1000 + whole.out.utf8.count)
        XCTAssertEqual(String(decoding: got.suffix(whole.out.utf8.count), as: UTF8.self), whole.out)
    }
    #endif

    /// 0.21.0: a receipt longer than the limit, written from offset 0 (`>`): shortened to the limit, then EFBIG — 74 on Linux
    /// (measured) and, by XNU's vn_write, on macOS too (the CI job measures it)
    func testFileSizeLimitCrossedFromOffsetZeroIs74() throws {
        var lines = ""
        for i in 0..<200 { lines += "{\"idx\":\(i),\"ts\":\"t\",\"data\":{},\"prev_hash\":\"\(String(repeating: "1", count: 64))\",\"self_hash\":\"\(String(repeating: "7", count: 64))\"}\n" }
        let big = try write(Array(lines.utf8))
        let g = try write([])
        let b = try shell("ulimit -f 1; exec \"$0\" \"$1\" >\"$2\"", [big, g])
        XCTAssertFalse(b.signaled); XCTAssertEqual(b.code, 74, b.err)
        XCTAssertTrue(b.err.hasPrefix("receipt not written: "), b.err)
        XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: g)).count, 1024)
    }

    /// 0.20.3 (13/10): a NON-BLOCKING stdout read once the pipe is full gets a receipt larger than the pipe buffer whole, exit 1 (it was
    /// 74 with 65 536 bytes in the pipe: fwrite reported EAGAIN as a lost receipt)
    func testNonBlockingStdoutReadLateIsWhole() throws {
        var lines = ""
        for i in 0..<20000 {
            lines += "{\"idx\":\(i),\"ts\":\"t\",\"data\":{\"e\":\(i)},\"prev_hash\":\"\(String(repeating: "1", count: 64))\",\"self_hash\":\"\(String(repeating: "7", count: 64))\"}\n"
        }
        let big = try write(Array(lines.utf8))
        let py = "import fcntl,os,subprocess,sys,time\nr,w=os.pipe()\nfcntl.fcntl(w,fcntl.F_SETFL,fcntl.fcntl(w,fcntl.F_GETFL)|os.O_NONBLOCK)\np=subprocess.Popen(sys.argv[1:],stdout=w)\nos.close(w)\nimport array,termios\ntry:\n    cap=fcntl.fcntl(r,1032)\nexcept OSError:\n    cap=0\nlast=-1\nt0=time.time()\nwhile p.poll() is None and time.time()-t0<60:\n    n=array.array('i',[0]); fcntl.ioctl(r,termios.FIONREAD,n,True)\n    if n[0]>=cap or (cap==0 and n[0]>0 and n[0]==last): break\n    last=n[0]; time.sleep(0.25 if cap==0 else 0.02)\ntime.sleep(0.3)\nb=b''\nwhile True:\n    c=os.read(r,65536)\n    if not c: break\n    b+=c\nrc=p.wait()\nsys.stdout.write('%d %d %d' % (rc, len(b), b.count(b'\"verdict\"')))\n"
        let r = try shell("exec python3 -c \"$1\" \"$0\" \"$2\"", [py, big])
        let v = r.out.split(separator: " ").compactMap { Int($0) }
        XCTAssertEqual(v.count, 3, "driver output \(r.out) \(r.err)")
        if v.count == 3 {
            XCTAssertEqual(v[0], 1, "exit code: \(r.out)")
            XCTAssertTrue(v[1] > 65536 && v[2] == 1, "receipt not whole: \(r.out)")
        }
    }

    /// review of 0.20.3, 13/10: the receipt ends with its newline (print wrote one; a mutant without it passed every test above)
    func testReceiptEndsWithNewline() throws {
        let r = try run([try write(validEntry("1"))])
        XCTAssertEqual(r.code, 0); XCTAssertTrue(r.out.hasSuffix("}\n"), "receipt end: \(r.out.suffix(4).debugDescription)")
    }

    #if os(Linux)
    /// review of 0.20.3, 13/10 (Linux: /proc, F_GETPIPE_SZ): waiting on a full non-blocking stdout sleeps in poll: under 0.3 s of CPU
    /// in 2 s of waiting (poll with timeout 0 spun at 100 %), and the receipt is whole once read
    func testWaitingOnAFullStdoutDoesNotSpin() throws {
        var lines = ""
        for i in 0..<20000 {
            lines += "{\"idx\":\(i),\"ts\":\"t\",\"data\":{\"e\":\(i)},\"prev_hash\":\"\(String(repeating: "1", count: 64))\",\"self_hash\":\"\(String(repeating: "7", count: 64))\"}\n"
        }
        let big = try write(Array(lines.utf8))
        let py = "import array,fcntl,os,subprocess,sys,termios,time\nr,w=os.pipe()\nfcntl.fcntl(w,fcntl.F_SETFL,fcntl.fcntl(w,fcntl.F_GETFL)|os.O_NONBLOCK)\np=subprocess.Popen(sys.argv[1:],stdout=w)\nos.close(w)\ncap=fcntl.fcntl(r,1032);t0=time.time()\nwhile p.poll() is None and time.time()-t0<60:\n    n=array.array('i',[0]); fcntl.ioctl(r,termios.FIONREAD,n,True)\n    if n[0]>=cap: break\n    time.sleep(0.02)\ntime.sleep(0.3)\ndef cpu():\n    f=open('/proc/%d/stat'%p.pid).read().rsplit(')',1)[1].split(); return (int(f[11])+int(f[12]))/os.sysconf('SC_CLK_TCK')\nc1=cpu(); time.sleep(2); c2=cpu()\nb=b''\nwhile True:\n    c=os.read(r,65536)\n    if not c: break\n    b+=c\nsys.stdout.write('%d %d %.3f' % (p.wait(), len(b), c2-c1))\n"
        let r = try shell("exec python3 -c \"$1\" \"$0\" \"$2\"", [py, big])
        let v = r.out.split(separator: " ").compactMap { Double($0) }
        XCTAssertEqual(v.count, 3, "driver output \(r.out) \(r.err)")
        if v.count == 3 {
            XCTAssertEqual(Int(v[0]), 1, "exit code: \(r.out)")
            XCTAssertTrue(v[1] > 65536, "receipt not whole: \(r.out)")
            XCTAssertTrue(v[2] < 0.3, "CPU while waiting: \(r.out)")
        }
    }

    /// review of 0.20.3, 13/10 (Linux, needs cc): write(2) taking 0 bytes is exit 74; an EINTR is retried and the receipt is whole
    func testZeroWriteIs74AndEintrIsRetried() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("cvverify-shim-\(UUID().uuidString)").path
        try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        let src = "#define _GNU_SOURCE\n#include <dlfcn.h>\n#include <errno.h>\n#include <stdlib.h>\n#include <unistd.h>\nstatic int d0,di;\nssize_t write(int fd,const void*b,size_t n){static ssize_t(*r)(int,const void*,size_t);if(!r)r=dlsym(RTLD_NEXT,\"write\");\nif(fd==1&&n&&getenv(\"SHIM_W0\")&&!d0){d0=1;return 0;}\nif(fd==1&&n&&getenv(\"SHIM_WI\")&&!di){di=1;errno=EINTR;return -1;}\nreturn r(fd,b,n);}\n"
        try src.write(toFile: dir + "/shim.c", atomically: true, encoding: .utf8)
        let cc = try shell("cc -shared -fPIC -o \"$1/shim.so\" \"$1/shim.c\" -ldl", [dir])
        if cc.code != 0 { throw XCTSkip("no C compiler") }
        let v = try write(validEntry("1"))
        let ctl = try run([v])
        let z = try shell("LD_PRELOAD=\"$1/shim.so\" SHIM_W0=1 exec \"$0\" \"$2\"", [dir, v])
        XCTAssertEqual(z.code, 74, "write 0: \(z.err)"); XCTAssertTrue(z.err.hasPrefix("receipt not written: short write"), z.err)
        let i = try shell("LD_PRELOAD=\"$1/shim.so\" SHIM_WI=1 exec \"$0\" \"$2\"", [dir, v])
        XCTAssertEqual(i.code, 0, "EINTR: \(i.err)"); XCTAssertEqual(i.out, ctl.out, "EINTR: receipt not whole")
        try? FileManager.default.removeItem(atPath: dir)
    }
    #endif
}
