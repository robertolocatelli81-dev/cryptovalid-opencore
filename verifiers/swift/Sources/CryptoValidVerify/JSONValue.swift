// Minimal, deterministic JSON model + canonical encoder.
// CryptoValid's self_hash is over Python's json.dumps(sort_keys=True,
// separators=(",",":"), ensure_ascii=True). Foundation's JSONSerialization does
// not guarantee key order or ASCII escaping and mangles number types, so we parse
// into an ordered-free model and re-serialise canonically ourselves. This encoder
// is the twin of the reference on the acceptance profile (verified by differential_oracle.py).
//
// The parser reads Unicode SCALARS, never Swift `Character`s: a Character is a grapheme cluster ("\r\n" is ONE
// Character, a quote followed by a combining mark is ONE Character) and String equality is canonical equivalence
// ("é" == "e\u{301}"). Both made this parser disagree with the reference (CRLF refused; two keys the reference keeps
// apart taken as duplicates). Keys are therefore compared scalar by scalar (`JSONKey`), as Python compares str.
// Acceptance profile (the same rules as verifier.py, JS, Go, Java and Rust; spec/CONFORMANCE.md):
//   - numbers: RFC 8259 integers only, -?(0|[1-9][0-9]*), within +/-(2^53-1); no fraction, no exponent, no '+',
//     no leading zero;
//   - strings: no raw control character U+0000..U+001F; `\u` takes exactly four ASCII hex digits; a high surrogate
//     escape must be followed at once by a low one (one scalar), anything unpaired is `lone_surrogate`;
//   - objects: no duplicate key (compared by scalars, escaped forms included);
//   - nesting: at most MAX_JSON_DEPTH arrays/objects deep (json_too_deep).
import Foundation

/// An object key compared and hashed by its Unicode scalars (Python str semantics), never by canonical equivalence.
public struct JSONKey: Hashable, Comparable, ExpressibleByStringLiteral, CustomStringConvertible {
    public let string: String
    public let scalars: [UInt32]
    public init(_ s: String) { string = s; scalars = s.unicodeScalars.map { $0.value } }
    public init(stringLiteral value: String) { self.init(value) }
    public static func == (l: JSONKey, r: JSONKey) -> Bool { l.scalars == r.scalars }
    public func hash(into h: inout Hasher) { h.combine(scalars) }
    public static func < (l: JSONKey, r: JSONKey) -> Bool { l.scalars.lexicographicallyPrecedes(r.scalars) }
    public var description: String { string }
}

/// Scalar-exact string equality (Python `==` on str). Swift's `==` on String is canonical equivalence.
public func scalarEqual(_ a: String, _ b: String) -> Bool { a.unicodeScalars.elementsEqual(b.unicodeScalars) }

public indirect enum JSONValue: Equatable {
    case null
    case bool(Bool)
    case int(Int64)          // JSON integers (CryptoValid records carry no floats)
    case double(Double)
    case string(String)
    case array([JSONValue])
    case object([JSONKey: JSONValue])

    public static func == (l: JSONValue, r: JSONValue) -> Bool {
        switch (l, r) {
        case (.null, .null): return true
        case let (.bool(a), .bool(b)): return a == b
        case let (.int(a), .int(b)): return a == b
        case let (.double(a), .double(b)): return a == b
        case let (.string(a), .string(b)): return scalarEqual(a, b)
        case let (.array(a), .array(b)): return a == b
        case let (.object(a), .object(b)): return a == b
        default: return false
        }
    }
}

public enum JSONError: Error, Equatable { case syntax(String) }

/// Normative nesting bound of the acceptance profile (spec/CONFORMANCE.md, verifier.py MAX_JSON_DEPTH): a line nested
/// deeper is refused as json_too_deep, as in Python, JS, Go, Java and Rust.
public let MAX_JSON_DEPTH = 512

public struct JSONParser {
    private let s: [Unicode.Scalar]
    private var i = 0
    private var depth = 0
    public init(_ text: String) { self.s = Array(text.unicodeScalars) }

    public static func parse(_ text: String) throws -> JSONValue {
        var p = JSONParser(text); let v = try p.value(); p.ws()
        if p.i != p.s.count { throw JSONError.syntax("trailing data") }
        return v
    }
    private func at(_ k: Int) -> Unicode.Scalar? { k < s.count ? s[k] : nil }
    private mutating func ws() { while let c = at(i), c == " " || c == "\t" || c == "\n" || c == "\r" { i += 1 } }
    private mutating func value() throws -> JSONValue {
        ws(); guard let c = at(i) else { throw JSONError.syntax("eof") }
        switch c {
        case "{", "[":
            depth += 1
            if depth > MAX_JSON_DEPTH { throw JSONError.syntax("json_too_deep: nesting exceeds \(MAX_JSON_DEPTH)") }
            let v = try (c == "{" ? object() : array())
            depth -= 1
            return v
        case "\"": return .string(try str())
        case "t": try lit("true"); return .bool(true)
        case "f": try lit("false"); return .bool(false)
        case "n": try lit("null"); return .null
        default: return try number()
        }
    }
    private mutating func lit(_ w: String) throws {
        for c in w.unicodeScalars { guard at(i) == c else { throw JSONError.syntax("literal") }; i += 1 }
    }
    private mutating func expect(_ c: Unicode.Scalar) throws {
        guard at(i) == c else { throw JSONError.syntax("expected \(c)") }; i += 1
    }
    private mutating func object() throws -> JSONValue {
        try expect("{"); var o: [JSONKey: JSONValue] = [:]; ws()
        if at(i) == "}" { i += 1; return .object(o) }
        while true {
            ws(); let k = JSONKey(try str()); ws(); try expect(":")
            if o[k] != nil { throw JSONError.syntax("duplicate key \(k.string)") }   // hash malleability guard
            o[k] = try value(); ws()
            if at(i) == "," { i += 1; continue }
            try expect("}"); return .object(o)
        }
    }
    private mutating func array() throws -> JSONValue {
        try expect("["); var a: [JSONValue] = []; ws()
        if at(i) == "]" { i += 1; return .array(a) }
        while true {
            a.append(try value()); ws()
            if at(i) == "," { i += 1; continue }
            try expect("]"); return .array(a)
        }
    }
    /// Exactly four ASCII hex digits (Foundation's UInt32(_:radix:) also took "+041", and the old code skipped a
    /// short or non-hex tail silently).
    private mutating func hex4() throws -> UInt32 {
        guard i + 4 <= s.count else { throw JSONError.syntax("bad \\u escape") }
        var v: UInt32 = 0
        for k in i..<(i + 4) {
            let c = s[k].value
            let d: UInt32
            switch c {
            case 0x30...0x39: d = c - 0x30
            case 0x41...0x46: d = c - 0x41 + 10
            case 0x61...0x66: d = c - 0x61 + 10
            default: throw JSONError.syntax("bad \\u escape")
            }
            v = v * 16 + d
        }
        i += 4
        return v
    }
    private mutating func str() throws -> String {
        try expect("\""); var out = String.UnicodeScalarView()
        while let c = at(i) {
            i += 1
            if c == "\"" { return String(out) }
            if c == "\\" {
                guard let e = at(i) else { break }
                i += 1
                switch e {
                case "n": out.append("\n"); case "t": out.append("\t"); case "r": out.append("\r")
                case "b": out.append("\u{08}"); case "f": out.append("\u{0C}")
                case "/": out.append("/"); case "\\": out.append("\\"); case "\"": out.append("\"")
                case "u":
                    let code = try hex4()
                    var scalar = code
                    if (0xD800...0xDBFF).contains(code) {          // high: needs `\u` + a low one at once
                        guard at(i) == "\\", at(i + 1) == "u" else { throw JSONError.syntax("lone_surrogate") }
                        i += 2
                        let lo = try hex4()
                        guard (0xDC00...0xDFFF).contains(lo) else { throw JSONError.syntax("lone_surrogate") }
                        scalar = 0x10000 + ((code - 0xD800) << 10) + (lo - 0xDC00)
                    } else if (0xDC00...0xDFFF).contains(code) {   // low without a preceding high
                        throw JSONError.syntax("lone_surrogate")
                    }
                    guard let sc = Unicode.Scalar(scalar) else { throw JSONError.syntax("bad scalar") }
                    out.append(sc)
                default: throw JSONError.syntax("bad escape")
                }
            } else if c.value < 0x20 {
                throw JSONError.syntax("control character in string (RFC 8259 forbids it unescaped)")
            } else { out.append(c) }
        }
        throw JSONError.syntax("unterminated string")
    }
    /// RFC 8259 integer: -?(0|[1-9][0-9]*)
    static func intGrammar(_ tok: [Unicode.Scalar]) -> Bool {
        let t = tok.first == "-" ? Array(tok.dropFirst()) : tok
        guard !t.isEmpty, t.allSatisfy({ $0.value >= 0x30 && $0.value <= 0x39 }) else { return false }
        return t.count == 1 || t[0] != "0"
    }
    private mutating func number() throws -> JSONValue {
        let start = i
        while let c = at(i), "+-0123456789.eE".unicodeScalars.contains(c) { i += 1 }
        let tok = Array(s[start..<i])
        if tok.isEmpty { throw JSONError.syntax("bad number") }
        let text = String(String.UnicodeScalarView(tok))
        if tok.contains(".") || tok.contains("e") || tok.contains("E") {
            throw JSONError.syntax("non-portable float \(text) (use a string)")   // portable profile
        }
        guard JSONParser.intGrammar(tok) else {
            throw JSONError.syntax("number \(text) is not JSON (no '+', no leading zero)")   // Int64("+10") / Int64("010") took them
        }
        guard let n = Int64(text), n.magnitude <= 9_007_199_254_740_991 else {
            throw JSONError.syntax("integer \(text) outside portable range +/-(2^53-1)")
        }
        return .int(n)
    }
}

public enum Canonical {
    /// Python-identical: sorted keys (by Unicode scalar), compact separators, ASCII escapes.
    public static func encode(_ v: JSONValue) -> String {
        switch v {
        case .null: return "null"
        case .bool(let b): return b ? "true" : "false"
        case .int(let n): return String(n)
        case .double(let d): return String(d)              // records carry no floats; kept for completeness
        case .string(let s): return escape(s)
        case .array(let a): return "[" + a.map(encode).joined(separator: ",") + "]"
        case .object(let o):
            return "{" + o.keys.sorted().map { escape($0.string) + ":" + encode(o[$0]!) }.joined(separator: ",") + "}"
        }
    }
    static func escape(_ s: String) -> String {
        var out = "\""
        for scalar in s.unicodeScalars {
            switch scalar {
            case "\"": out += "\\\""
            case "\\": out += "\\\\"
            case "\n": out += "\\n"
            case "\r": out += "\\r"
            case "\t": out += "\\t"
            case "\u{08}": out += "\\b"
            case "\u{0C}": out += "\\f"
            default:
                if scalar.value < 0x20 || scalar.value > 0x7e {
                    if scalar.value > 0xFFFF {              // surrogate pair, like Python
                        let v = scalar.value - 0x10000
                        out += String(format: "\\u%04x\\u%04x", 0xD800 + (v >> 10), 0xDC00 + (v & 0x3FF))
                    } else {
                        out += String(format: "\\u%04x", scalar.value)
                    }
                } else { out.unicodeScalars.append(scalar) }
            }
        }
        return out + "\""
    }
}
