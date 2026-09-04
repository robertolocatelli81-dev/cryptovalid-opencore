// Minimal, deterministic JSON model + canonical encoder.
// CryptoValid's self_hash is over Python's json.dumps(sort_keys=True,
// separators=(",",":"), ensure_ascii=True). Foundation's JSONSerialization does
// not guarantee key order or ASCII escaping and mangles number types, so we parse
// into an ordered-free model and re-serialise canonically ourselves. This encoder
// is the twin of the reference on the acceptance profile (floats/NaN/out-of-range ints/dup keys rejected; verified by differential_oracle.py).
import Foundation

public indirect enum JSONValue: Equatable {
    case null
    case bool(Bool)
    case int(Int64)          // JSON integers (CryptoValid records carry no floats)
    case double(Double)
    case string(String)
    case array([JSONValue])
    case object([String: JSONValue])
}

public enum JSONError: Error { case syntax(String) }

public struct JSONParser {
    private let s: [Character]
    private var i = 0
    public init(_ text: String) { self.s = Array(text) }

    public static func parse(_ text: String) throws -> JSONValue {
        var p = JSONParser(text); let v = try p.value(); p.ws()
        if p.i != p.s.count { throw JSONError.syntax("trailing data") }
        return v
    }
    private mutating func ws() { while i < s.count, " \t\n\r".contains(s[i]) { i += 1 } }
    private mutating func value() throws -> JSONValue {
        ws(); guard i < s.count else { throw JSONError.syntax("eof") }
        switch s[i] {
        case "{": return try object()
        case "[": return try array()
        case "\"": return .string(try str())
        case "t": try lit("true"); return .bool(true)
        case "f": try lit("false"); return .bool(false)
        case "n": try lit("null"); return .null
        default: return try number()
        }
    }
    private mutating func lit(_ w: String) throws {
        for c in w { guard i < s.count, s[i] == c else { throw JSONError.syntax("literal") }; i += 1 }
    }
    private mutating func expect(_ c: Character) throws {
        guard i < s.count, s[i] == c else { throw JSONError.syntax("expected \(c)") }; i += 1
    }
    private mutating func object() throws -> JSONValue {
        try expect("{"); var o: [String: JSONValue] = [:]; ws()
        if i < s.count, s[i] == "}" { i += 1; return .object(o) }
        while true {
            ws(); let k = try str(); ws(); try expect(":")
            if o[k] != nil { throw JSONError.syntax("duplicate key \(k)") }   // hash malleability guard
            o[k] = try value(); ws()
            if i < s.count, s[i] == "," { i += 1; continue }
            try expect("}"); return .object(o)
        }
    }
    private mutating func array() throws -> JSONValue {
        try expect("["); var a: [JSONValue] = []; ws()
        if i < s.count, s[i] == "]" { i += 1; return .array(a) }
        while true {
            a.append(try value()); ws()
            if i < s.count, s[i] == "," { i += 1; continue }
            try expect("]"); return .array(a)
        }
    }
    private mutating func str() throws -> String {
        try expect("\""); var out = ""
        while i < s.count {
            let c = s[i]; i += 1
            if c == "\"" { return out }
            if c == "\\" {
                guard i < s.count else { break }
                let e = s[i]; i += 1
                switch e {
                case "n": out += "\n"; case "t": out += "\t"; case "r": out += "\r"
                case "b": out += "\u{08}"; case "f": out += "\u{0C}"
                case "/": out += "/"; case "\\": out += "\\"; case "\"": out += "\""
                case "u":
                    let hex = String(s[i..<min(i+4, s.count)]); i += 4
                    if let code = UInt32(hex, radix: 16), let sc = Unicode.Scalar(code) { out.unicodeScalars.append(sc) }
                default: throw JSONError.syntax("bad escape")
                }
            } else { out.append(c) }
        }
        throw JSONError.syntax("unterminated string")
    }
    private mutating func number() throws -> JSONValue {
        let start = i
        while i < s.count, "+-0123456789.eE".contains(s[i]) { i += 1 }
        let tok = String(s[start..<i])
        if tok.isEmpty { throw JSONError.syntax("bad number") }
        if tok.contains(".") || tok.contains("e") || tok.contains("E") {
            throw JSONError.syntax("non-portable float \(tok) (use a string)")   // portable profile
        }
        guard let n = Int64(tok), abs(n) <= 9_007_199_254_740_991 else {
            throw JSONError.syntax("integer \(tok) outside portable range +/-(2^53-1)")
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
            let keys = o.keys.sorted { lhs, rhs in
                let l = Array(lhs.unicodeScalars), r = Array(rhs.unicodeScalars)
                for k in 0..<Swift.min(l.count, r.count) where l[k] != r[k] { return l[k] < r[k] }
                return l.count < r.count
            }
            return "{" + keys.map { escape($0) + ":" + encode(o[$0]!) }.joined(separator: ",") + "}"
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
