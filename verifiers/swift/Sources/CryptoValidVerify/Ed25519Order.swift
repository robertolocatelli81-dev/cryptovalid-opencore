// Ed25519 points of small and mixed order (0.21.0). swift-crypto (Linux) verified a key or an R of small order, a key of
// mixed order and a key with x = 0 and the sign bit set: measured 14/10/2026 on the 12 classes of
// novifinancial/ed25519-speccheck rebuilt on ledger entries (classes 0-3, 10, 11); the x402 acceptance checker refuses all
// 12 (b37e471). Apple's CryptoKit was not measured: the checks below run before the library on every platform, so the
// outcome does not depend on it. The key must decode as RFC 8032 5.1.3 says (y < p; x = 0 with the sign bit set refused),
// not be of small order ([8]A neutral) and lie in the subgroup of order L ([L]A neutral); R must decode and not be of small
// order (with A in the subgroup the cofactorless equation refuses an R of mixed order). Arithmetic modulo p = 2^255 - 19 on
// little-endian UInt64 limbs, written from RFC 8032 5.1 (constants, 5.1.3, 5.1.4); not constant time (public values only).
import Foundation

enum Ed25519Order {
    typealias N = [UInt64]   // little-endian limbs, any length

    static func norm(_ a: N) -> N { var a = a; while a.count > 1 && a.last == 0 { a.removeLast() }; return a.isEmpty ? [0] : a }
    static func cmp(_ a: N, _ b: N) -> Int {
        let a = norm(a), b = norm(b)
        if a.count != b.count { return a.count < b.count ? -1 : 1 }
        for i in stride(from: a.count - 1, through: 0, by: -1) where a[i] != b[i] { return a[i] < b[i] ? -1 : 1 }
        return 0
    }
    static func add(_ a: N, _ b: N) -> N {
        var r = N(repeating: 0, count: max(a.count, b.count) + 1); var c: UInt64 = 0
        for i in 0..<(r.count - 1) {
            let x = i < a.count ? a[i] : 0, y = i < b.count ? b[i] : 0
            let (s1, o1) = x.addingReportingOverflow(y); let (s2, o2) = s1.addingReportingOverflow(c)
            r[i] = s2; c = (o1 ? 1 : 0) + (o2 ? 1 : 0)
        }
        r[r.count - 1] = c; return norm(r)
    }
    static func sub(_ a: N, _ b: N) -> N {   // a >= b
        var r = a; var br: UInt64 = 0
        for i in 0..<r.count {
            let y = i < b.count ? b[i] : 0
            let (s1, o1) = r[i].subtractingReportingOverflow(y); let (s2, o2) = s1.subtractingReportingOverflow(br)
            r[i] = s2; br = (o1 ? 1 : 0) + (o2 ? 1 : 0)
        }
        return norm(r)
    }
    static func mul(_ a: N, _ b: N) -> N {
        var r = N(repeating: 0, count: a.count + b.count)
        for i in 0..<a.count {
            var carry: UInt64 = 0
            for j in 0..<b.count {
                let (hi, lo) = a[i].multipliedFullWidth(by: b[j])
                let (s1, o1) = r[i + j].addingReportingOverflow(lo); let (s2, o2) = s1.addingReportingOverflow(carry)
                r[i + j] = s2; carry = hi &+ (o1 ? 1 : 0) &+ (o2 ? 1 : 0)
            }
            r[i + b.count] = carry
        }
        return norm(r)
    }
    static func bit(_ a: N, _ i: Int) -> Bool { i / 64 < a.count && (a[i / 64] >> UInt64(i % 64)) & 1 == 1 }
    static func bitLength(_ a: N) -> Int { let a = norm(a); return (a.count - 1) * 64 + (64 - a.last!.leadingZeroBitCount) }
    static let P: N = [0xFFFF_FFFF_FFFF_FFED, 0xFFFF_FFFF_FFFF_FFFF, 0xFFFF_FFFF_FFFF_FFFF, 0x7FFF_FFFF_FFFF_FFFF]
    static let L: N = [0x5812_631A_5CF5_D3ED, 0x14DE_F9DE_A2F7_9CD6, 0, 0x1000_0000_0000_0000]
    static func red(_ x: N) -> N {   // x mod p: x = hi * 2^255 + lo = lo + 19 hi (mod p), until hi = 0
        var x = norm(x)
        while bitLength(x) > 255 {
            var lo = Array(x.prefix(4)); while lo.count < 4 { lo.append(0) }; lo[3] &= 0x7FFF_FFFF_FFFF_FFFF
            var hi = N(repeating: 0, count: max(x.count - 3, 1))
            for i in 0..<hi.count {   // x >> 255
                let a = 3 + i < x.count ? x[3 + i] : 0, b = 4 + i < x.count ? x[4 + i] : 0
                hi[i] = (a >> 63) | (b << 1)
            }
            x = add(lo, mul(norm(hi), [19]))
        }
        while cmp(x, P) >= 0 { x = sub(x, P) }
        return x
    }
    static func fadd(_ a: N, _ b: N) -> N { red(add(a, b)) }
    static func fsub(_ a: N, _ b: N) -> N { red(add(a, sub(P, red(b)))) }
    static func fmul(_ a: N, _ b: N) -> N { red(mul(a, b)) }
    static func fpow(_ b: N, _ e: N) -> N {
        var r: N = [1]
        for i in stride(from: bitLength(e) - 1, through: 0, by: -1) { r = fmul(r, r); if bit(e, i) { r = fmul(r, b) } }
        return r
    }
    static let D: N = fmul(sub(P, [121665]), fpow([121666], sub(P, [2])))
    static let I: N = fpow([2], { var e = sub(P, [1]); e = shr(e, 2); return e }())
    static func shr(_ a: N, _ k: Int) -> N {   // k < 64
        var r = a
        for i in 0..<r.count { r[i] = (a[i] >> UInt64(k)) | (i + 1 < a.count ? a[i + 1] << UInt64(64 - k) : 0) }
        return norm(r)
    }
    typealias Pt = (x: N, y: N, z: N, t: N)
    static func decode(_ b: [UInt8]) -> Pt? {   // RFC 8032 5.1.3
        guard b.count == 32 else { return nil }
        var n = N(repeating: 0, count: 4)
        for i in 0..<32 { n[i / 8] |= UInt64(b[i]) << UInt64(8 * (i % 8)) }
        let x0 = (n[3] >> 63) & 1 == 1; n[3] &= 0x7FFF_FFFF_FFFF_FFFF
        let y = norm(n)
        if cmp(y, P) >= 0 { return nil }
        let yy = fmul(y, y), u = fsub(yy, [1]), v = fadd(fmul(D, yy), [1])
        let v3 = fmul(fmul(v, v), v), v7 = fmul(fmul(v3, v3), v)
        var x = fmul(fmul(u, v3), fpow(fmul(u, v7), shr(sub(P, [5]), 3)))
        let vxx = fmul(v, fmul(x, x))
        if cmp(vxx, u) == 0 { } else if cmp(vxx, fsub([0], u)) == 0 { x = fmul(x, I) } else { return nil }
        if cmp(x, [0]) == 0 && x0 { return nil }
        if bit(x, 0) != x0 { x = sub(P, x) }
        return (x, y, [1], fmul(x, y))
    }
    static func padd(_ p: Pt, _ q: Pt) -> Pt {   // RFC 8032 5.1.4
        let a = fmul(fsub(p.y, p.x), fsub(q.y, q.x)), b = fmul(fadd(p.y, p.x), fadd(q.y, q.x))
        let c = fmul(fmul(fmul(p.t, [2]), D), q.t), d = fmul(fmul(p.z, [2]), q.z)
        let e = fsub(b, a), f = fsub(d, c), g = fadd(d, c), h = fadd(b, a)
        return (fmul(e, f), fmul(g, h), fmul(f, g), fmul(e, h))
    }
    static func smul(_ k: N, _ p: Pt) -> Pt {
        var r: Pt = ([0], [1], [1], [0])
        for i in stride(from: bitLength(k) - 1, through: 0, by: -1) { r = padd(r, r); if bit(k, i) { r = padd(r, p) } }
        return r
    }
    static func neutral(_ p: Pt) -> Bool { cmp(p.x, [0]) == 0 && cmp(p.y, p.z) == 0 }

    /// nil when the 32-octet key is usable; else key_not_decodable, small_order_key or mixed_order_key.
    public static func keyProblem(_ pk: [UInt8]) -> String? {
        guard let a = decode(pk) else { return "key_not_decodable" }
        if neutral(smul([8], a)) { return "small_order_key" }
        if !neutral(smul(L, a)) { return "mixed_order_key" }
        return nil
    }
    /// nil when R (the first 32 octets of a 64-octet signature) decodes and is not of small order.
    public static func rProblem(_ sig: [UInt8]) -> String? {
        guard sig.count == 64, let r = decode(Array(sig[0..<32])) else { return "r_not_decodable" }
        return neutral(smul([8], r)) ? "small_order_r" : nil
    }
}
