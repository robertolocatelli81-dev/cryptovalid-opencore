// SHA3-256 (FIPS 202) in pure Swift — CryptoKit does not provide SHA3, so this
// package carries a small Keccak-f[1600]. Byte-for-byte twin of the Keccak used in
// the JS and Java verifiers; validated against the shared conformance vectors.
import Foundation

public enum SHA3_256 {
    private static let RC: [UInt64] = [
        0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
        0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
        0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
        0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
        0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
        0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008]
    private static let ROT: [Int] = [0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14]

    private static func rotl(_ x: UInt64, _ n: Int) -> UInt64 { n == 0 ? x : (x << UInt64(n)) | (x >> UInt64(64 - n)) }

    private static func f(_ s: inout [UInt64]) {
        for r in 0..<24 {
            var c = [UInt64](repeating: 0, count: 5)
            for x in 0..<5 { c[x] = s[x] ^ s[x+5] ^ s[x+10] ^ s[x+15] ^ s[x+20] }
            for x in 0..<5 {
                let d = c[(x+4)%5] ^ rotl(c[(x+1)%5], 1)
                var y = 0; while y < 25 { s[x+y] ^= d; y += 5 }
            }
            var b = [UInt64](repeating: 0, count: 25)
            for x in 0..<5 { for y in 0..<5 { b[y + 5*((2*x + 3*y) % 5)] = rotl(s[x + 5*y], ROT[x + 5*y]) } }
            for x in 0..<5 { for y in 0..<5 { s[x + 5*y] = b[x + 5*y] ^ (~b[(x+1)%5 + 5*y] & b[(x+2)%5 + 5*y]) } }
            s[0] ^= RC[r]
        }
    }

    public static func hex(_ data: [UInt8]) -> String {
        let rate = 136
        var msg = data
        let padLen = ((msg.count + 1 + rate - 1) / rate) * rate
        msg.append(0x06)
        while msg.count < padLen { msg.append(0x00) }
        msg[msg.count - 1] ^= 0x80
        var s = [UInt64](repeating: 0, count: 25)
        var off = 0
        while off < msg.count {
            for i in 0..<(rate/8) {
                var lane: UInt64 = 0
                for j in stride(from: 7, through: 0, by: -1) { lane = (lane << 8) | UInt64(msg[off + 8*i + j]) }
                s[i] ^= lane
            }
            f(&s); off += rate
        }
        var out = [UInt8]()
        for i in 0..<4 { var lane = s[i]; for _ in 0..<8 { out.append(UInt8(lane & 0xff)); lane >>= 8 } }
        return out.map { String(format: "%02x", $0) }.joined()
    }
    public static func hex(_ s: String) -> String { hex(Array(s.utf8)) }
}
