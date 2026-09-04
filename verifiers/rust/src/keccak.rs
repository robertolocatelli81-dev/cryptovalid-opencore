//! SHA3-256 (FIPS 202), pure Rust, no dependencies.
const RC: [u64; 24] = [
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808A,
    0x8000000080008000,
    0x000000000000808B,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008A,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000A,
    0x000000008000808B,
    0x800000000000008B,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800A,
    0x800000008000000A,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
];
const ROT: [u32; 25] = [
    0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14,
];

fn keccak_f(s: &mut [u64; 25]) {
    for &rc in RC.iter() {
        let mut c = [0u64; 5];
        for x in 0..5 {
            c[x] = s[x] ^ s[x + 5] ^ s[x + 10] ^ s[x + 15] ^ s[x + 20];
        }
        for x in 0..5 {
            let d = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
            let mut y = 0;
            while y < 25 {
                s[x + y] ^= d;
                y += 5;
            }
        }
        let mut b = [0u64; 25];
        for x in 0..5 {
            for y in 0..5 {
                b[y + 5 * ((2 * x + 3 * y) % 5)] = s[x + 5 * y].rotate_left(ROT[x + 5 * y]);
            }
        }
        for x in 0..5 {
            for y in 0..5 {
                s[x + 5 * y] = b[x + 5 * y] ^ ((!b[(x + 1) % 5 + 5 * y]) & b[(x + 2) % 5 + 5 * y]);
            }
        }
        s[0] ^= rc;
    }
}

pub fn hex(data: &[u8]) -> String {
    const RATE: usize = 136;
    let mut msg = data.to_vec();
    msg.push(0x06);
    while !msg.len().is_multiple_of(RATE) {
        msg.push(0);
    }
    let last = msg.len() - 1;
    msg[last] ^= 0x80;
    let mut s = [0u64; 25];
    for block in msg.chunks(RATE) {
        for (i, lane) in block.chunks(8).enumerate() {
            let mut v = 0u64;
            for j in (0..8).rev() {
                v = (v << 8) | lane[j] as u64;
            }
            s[i] ^= v;
        }
        keccak_f(&mut s);
    }
    let mut out = String::new();
    for &lane in s.iter().take(4) {
        for b in lane.to_le_bytes() {
            out.push_str(&format!("{:02x}", b));
        }
    }
    out
}
