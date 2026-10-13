// cvverify — CLI wrapper. Usage: cvverify <ledger.jsonl> [--algo sha256|sha3_256] [--pubkey hex]
// Exit 0 = PASS, 1 = FAIL, 2 = usage or FILE_ERROR, 74 = the receipt was not written whole (stdout full, closed or a
// reader gone; 0.20.3), whatever the verdict.
import Foundation
import CryptoValidVerify
#if canImport(Glibc)
import Glibc
#elseif canImport(Darwin)
import Darwin
#endif

// A reader that is gone must be an EPIPE error the program reads, not a SIGPIPE death (141 in a shell, 0.20.2); past a
// file size limit (`ulimit -f`) the write must return EFBIG, not the kernel kill the process with SIGXFSZ (0.20.3).
signal(SIGPIPE, SIG_IGN)
signal(SIGXFSZ, SIG_IGN)

/// Write the receipt to fd 1, every byte, and read errno before choosing the exit code (0.20.3): a short write continues
/// from the next byte, EINTR retries, EAGAIN (a non-blocking stdout that is full: a reader that reads late) waits in
/// poll(2) as a blocking write would, any other error (ENOSPC, EPIPE, EBADF, EFBIG) is exit 74 with one stderr line.
/// `print` + `exit` dropped the error (0.20.2), and fwrite + fflush reported a full non-blocking stdout as lost.
func emit(_ receipt: String, _ code: Int32) -> Never {
    let bytes = Array((receipt + "\n").utf8)
    var off = 0
    var why: String? = nil
    while off < bytes.count {
        let n = bytes.withUnsafeBufferPointer { write(1, $0.baseAddress! + off, $0.count - off) }
        if n > 0 { off += n; continue }
        if n == 0 { why = "short write: \(bytes.count - off) bytes not written"; break }
        let e = errno
        if e == EINTR { continue }
        if e == EAGAIN || e == EWOULDBLOCK {
            var p = pollfd(fd: 1, events: Int16(POLLOUT), revents: 0)
            if poll(&p, 1, -1) < 0 && errno != EINTR { why = String(cString: strerror(errno)); break }
            continue
        }
        why = String(cString: strerror(e)); break
    }
    if let why = why {
        // fputs, not FileHandle.write: the latter traps (SIGILL) when stderr fails too; here the exit stays 74
        _ = fputs("receipt not written: \(why)\n", stderr); _ = fflush(stderr)
        exit(74)   // sysexits EX_IOERR
    }
    exit(code)
}

let usageText = "usage: cvverify <ledger.jsonl> [--algo sha256|sha3_256] [--pubkey hex]\n"
// fputs, not FileHandle.standardError.write: that traps (SIGILL, exit 132) when stderr is full or closed, and with stderr
// closed fd 2 may be the file the shell opened for stdout (0.20.3); the exit stays 2
func usage() -> Never { _ = fputs(usageText, stderr); _ = fflush(stderr); exit(2) }

// One grammar with the other verifiers (21/09/2026, differential_oracle.py CLI cases): the ledger path first; an
// unknown flag, a value flag without a value, with "" or with a value starting with "-", a second positional = usage
// error, exit 2, no verdict — never a verdict with the constraint dropped. `--algo` takes only the two profiles
// (verifier.py's argparse choices); a repeated flag keeps its last value, as in Python, JS and Rust.
let args = Array(CommandLine.arguments.dropFirst())
guard let path = args.first, path.unicodeScalars.first != "-" else { usage() }   // scalar test: hasPrefix compares graphemes
var algo: String? = nil, pubkey: String? = nil
var k = 1
while k < args.count {
    let flag = args[k]
    guard scalarEqual(flag, "--algo") || scalarEqual(flag, "--pubkey"), k + 1 < args.count else { usage() }
    let v = args[k + 1]
    if v.unicodeScalars.first == nil || v.unicodeScalars.first == "-" { usage() }
    if scalarEqual(flag, "--algo") {
        guard scalarEqual(v, "sha256") || scalarEqual(v, "sha3_256") else { usage() }
        algo = v
    } else {
        pubkey = v
    }
    k += 2
}
guard let bytes = CryptoValidVerifier.readLedgerFile(atPath: path) else {   // a FIFO too (12/10/2026)
    emit("{\"verdict\":\"FILE_ERROR\"}", 2)
}
// bytes, not String(contentsOfFile:): a file that is not UTF-8 is read, then FAILs with a named error (as Rust, JS, Go,
// Java); it used to be FILE_ERROR
let r = CryptoValidVerifier.verify(ledgerBytes: bytes, algo: algo, expectedPubkeyHex: pubkey)
let enc = JSONEncoder(); enc.outputFormatting = [.prettyPrinted, .sortedKeys]
emit(String(data: try! enc.encode(r), encoding: .utf8)!, r.verdict == "PASS" ? 0 : 1)
