//! cvverify — CLI. Usage: cvverify <ledger.jsonl> [--algo sha256|sha3_256]
//! Exit 0 = PASS, 1 = FAIL, 2 = usage or an unreadable file, 74 = the receipt was not written whole (stdout full,
//! closed, a file size limit or a reader gone; 0.20.3), whatever the verdict. A full non-blocking stdout is waited for.
use std::io::Write;
use std::process::exit;

/// sysexits.h EX_IOERR: the receipt could not be written whole.
const EX_IOERR: i32 = 74;

/// One line on stderr that never panics: `eprintln!` panics when stderr cannot take it (a full disk, a reader gone),
/// and a usage error then exited 101 instead of the documented 2 (0.20.3, as cra-evidence 0.5.1).
fn say(msg: &str) {
    let _ = writeln!(std::io::stderr(), "{msg}");
}

fn usage() -> ! {
    say("usage: cvverify <ledger.jsonl> [--algo sha256|sha3_256]");
    exit(2);
}

/// Write the receipt, every byte, before choosing the exit code. `println!` panicked on a write error (exit 101 and a
/// panic message, 0.20.2). Since 0.20.3: SIGXFSZ ignored (past a file size limit the write returns EFBIG instead of
/// the kernel killing the process), fd 1 written in a loop that sees the count, a full non-blocking stdout waited for
/// in poll(2) (a reader that reads late is not a lost receipt), any other error (ENOSPC, EPIPE, EBADF, EFBIG) exit 74
/// with one stderr line.
fn emit(receipt: &str, code: i32) -> ! {
    #[cfg(all(any(target_os = "linux", target_os = "macos"), not(any(target_arch = "mips", target_arch = "mips64", target_arch = "sparc64"))))]
    {
        extern "C" {
            fn signal(signum: i32, handler: usize) -> usize;
        }
        const SIGXFSZ: i32 = 25;
        const SIG_IGN: usize = 1;
        unsafe {
            signal(SIGXFSZ, SIG_IGN);
        }
    }
    let mut bytes = receipt.as_bytes().to_vec();
    bytes.push(b'\n');
    if let Err(e) = write_all_stdout(&bytes) {
        say(&format!("receipt not written: {e}")); // never eprintln!: it would panic if stderr is gone too
        exit(EX_IOERR);
    }
    exit(code);
}

/// Every byte to fd 1: a short write continues from the next byte, EINTR retries, WouldBlock waits in poll(2) as a
/// blocking write would, 0 bytes taken is an error. The descriptor is borrowed, never closed.
#[cfg(unix)]
fn write_all_stdout(mut buf: &[u8]) -> std::io::Result<()> {
    use std::io::ErrorKind;
    use std::os::unix::io::FromRawFd;
    #[repr(C)]
    struct PollFd {
        fd: i32,
        events: i16,
        revents: i16,
    }
    #[cfg(target_os = "linux")]
    type NFds = std::os::raw::c_ulong; // nfds_t is unsigned long on Linux
    #[cfg(not(target_os = "linux"))]
    type NFds = std::os::raw::c_uint;
    extern "C" {
        fn poll(fds: *mut PollFd, nfds: NFds, timeout: i32) -> i32;
    }
    const POLLOUT: i16 = 4;
    let mut out = std::mem::ManuallyDrop::new(unsafe { std::fs::File::from_raw_fd(1) });
    while !buf.is_empty() {
        match out.write(buf) {
            Ok(0) => return Err(std::io::Error::new(ErrorKind::WriteZero, format!("short write: {} bytes not written", buf.len()))),
            Ok(n) => buf = &buf[n..],
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(e) if e.kind() == ErrorKind::WouldBlock => {
                let mut p = PollFd { fd: 1, events: POLLOUT, revents: 0 };
                if unsafe { poll(&mut p, 1, -1) } < 0 {
                    let e = std::io::Error::last_os_error();
                    if e.kind() != ErrorKind::Interrupted {
                        return Err(e);
                    }
                }
            }
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn write_all_stdout(buf: &[u8]) -> std::io::Result<()> {
    let mut so = std::io::stdout().lock();
    so.write_all(buf).and_then(|_| so.flush())
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let path = match args.first() {
        Some(p) if !p.starts_with('-') => p,
        _ => usage(),
    };
    // one grammar (21/09/2026): an unknown flag, "--algo" without a value or with "", a second positional = usage error, exit 2
    let mut algo: Option<&str> = None;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--algo" => {
                match args.get(i + 1) {
                    // only the two profiles (argparse choices in the reference): "foo" was hashed as SHA-256 and printed, unescaped,
                    // as "algorithm" in the receipt (NEMESIS 12/10/2026)
                    Some(v) if v == "sha256" || v == "sha3_256" => { algo = Some(v.as_str()); i += 2; }
                    _ => usage(),
                }
            }
            _ => usage(),
        }
    }
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            emit(&format!("{{\"verdict\":\"FILE_ERROR\",\"error\":\"{}\"}}", e), 2);
        }
    };
    let text = match String::from_utf8(bytes) {   // the file exists but is not UTF-8: a FAIL verdict like the other verifiers, not "file error"
        Ok(t) => t,
        Err(_) => {
            emit("{\"verdict\":\"FAIL\",\"error\":\"ledger is not valid UTF-8\"}", 1);
        }
    };
    let r = cvverify::verify_ledger(&text, algo);
    emit(&r.to_json(), if r.verdict == "PASS" { 0 } else { 1 });
}
