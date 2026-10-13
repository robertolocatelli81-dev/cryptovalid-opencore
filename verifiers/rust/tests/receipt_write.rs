//! 0.20.3: a receipt that is not written whole is exit 74 (sysexits EX_IOERR) with one stderr line, whatever the
//! verdict. The real binary runs with stdout on /dev/full (ENOSPC) and on a pipe whose read end is closed before the
//! start (EPIPE). On 0.20.2 `println!` panicked: exit 101 and a panic message. `>&-` is not tested: the Rust runtime
//! reopens fd 1 on /dev/null, the program cannot see it.
use std::fs::{File, OpenOptions};
use std::process::{Command, Stdio};

fn vector(name: &str) -> String {
    format!("{}/tests/vectors/{}", env!("CARGO_MANIFEST_DIR"), name)
}

fn run(arg: &str, stdout: Stdio) -> (i32, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_cvverify"))
        .arg(arg)
        .stdout(stdout)
        .stderr(Stdio::piped())
        .output()
        .expect("cvverify runs");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn receipt_not_written_is_exit_74() {
    let missing = vector("no_such_file.jsonl");
    let not_utf8 = format!("{}/cvverify-not-utf8-{}.jsonl", std::env::temp_dir().display(), std::process::id());
    std::fs::write(&not_utf8, [0xffu8, b'\n']).unwrap();
    let cases = [
        (vector("valid_sha256.jsonl"), 0),
        (vector("broken_link.jsonl"), 1),
        (not_utf8.clone(), 1),
        (missing, 2),
    ];
    for (path, code) in cases.iter() {
        let ctl = Command::new(env!("CARGO_BIN_EXE_cvverify")).arg(path).output().unwrap();
        assert_eq!(ctl.status.code(), Some(*code), "control {}", path);
        assert!(String::from_utf8_lossy(&ctl.stdout).contains("\"verdict\""), "control receipt {}", path);
        assert!(ctl.stderr.is_empty(), "control stderr {}", path);

        let full: File = OpenOptions::new().write(true).open("/dev/full").unwrap();
        let (c, e) = run(path, Stdio::from(full));
        assert_eq!(c, 74, "/dev/full {}: stderr {:?}", path, e);
        assert!(e.starts_with("receipt not written: "), "/dev/full {}: stderr {:?}", path, e);
        assert!(!e.contains("panicked"), "/dev/full {}", path);

        let (reader, writer) = std::io::pipe().unwrap();
        drop(reader);
        let (c, e) = run(path, Stdio::from(writer));
        assert_eq!(c, 74, "reader gone {}: stderr {:?}", path, e);
        assert!(e.starts_with("receipt not written: "), "reader gone {}: stderr {:?}", path, e);
    }
    let _ = std::fs::remove_file(&not_utf8);
}

/// 0.20.3 (13/10): usage with stderr full keeps exit 2 (`eprintln!` panicked: 101).
#[test]
fn usage_with_stderr_full_is_exit_2() {
    for args in [vec![], vec!["--algo"], vec!["x.jsonl", "--bogus"]] {
        let full: File = OpenOptions::new().write(true).open("/dev/full").unwrap();
        let out = Command::new(env!("CARGO_BIN_EXE_cvverify")).args(&args).stderr(Stdio::from(full)).output().unwrap();
        assert_eq!(out.status.code(), Some(2), "usage {:?} with stderr full", args);
        assert!(out.stdout.is_empty(), "usage {:?}: stdout {:?}", args, out.stdout);
    }
}

/// 0.20.3 (13/10): a regular file that stops growing (bash `ulimit -f 1`, 24 bytes left; and `ulimit -f 0`) is exit 74
/// with one line: the kernel killed the process with SIGXFSZ before (no exit code, no line).
#[test]
fn file_size_limit_is_exit_74() {
    for (blocks, prefill) in [(1, 1000usize), (0, 0)] {
        let f = format!("{}/cvverify-fsize-{}-{}.out", std::env::temp_dir().display(), std::process::id(), blocks);
        std::fs::write(&f, vec![b'x'; prefill]).unwrap();
        let out = Command::new("bash")
            .args(["-c", &format!("ulimit -f {blocks}; exec \"$0\" \"$1\" >>\"$2\""), env!("CARGO_BIN_EXE_cvverify"), &vector("valid_sha256.jsonl"), &f])
            .output()
            .unwrap();
        let _ = std::fs::remove_file(&f);
        let e = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(74), "ulimit -f {blocks}: status {:?} stderr {e:?}", out.status);
        assert!(e.starts_with("receipt not written: "), "ulimit -f {blocks}: {e:?}");
    }
}

/// 0.20.3 (13/10): a NON-BLOCKING stdout read once the pipe is full gets a receipt larger than the pipe buffer whole, with the
/// verdict's code (it was 74 with 65 536 bytes in the pipe: WouldBlock reported as an error).
#[test]
fn nonblocking_stdout_read_late_is_whole() {
    let big = format!("{}/cvverify-nb-{}.jsonl", std::env::temp_dir().display(), std::process::id());
    let mut s = String::new();
    for i in 0..20000 {
        s.push_str(&format!("{{\"idx\":{i},\"ts\":\"2026-08-13T10:00:00Z\",\"data\":{{\"e\":{i}}},\"prev_hash\":\"{:064x}\",\"self_hash\":\"{:064x}\"}}\n", i + 1, i + 7));
    }
    std::fs::write(&big, s).unwrap();
    let script = "import fcntl,os,subprocess,sys,time\nr,w=os.pipe()\nfcntl.fcntl(w,fcntl.F_SETFL,fcntl.fcntl(w,fcntl.F_GETFL)|os.O_NONBLOCK)\np=subprocess.Popen(sys.argv[1:],stdout=w)\nos.close(w)\nimport array,termios\nt0=time.time()\nwhile p.poll() is None and time.time()-t0<60:\n    n=array.array('i',[0]); fcntl.ioctl(r,termios.FIONREAD,n,True)\n    if n[0]>=fcntl.fcntl(r,1032): break\n    time.sleep(0.02)\ntime.sleep(0.3)\nb=b''\nwhile True:\n    c=os.read(r,65536)\n    if not c: break\n    b+=c\nrc=p.wait()\nsys.stdout.write('%d %d %d' % (rc, len(b), b.count(b'\"verdict\"')))\n";
    let out = Command::new("python3").args(["-c", script, env!("CARGO_BIN_EXE_cvverify"), &big]).output().unwrap();
    let _ = std::fs::remove_file(&big);
    let got = String::from_utf8_lossy(&out.stdout).into_owned();
    let v: Vec<usize> = got.split_whitespace().map(|x| x.parse().unwrap()).collect();
    assert_eq!(v[0], 1, "exit code (FAIL verdict), got {got:?}");
    assert!(v[1] > 65536 && v[2] == 1, "receipt not whole: {got:?}");
}

/// review of 0.20.3, 13/10: the receipt ends with its newline (println! wrote one; a mutant without it passed every test above).
#[test]
fn receipt_ends_with_newline() {
    let out = Command::new(env!("CARGO_BIN_EXE_cvverify")).arg(vector("valid_sha256.jsonl")).output().unwrap();
    assert_eq!(out.status.code(), Some(0));
    assert!(out.stdout.ends_with(b"}\n"), "receipt end {:?}", &out.stdout[out.stdout.len().saturating_sub(4)..]);
}

/// review of 0.20.3, 13/10: stdout AND stderr full: the line cannot be said, the exit is still 74 (never a panic, 101).
#[test]
fn stdout_and_stderr_full_is_exit_74() {
    for v in ["valid_sha256.jsonl", "broken_link.jsonl"] {
        let o: File = OpenOptions::new().write(true).open("/dev/full").unwrap();
        let e: File = OpenOptions::new().write(true).open("/dev/full").unwrap();
        let s = Command::new(env!("CARGO_BIN_EXE_cvverify")).arg(vector(v)).stdout(Stdio::from(o)).stderr(Stdio::from(e)).status().unwrap();
        assert_eq!(s.code(), Some(74), "{v}: {s:?}");
    }
}

/// review of 0.20.3, 13/10: the wait on a full non-blocking stdout sleeps in poll(2): less than 0.3 s of CPU in 2 s of waiting
/// (a poll with timeout 0 spun at 100 %), and the receipt is whole once read. Linux (/proc, F_GETPIPE_SZ).
#[cfg(target_os = "linux")]
#[test]
fn waiting_on_a_full_stdout_does_not_spin() {
    let big = format!("{}/cvverify-spin-{}.jsonl", std::env::temp_dir().display(), std::process::id());
    let mut s = String::new();
    for i in 0..20000 {
        s.push_str(&format!("{{\"idx\":{i},\"ts\":\"2026-08-13T10:00:00Z\",\"data\":{{\"e\":{i}}},\"prev_hash\":\"{:064x}\",\"self_hash\":\"{:064x}\"}}\n", i + 1, i + 7));
    }
    std::fs::write(&big, s).unwrap();
    let script = "import array,fcntl,os,subprocess,sys,termios,time\nr,w=os.pipe()\nfcntl.fcntl(w,fcntl.F_SETFL,fcntl.fcntl(w,fcntl.F_GETFL)|os.O_NONBLOCK)\np=subprocess.Popen(sys.argv[1:],stdout=w)\nos.close(w)\ncap=fcntl.fcntl(r,1032);t0=time.time()\nwhile p.poll() is None and time.time()-t0<60:\n    n=array.array('i',[0]); fcntl.ioctl(r,termios.FIONREAD,n,True)\n    if n[0]>=cap: break\n    time.sleep(0.02)\ntime.sleep(0.3)\ndef cpu():\n    f=open('/proc/%d/stat'%p.pid).read().rsplit(')',1)[1].split(); return (int(f[11])+int(f[12]))/os.sysconf('SC_CLK_TCK')\nc1=cpu(); time.sleep(2); c2=cpu()\nb=b''\nwhile True:\n    c=os.read(r,65536)\n    if not c: break\n    b+=c\nsys.stdout.write('%d %d %.3f' % (p.wait(), len(b), c2-c1))\n";
    let out = Command::new("python3").args(["-c", script, env!("CARGO_BIN_EXE_cvverify"), &big]).output().unwrap();
    let _ = std::fs::remove_file(&big);
    let got = String::from_utf8_lossy(&out.stdout).into_owned();
    let v: Vec<f64> = got.split_whitespace().map(|x| x.parse().unwrap()).collect();
    assert_eq!(v.len(), 3, "driver: {got:?} {:?}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(v[0] as i32, 1, "exit code: {got:?}");
    assert!(v[1] > 65536.0, "receipt not whole: {got:?}");
    assert!(v[2] < 0.3, "CPU while waiting: {got:?}");
}

/// review of 0.20.3, 13/10: write(2) taking 0 bytes is an error (74), an EINTR is retried (the receipt whole, exit 0). Injected
/// with an LD_PRELOAD shim built by `cc`; skipped where there is no C compiler. Linux.
#[cfg(target_os = "linux")]
#[test]
fn zero_write_is_74_and_eintr_is_retried() {
    let dir = std::env::temp_dir().join(format!("cvverify-shim-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let c = dir.join("shim.c");
    std::fs::write(&c, "#define _GNU_SOURCE\n#include <dlfcn.h>\n#include <errno.h>\n#include <stdlib.h>\n#include <unistd.h>\nstatic int d0,di;\nssize_t write(int fd,const void*b,size_t n){static ssize_t(*r)(int,const void*,size_t);if(!r)r=dlsym(RTLD_NEXT,\"write\");\nif(fd==1&&n&&getenv(\"SHIM_W0\")&&!d0){d0=1;return 0;}\nif(fd==1&&n&&getenv(\"SHIM_WI\")&&!di){di=1;errno=EINTR;return -1;}\nreturn r(fd,b,n);}\n").unwrap();
    let so = dir.join("shim.so");
    match Command::new("cc").args(["-shared", "-fPIC", "-o"]).arg(&so).arg(&c).arg("-ldl").status() {
        Ok(s) if s.success() => {}
        _ => { eprintln!("no C compiler: skipped"); return; }
    }
    let run = |var: &str| Command::new(env!("CARGO_BIN_EXE_cvverify")).arg(vector("valid_sha256.jsonl")).env("LD_PRELOAD", &so).env(var, "1").output().unwrap();
    let z = run("SHIM_W0");
    assert_eq!(z.status.code(), Some(74), "write 0: {:?}", String::from_utf8_lossy(&z.stderr));
    assert!(String::from_utf8_lossy(&z.stderr).starts_with("receipt not written: short write"));
    let i = run("SHIM_WI");
    let ctl = Command::new(env!("CARGO_BIN_EXE_cvverify")).arg(vector("valid_sha256.jsonl")).output().unwrap();
    assert_eq!(i.status.code(), Some(0), "EINTR: {:?}", String::from_utf8_lossy(&i.stderr));
    assert_eq!(i.stdout, ctl.stdout, "EINTR: receipt not whole");
    let _ = std::fs::remove_dir_all(&dir);
}
