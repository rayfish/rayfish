//! Build script: stamp the git short SHA into the binary so nightly builds are
//! identifiable. `ray version`/`--version` and `ray report` surface it, and
//! `ray update --nightly` uses the running binary's checksum (not its version)
//! to decide whether a swap is needed — but the SHA is what a tester quotes.
//!
//! Falls back to `unknown` when git is unavailable (e.g. a source tarball build
//! outside a checkout), so the build never fails for lack of a `.git` dir.
//!
//! It also sets the Windows main-thread stack reserve; see [`STACK_RESERVE`].

use std::env;
use std::process::Command;

/// Stack reserved for the main thread of `ray.exe`, matching the 8 MiB Linux
/// gives a process by default.
///
/// Windows takes this from the PE header and defaults to 1 MiB, which is not
/// enough to build the clap command tree in a debug build: every `ray` command,
/// `--version` included, overflowed the stack and died with `0xC00000FD` before
/// it could parse an argument. A release build fits in a quarter of that, so
/// only a locally built binary and CI ever hit it, which is the worst way to
/// find out. Reserve is address space and nothing more (pages commit as the
/// stack grows), so the headroom costs no memory.
const STACK_RESERVE: usize = 8 * 1024 * 1024;

fn main() {
    let sha = Command::new("git")
        .args(["rev-parse", "--short=8", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".to_string());

    println!("cargo:rustc-env=RAY_GIT_SHA={sha}");

    // Rebuild when HEAD moves so the stamp stays current. `.git/HEAD` covers
    // commits/checkouts; the packed-refs/refs paths cover branch updates.
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/refs");
    println!("cargo:rerun-if-changed=.git/packed-refs");

    if env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        // `-bins` so this lands on `ray.exe` and not on the test harnesses,
        // which get their stacks from the threads libtest spawns them on.
        let arg = match env::var("CARGO_CFG_TARGET_ENV").as_deref() {
            // link.exe spells it itself; the gnu targets go through gcc to ld.
            Ok("msvc") => format!("/STACK:{STACK_RESERVE}"),
            _ => format!("-Wl,--stack,{STACK_RESERVE}"),
        };
        println!("cargo:rustc-link-arg-bins={arg}");
    }
}
