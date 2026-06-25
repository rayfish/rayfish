//! Build script: stamp the git short SHA into the binary so nightly builds are
//! identifiable. `ray version`/`--version` and `ray report` surface it, and
//! `ray update --nightly` uses the running binary's checksum (not its version)
//! to decide whether a swap is needed — but the SHA is what a tester quotes.
//!
//! Falls back to `unknown` when git is unavailable (e.g. a source tarball build
//! outside a checkout), so the build never fails for lack of a `.git` dir.

use std::process::Command;

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
}
