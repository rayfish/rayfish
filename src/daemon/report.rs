//! Diagnostics bundle creation and access control.

use super::*;

/// Read the most recent rolling log files from [`crate::logdir::log_dir`],
/// newest first, capped at ~3 MB total so report bundles stay small. Returns
/// `(archive_name, bytes)` entries placed under `logs/` in the tarball.
pub(super) fn collect_recent_logs() -> Vec<(String, Vec<u8>)> {
    const MAX_TOTAL: u64 = 3 * 1024 * 1024;

    let dir = crate::logdir::log_dir();
    let mut entries: Vec<PathBuf> = match std::fs::read_dir(&dir) {
        Ok(rd) => rd
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.starts_with("rayfish.log") || n == "panic.log")
            })
            .collect(),
        Err(_) => return Vec::new(),
    };
    // Daily rotation appends a date suffix, so lexical order is chronological;
    // take the newest files first.
    entries.sort();
    entries.reverse();

    let mut out = Vec::new();
    let mut total = 0u64;
    for path in entries {
        let Ok(bytes) = std::fs::read(&path) else {
            continue;
        };
        total += bytes.len() as u64;
        if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
            out.push((format!("logs/{name}"), bytes));
        }
        if total >= MAX_TOTAL {
            break;
        }
    }
    out
}

/// Write `files` as a gzipped tar archive at a new, non-symlink `path`.
/// Each entry is `(name, bytes)`.
///
/// The bundle stays 0600 for its whole life when there is an `owner` to hand it
/// to: it packs the root daemon's `rayfish=debug` logs, status dump, peer ids
/// and mesh IPs, and `IpcMessage::Report` is an open read, so a world-readable
/// copy sitting in `/tmp` is those logs handed to every other local user. It
/// widens to 0644 only when the file is still root-owned and would otherwise be
/// unreadable by the very caller that asked for it.
fn write_bundle(
    path: &Path,
    files: &[(String, Vec<u8>)],
    owner: Option<&ReportRequester>,
) -> std::io::Result<()> {
    let mut file = create_bundle_file(path, owner)?;
    let result = (|| {
        let enc = flate2::write::GzEncoder::new(&mut file, flate2::Compression::default());
        let mut builder = tar::Builder::new(enc);
        for (name, data) in files {
            let mut header = tar::Header::new_gnu();
            header.set_size(data.len() as u64);
            header.set_mode(0o644);
            // `append_data` sets the path and recomputes the checksum.
            builder.append_data(&mut header, name, data.as_slice())?;
        }
        builder.into_inner()?.finish()?;
        file.sync_all()?;
        hand_bundle_to_requester(&file, owner)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(path);
    }
    result
}

/// The bundle's file, created exclusively and readable by nobody else yet.
#[cfg(unix)]
fn create_bundle_file(path: &Path, _owner: Option<&ReportRequester>) -> std::io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;

    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
}

/// The Windows counterpart. `CREATE_NEW` is what `O_NOFOLLOW` is here: it fails
/// on anything already at the path, a planted reparse point included. The DACL
/// names the requester at creation rather than being widened afterwards, since
/// Windows has no ownership handoff to widen *from*.
#[cfg(windows)]
fn create_bundle_file(path: &Path, owner: Option<&ReportRequester>) -> std::io::Result<File> {
    let ReportRequester::Windows { sid } = match owner {
        Some(owner) => owner,
        // No identified caller, so nobody beyond SYSTEM and Administrators gets
        // to read the daemon's logs.
        None => return crate::windows_security::create_report_file(path, None).map_err(to_io),
    };
    crate::windows_security::create_report_file(path, Some(sid)).map_err(to_io)
}

/// Flatten back to an `io::Error` **keeping the kind**. `create_report_bundle`
/// retries on `AlreadyExists` to survive a name collision, and it can only see
/// one if the kind survives the trip through `anyhow`; `io::Error::other` would
/// make every collision look like a hard failure and end the loop on its first
/// iteration.
#[cfg(windows)]
fn to_io(error: anyhow::Error) -> std::io::Error {
    let kind = error
        .chain()
        .find_map(|cause| cause.downcast_ref::<std::io::Error>())
        .map(std::io::Error::kind);
    match kind {
        Some(kind) => std::io::Error::new(kind, format!("{error:#}")),
        None => std::io::Error::other(format!("{error:#}")),
    }
}

/// Open the finished bundle to whoever asked for it.
///
/// Unix only: on Windows the DACL was set when the file was created, because
/// there is no equivalent of "still root-owned, so widen the mode".
#[cfg(unix)]
fn hand_bundle_to_requester(file: &File, owner: Option<&ReportRequester>) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let given_to_requester = match owner {
        Some(ReportRequester::Unix { uid, gid }) => {
            let rc = unsafe { libc::fchown(file.as_raw_fd(), *uid, *gid) };
            if rc == 0 {
                true
            } else {
                // Best-effort, as it was before the fd move: a daemon
                // without CAP_CHOWN, or a /tmp on a mount that refuses
                // ownership changes, would otherwise have its finished
                // archive deleted by the cleanup below and report
                // "Operation not permitted" with nothing to attach.
                tracing::warn!(
                    error = %std::io::Error::last_os_error(),
                    "could not hand the report bundle to the requester"
                );
                false
            }
        }
        None => false,
    };
    if !given_to_requester {
        // Still root-owned, so the caller needs the wider mode to read it
        // at all. This is the only path that exposes the bundle.
        file.set_permissions(std::fs::Permissions::from_mode(0o644))?;
    }
    Ok(())
}

#[cfg(windows)]
fn hand_bundle_to_requester(_file: &File, _owner: Option<&ReportRequester>) -> std::io::Result<()> {
    Ok(())
}

/// Delete `uid`'s earlier bundles in `dir`.
///
/// The old fixed `rayfish-report-{ts}.tgz` was truncated and reused within the
/// same second, which bounded a flood at one file. An unpredictable name closed
/// the symlink hole but took that bound away, and `IpcMessage::Report` is in the
/// open-reads arm of `check_authorized`: without this, any local account can
/// loop `ray report` and have the root daemon leave a fresh gzip of up to seven
/// days of debug logs in `/tmp` every time, forever.
///
/// `/tmp` is world-writable and this runs as root, so the unlink is deliberately
/// narrow: `symlink_metadata` does not follow a planted link, and only a regular
/// file owned by the same uid whose name matches the bundle pattern is removed.
/// A short, stable tag naming the principal a bundle belongs to, so the sweep
/// can pick out this caller's own without reading an owner back off the disk.
#[cfg(unix)]
fn requester_tag(owner: Option<&ReportRequester>) -> String {
    let uid = match owner {
        Some(ReportRequester::Unix { uid, .. }) => *uid,
        None => unsafe { libc::geteuid() },
    };
    format!("u{uid}")
}

/// The Windows counterpart. A hash of the SID rather than the SID itself: the
/// daemon's temp directory is `C:\Windows\Temp`, which any local account may
/// list, and who has run `ray report` is not their business. Truncating to 8
/// bytes is fine for telling a handful of local principals apart; a collision
/// costs one lost bundle, not access to one.
#[cfg(windows)]
fn requester_tag(owner: Option<&ReportRequester>) -> String {
    use sha2::{Digest, Sha256};

    let sid = match owner {
        Some(ReportRequester::Windows { sid }) => sid.as_str(),
        None => "",
    };
    format!("s{}", hex::encode(&Sha256::digest(sid.as_bytes())[..8]))
}

/// A reader holding one open keeps it until they close it.
fn sweep_prior_bundles(dir: &Path, owner: Option<&ReportRequester>) {
    #[cfg(unix)]
    use std::os::unix::fs::MetadataExt;

    // Only this caller's own bundles, matched by the tag their names carry.
    // The pipe DACL limits `Report` to LocalSystem, Administrators and the
    // operator, but that is still more than one principal, and
    // `create_report_file` grants read to exactly one of them per bundle. An
    // administrator running `ray report` must not unlink the bundle the daemon
    // just handed the operator and that they have not opened yet.
    let prefix = format!("rayfish-report-{}-", requester_tag(owner));
    // On Unix the name is a hint and the uid below is the decision, since `/tmp`
    // lets any account create a file with any name in it.
    #[cfg(unix)]
    let uid = match owner {
        Some(ReportRequester::Unix { uid, .. }) => *uid,
        None => unsafe { libc::geteuid() },
    };
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.filter_map(|e| e.ok()) {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if !name.starts_with(&prefix) || !name.ends_with(".tgz") {
            continue;
        }
        let path = entry.path();
        let Ok(md) = std::fs::symlink_metadata(&path) else {
            continue;
        };
        if !md.is_file() {
            continue;
        }
        // `std::fs::Metadata` carries no owner on Windows, so there is no second
        // check to make there: the tag in the name is the whole scoping, which
        // is why it has to be in the name. A bundle someone still has open
        // refuses to be deleted, and the next sweep gets it.
        #[cfg(unix)]
        if md.uid() != uid {
            continue;
        }
        let _ = std::fs::remove_file(&path);
    }
}

/// Create a report under `dir` with an unpredictable, exclusively-created name.
pub(super) fn create_report_bundle(
    dir: &Path,
    files: &[(String, Vec<u8>)],
    owner: Option<&ReportRequester>,
) -> std::io::Result<PathBuf> {
    // Reclaim the caller's previous bundles first; the new one replaces them.
    sweep_prior_bundles(dir, owner);
    // The tag is what makes the sweep above find this caller's bundles and only
    // this caller's, so it has to go in every name the sweep is meant to match.
    let tag = requester_tag(owner);
    for _ in 0..16 {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let nonce: u64 = rand::random();
        let path = dir.join(format!("rayfish-report-{tag}-{timestamp}-{nonce:016x}.tgz"));
        match write_bundle(&path, files, owner) {
            Ok(()) => return Ok(path),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        "could not allocate a unique report path",
    ))
}

#[cfg(test)]
mod report_tests {
    use super::{ReportRequester, collect_recent_logs, requester_tag, sweep_prior_bundles};

    /// Some principal that is not this process, for asserting the sweep leaves
    /// other people's bundles alone.
    #[cfg(unix)]
    fn other_requester() -> ReportRequester {
        ReportRequester::Unix {
            uid: unsafe { libc::geteuid() } ^ 1,
            gid: unsafe { libc::getegid() },
        }
    }

    #[cfg(windows)]
    fn other_requester() -> ReportRequester {
        ReportRequester::Windows {
            sid: "S-1-5-21-0-0-0-4242".to_owned(),
        }
    }

    /// The identity a bundle is written for, so the sweep that reclaims it is
    /// scoped to a caller this process can actually stand in for.
    #[cfg(unix)]
    pub(super) fn current_requester() -> ReportRequester {
        // chowning a file to the uid/gid that already owns it is permitted for
        // an unprivileged owner, so this takes the success branch off root too.
        ReportRequester::Unix {
            uid: unsafe { libc::geteuid() },
            gid: unsafe { libc::getegid() },
        }
    }

    #[cfg(windows)]
    pub(super) fn current_requester() -> ReportRequester {
        ReportRequester::Windows {
            sid: crate::windows_identity::current_user_sid()
                .expect("a running process always has a user SID"),
        }
    }

    /// The bound on `/tmp`: `Report` is an open read, so without the sweep any
    /// local account could loop `ray report` and leave a fresh gzip of the
    /// daemon's debug logs behind every time. Writing the bundles here rather
    /// than going through `create_report_bundle` keeps the test on both
    /// platforms: on Windows that path demands LocalSystem or an elevated
    /// Administrator, which a test process is not.
    #[test]
    fn the_sweep_reclaims_the_requesters_earlier_bundles() {
        let dir = tempfile::tempdir().unwrap();
        let bundle = |who: &ReportRequester, nonce: &str| {
            dir.path().join(format!(
                "rayfish-report-{}-1-{nonce}.tgz",
                requester_tag(Some(who))
            ))
        };
        let stale = bundle(&current_requester(), "aaaaaaaaaaaaaaaa");
        // Another principal the pipe DACL also admits. On Windows the tag is the
        // only thing keeping this file: both bundles are the test process's own,
        // so no ownership check can tell them apart there.
        let theirs = bundle(&other_requester(), "bbbbbbbbbbbbbbbb");
        let unrelated = dir.path().join("someone-elses.tgz");
        std::fs::write(&stale, b"old bundle").unwrap();
        std::fs::write(&theirs, b"not the caller's").unwrap();
        std::fs::write(&unrelated, b"not ours").unwrap();

        sweep_prior_bundles(dir.path(), Some(&current_requester()));

        assert!(!stale.exists(), "the caller's previous bundle was kept");
        assert!(theirs.exists(), "another principal's bundle was deleted");
        assert!(unrelated.exists(), "an unrelated file was deleted");
    }

    #[test]
    fn test_collect_recent_logs_missing_dir_is_empty() {
        // The log dir may not exist in CI / non-root test runs; must not panic.
        let _ = collect_recent_logs();
    }
}

/// The rest of the bundle's guarantees are POSIX ones: `O_NOFOLLOW` and
/// `O_EXCL` on the create, `fchown` to hand it over, and mode bits to keep it
/// private. Windows reaches the same end through an SDDL DACL on `CreateFileW`
/// (`windows_security::create_report_file`), which only LocalSystem or an
/// elevated Administrator may write, so there is nothing here for a test
/// process on that platform to assert.
#[cfg(all(test, unix))]
mod report_permission_tests {
    use super::report_tests::current_requester;
    use super::{create_report_bundle, write_bundle};

    #[test]
    fn test_write_bundle_is_valid_targz() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bundle.tgz");
        let files = vec![
            ("sysinfo.txt".to_string(), b"rayfish 0.1.0\n".to_vec()),
            (
                "logs/rayfish.log.2026-06-23".to_string(),
                b"hello log\n".to_vec(),
            ),
        ];
        write_bundle(&path, &files, None).unwrap();

        // Re-read it back through the gzip+tar decoders to prove it's well-formed.
        let f = std::fs::File::open(&path).unwrap();
        let dec = flate2::read::GzDecoder::new(f);
        let mut archive = tar::Archive::new(dec);
        let mut names: Vec<String> = archive
            .entries()
            .unwrap()
            .map(|e| e.unwrap().path().unwrap().to_string_lossy().into_owned())
            .collect();
        names.sort();
        assert_eq!(names, vec!["logs/rayfish.log.2026-06-23", "sysinfo.txt"]);
    }

    #[test]
    fn test_write_bundle_refuses_symlink_destination() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target");
        let path = dir.path().join("bundle.tgz");
        std::fs::write(&target, b"do not overwrite").unwrap();
        symlink(&target, &path).unwrap();

        let result = write_bundle(
            &path,
            &[("status.txt".to_string(), b"sensitive report".to_vec())],
            None,
        );

        assert!(result.is_err(), "a report destination symlink was followed");
        assert_eq!(std::fs::read(&target).unwrap(), b"do not overwrite");
    }

    /// The bundle used to be widened to 0644 even on the path that chowns it to
    /// the requester. `Report` is an open read and the archive packs the root
    /// daemon's debug logs, so that left any other local user free to read them
    /// out of `/tmp`.
    #[test]
    fn a_bundle_handed_to_its_requester_stays_private() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bundle.tgz");
        let files = vec![("status.txt".to_string(), b"peer ids and mesh ips".to_vec())];

        write_bundle(&path, &files, Some(&current_requester())).unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "report bundle is readable by other local users"
        );
    }

    /// The fallback: with nobody to give it to the bundle stays root-owned, so
    /// it has to be readable or the caller cannot collect what it asked for.
    #[test]
    fn an_unowned_bundle_is_readable() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bundle.tgz");

        write_bundle(&path, &[("status.txt".to_string(), b"x".to_vec())], None).unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o644);
    }

    /// The existing symlink test points at a file that exists, which `O_EXCL`
    /// alone refuses. A dangling link is the case that would let a planted path
    /// be created at the target, and it must be refused too. Neither test can
    /// isolate `O_NOFOLLOW` while the open also carries `O_EXCL`, which fails on
    /// any symlink: the flag is there for a future helper that opens this path
    /// without it.
    #[test]
    fn test_write_bundle_refuses_a_dangling_symlink_destination() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("not-there-yet");
        let path = dir.path().join("bundle.tgz");
        symlink(&target, &path).unwrap();

        let result = write_bundle(
            &path,
            &[("status.txt".to_string(), b"sensitive report".to_vec())],
            None,
        );

        assert!(
            result.is_err(),
            "a dangling destination symlink was followed"
        );
        assert!(!target.exists(), "the symlink target was created");
    }

    /// A random name per call closed the symlink hole but removed the only
    /// bound on `/tmp`: nothing ever deleted a bundle again, and `Report` is an
    /// open read, so an unprivileged caller could loop it to fill the disk.
    #[test]
    fn a_new_bundle_reclaims_the_requesters_earlier_ones() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        // Both names carry the caller's own tag, so the sweep treats them as
        // candidates and the symlink below is actually tested rather than
        // filtered out by the name before it gets there.
        let tag = super::requester_tag(Some(&current_requester()));
        let stale = dir
            .path()
            .join(format!("rayfish-report-{tag}-1-aaaaaaaaaaaaaaaa.tgz"));
        let unrelated = dir.path().join("someone-elses.tgz");
        let victim = dir.path().join("victim");
        let planted = dir
            .path()
            .join(format!("rayfish-report-{tag}-2-bbbbbbbbbbbbbbbb.tgz"));
        std::fs::write(&stale, b"old bundle").unwrap();
        std::fs::write(&unrelated, b"not ours").unwrap();
        std::fs::write(&victim, b"do not delete").unwrap();
        // A symlink wearing the bundle name: /tmp is world-writable and this
        // runs as root, so the sweep must not follow it.
        symlink(&victim, &planted).unwrap();

        let fresh = create_report_bundle(
            dir.path(),
            &[("status.txt".to_string(), b"report".to_vec())],
            Some(&current_requester()),
        )
        .unwrap();

        assert!(!stale.exists(), "the caller's previous bundle was kept");
        assert!(fresh.exists(), "the new bundle is missing");
        assert!(unrelated.exists(), "an unrelated file was deleted");
        assert_eq!(
            std::fs::read(&victim).unwrap(),
            b"do not delete",
            "the sweep followed a planted symlink"
        );
    }
}
