//! The Windows operator SID file: which local account may run mutating
//! commands without elevation.

use super::*;

pub(super) const OPERATOR_SID_FILE: &str = "operator.sid";

pub(super) const OPERATOR_LOCK_FILE: &str = "operator.sid.lock";

pub(super) fn operator_sid_at(path: &Path) -> Result<Option<String>> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).context("inspect operator SID"),
    };
    anyhow::ensure!(
        !metadata.file_type().is_symlink(),
        "operator SID is a reparse point"
    );
    use std::io::Read;
    #[cfg(not(test))]
    let mut file = crate::windows_security::open_protected_file_no_follow(path)?;
    #[cfg(test)]
    let mut file = std::fs::File::open(path)?;
    let mut sid = String::new();
    file.read_to_string(&mut sid)?;
    let sid = sid.trim().to_string();
    Ok((!sid.is_empty()).then_some(sid))
}

pub(super) fn lock_operator(dir: &Path) -> Result<crate::windows_security::OperatorFileLock> {
    crate::windows_security::lock_operator_file(&dir.join(OPERATOR_LOCK_FILE))
}

pub fn operator_sid() -> Result<Option<String>> {
    let path = config_dir()?.join(OPERATOR_SID_FILE);
    operator_sid_at(&path)
}

pub fn set_operator_sid(sid: &str) -> Result<()> {
    crate::windows_security::pipe_descriptor(Some(sid))?;
    let dir = config_dir()?;
    let _lock = lock_operator(&dir)?;
    let path = dir.join(OPERATOR_SID_FILE);
    write_atomic(&path, &format!("{sid}\n"), true)
}

/// Atomically record the first Windows operator without replacing an existing
/// non-empty SID. Returns `true` only to the process that won the claim.
pub fn claim_operator_sid(sid: &str) -> Result<bool> {
    crate::windows_security::pipe_descriptor(Some(sid))?;
    let dir = config_dir()?;
    let _lock = lock_operator(&dir)?;
    let path = dir.join(OPERATOR_SID_FILE);
    if operator_sid_at(&path)?.is_some() {
        return Ok(false);
    }
    if path.exists() && std::fs::metadata(&path)?.len() == 0 {
        std::fs::remove_file(&path).context("remove incomplete operator SID claim")?;
    }
    let tmp = windows_config_stage_path(&dir, OPERATOR_SID_FILE);
    let result = (|| -> Result<bool> {
        use std::io::Write;
        let mut file = create_windows_config_stage(&tmp)?;
        writeln!(file, "{sid}").context("write operator SID claim")?;
        file.sync_all().context("flush operator SID claim")?;
        drop(file);
        crate::windows_security::move_no_replace(&tmp, &path)
    })();
    if tmp.exists() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

/// Compensate only the exact claim made by this process. A concurrent explicit
/// recovery that changed the operator is never removed.
pub fn remove_operator_sid_if_matches(sid: &str) -> Result<bool> {
    let dir = config_dir()?;
    let _lock = lock_operator(&dir)?;
    let path = dir.join(OPERATOR_SID_FILE);
    if operator_sid_at(&path)?.as_deref() != Some(sid) {
        return Ok(false);
    }
    std::fs::remove_file(path).context("remove failed operator SID claim")?;
    Ok(true)
}

/// Restore an operator value only if nobody replaced the value being
/// compensated. Used by service-restart recovery to avoid stale rollback.
pub fn replace_operator_sid_if_matches(expected: &str, replacement: Option<&str>) -> Result<bool> {
    if let Some(sid) = replacement {
        crate::windows_security::pipe_descriptor(Some(sid))?;
    }
    let dir = config_dir()?;
    let _lock = lock_operator(&dir)?;
    let path = dir.join(OPERATOR_SID_FILE);
    if operator_sid_at(&path)?.as_deref() != Some(expected) {
        return Ok(false);
    }
    match replacement {
        Some(sid) => write_atomic(&path, &format!("{sid}\n"), true)?,
        None => std::fs::remove_file(&path).context("remove compensated operator SID")?,
    }
    Ok(true)
}
