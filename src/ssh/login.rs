//! Local-account lookup for mesh SSH sessions.

use std::path::PathBuf;

use anyhow::{Context, Result};
use uzers::os::unix::UserExt;

/// The resolved local account every channel on one SSH connection runs as.
pub(super) struct LoginInfo {
    pub(super) uid: u32,
    pub(super) gid: u32,
    pub(super) home: PathBuf,
    pub(super) shell: PathBuf,
    pub(super) name: String,
}

pub(super) fn resolve_login(login_user: &str) -> Result<LoginInfo> {
    let user = uzers::get_user_by_name(login_user)
        .with_context(|| format!("no such local user: {login_user}"))?;
    Ok(LoginInfo {
        uid: user.uid(),
        gid: user.primary_group_id(),
        home: user.home_dir().to_path_buf(),
        shell: user.shell().to_path_buf(),
        name: user.name().to_string_lossy().to_string(),
    })
}
