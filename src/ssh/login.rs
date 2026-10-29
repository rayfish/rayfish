//! Local-account lookup for mesh SSH sessions.

use std::ffi::CString;
use std::path::PathBuf;

use anyhow::{Context, Result};
use uzers::os::unix::UserExt;

use super::session_env::group_list;

/// The resolved local account every channel on one SSH connection runs as.
pub(super) struct LoginInfo {
    pub(super) uid: u32,
    pub(super) gid: u32,
    pub(super) home: PathBuf,
    pub(super) shell: PathBuf,
    pub(super) name: String,
    /// Supplementary groups, primary first, resolved once here so dropping
    /// privileges later never waits on NSS.
    pub(super) groups: Vec<libc::gid_t>,
}

pub(super) fn resolve_login(login_user: &str) -> Result<LoginInfo> {
    let user = uzers::get_user_by_name(login_user)
        .with_context(|| format!("no such local user: {login_user}"))?;
    let c_name = CString::new(user.name().as_encoded_bytes()).context("user name contains NUL")?;
    let groups = group_list(&c_name, user.primary_group_id())?;
    Ok(LoginInfo {
        groups,
        uid: user.uid(),
        gid: user.primary_group_id(),
        home: user.home_dir().to_path_buf(),
        shell: user.shell().to_path_buf(),
        name: user.name().to_string_lossy().to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn groups_are_resolved_once_at_login() {
        // Every helper and session drops to these groups; looking them up per
        // call puts an NSS round trip (sssd, LDAP) outside any deadline.
        let name = uzers::get_current_username().expect("a passwd entry");
        let info = resolve_login(&name.to_string_lossy()).expect("login");
        assert!(info.groups.contains(&info.gid), "groups: {:?}", info.groups);
    }
}
