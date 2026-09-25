//! Filesystem permission checks for SSH-owned unix sockets.

use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;

use anyhow::{Context, Result};

use super::login::LoginInfo;

/// Whether the login account has every requested permission bit on `path`.
pub(super) fn account_can(path: &Path, info: &LoginInfo, want: u32) -> bool {
    if info.uid == 0 {
        return true;
    }
    let Ok(metadata) = std::fs::metadata(path) else {
        return false;
    };
    let mode = metadata.permissions().mode();
    let bits = if metadata.uid() == info.uid {
        (mode >> 6) & 7
    } else if metadata.gid() == info.gid || in_group(info, metadata.gid()) {
        (mode >> 3) & 7
    } else {
        mode & 7
    };
    bits & want == want
}

fn in_group(info: &LoginInfo, gid: u32) -> bool {
    uzers::get_user_groups(&info.name, info.gid)
        .map(|groups| groups.iter().any(|group| group.gid() == gid))
        .unwrap_or(false)
}

/// Make a root-created socket or directory owned and usable by the login account.
pub(super) fn hand_over(path: &Path, info: &LoginInfo, mode: u32) -> Result<()> {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .with_context(|| format!("setting mode on {}", path.display()))?;
    std::os::unix::fs::chown(path, Some(info.uid), Some(info.gid))
        .with_context(|| format!("handing {} to {}", path.display(), info.name))?;
    Ok(())
}
