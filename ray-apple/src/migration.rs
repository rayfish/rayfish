use std::fs;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context, Result, bail};

static STAGING_ID: AtomicU64 = AtomicU64::new(0);

pub(crate) fn copy_legacy_state(source: &Path, destination: &Path) -> Result<()> {
    if !source.is_dir() {
        bail!("legacy Rayfish state directory is unavailable");
    }
    if source == destination {
        bail!("legacy and extension state directories are the same");
    }
    if destination.exists()
        && fs::read_dir(destination)
            .with_context(|| format!("reading {}", destination.display()))?
            .next()
            .is_some()
    {
        bail!("extension state directory is not empty");
    }

    let parent = destination
        .parent()
        .context("extension state directory has no parent")?;
    fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    let sequence = STAGING_ID.fetch_add(1, Ordering::Relaxed);
    let staging = parent.join(format!(
        ".rayfish-migration-{}-{sequence}",
        std::process::id()
    ));
    if staging.exists() {
        bail!("migration staging directory already exists");
    }

    let result = (|| {
        fs::create_dir(&staging).with_context(|| format!("creating {}", staging.display()))?;
        copy_directory(source, &staging)?;
        if destination.exists() {
            fs::remove_dir(destination)
                .with_context(|| format!("removing empty {}", destination.display()))?;
        }
        fs::rename(&staging, destination).with_context(|| {
            format!(
                "moving migrated state from {} to {}",
                staging.display(),
                destination.display()
            )
        })?;
        Ok(())
    })();
    if result.is_err() && staging.exists() {
        let _ = fs::remove_dir_all(&staging);
    }
    result
}

fn copy_directory(source: &Path, destination: &Path) -> Result<()> {
    for entry in fs::read_dir(source).with_context(|| format!("reading {}", source.display()))? {
        let entry = entry.with_context(|| format!("reading entry in {}", source.display()))?;
        let kind = entry
            .file_type()
            .with_context(|| format!("reading type of {}", entry.path().display()))?;
        let target = destination.join(entry.file_name());
        if kind.is_symlink() {
            bail!("legacy state contains a symbolic link")
        }
        if kind.is_dir() {
            fs::create_dir(&target).with_context(|| format!("creating {}", target.display()))?;
            copy_directory(&entry.path(), &target)?;
        } else if kind.is_file() {
            fs::copy(entry.path(), &target)
                .with_context(|| format!("copying {}", entry.path().display()))?;
        } else {
            bail!("legacy state contains an unsupported file type")
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn copies_a_legacy_tree_without_changing_the_source() {
        let root = tempfile::tempdir().expect("temporary directory should exist");
        let source = root.path().join("legacy");
        let destination = root.path().join("extension");
        fs::create_dir_all(source.join("networks")).expect("legacy tree should exist");
        fs::write(source.join("secret_key"), "key").expect("legacy key should write");
        fs::write(source.join("networks/home.toml"), "name = 'home'")
            .expect("legacy network should write");

        copy_legacy_state(&source, &destination).expect("migration should succeed");

        assert_eq!(
            fs::read_to_string(source.join("secret_key")).unwrap(),
            "key"
        );
        assert_eq!(
            fs::read_to_string(destination.join("secret_key")).unwrap(),
            "key"
        );
        assert_eq!(
            fs::read_to_string(destination.join("networks/home.toml")).unwrap(),
            "name = 'home'"
        );
    }

    #[test]
    fn refuses_to_replace_existing_state() {
        let root = tempfile::tempdir().expect("temporary directory should exist");
        let source = root.path().join("legacy");
        let destination = root.path().join("extension");
        fs::create_dir(&source).expect("legacy tree should exist");
        fs::write(source.join("secret_key"), "key").expect("legacy key should write");
        fs::create_dir(&destination).expect("extension tree should exist");
        fs::write(destination.join("secret_key"), "different").expect("extension key should write");

        assert!(copy_legacy_state(&source, &destination).is_err());
        assert_eq!(
            fs::read_to_string(destination.join("secret_key")).unwrap(),
            "different"
        );
    }
}
