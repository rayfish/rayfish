use std::fs;
use std::path::Path;

use anyhow::{Context, Result, bail};

const MIGRATION_MARKER: &str = ".legacy-state-migrated";

pub(crate) fn copy_legacy_state(source: &Path, destination: &Path) -> Result<()> {
    let source_type = fs::symlink_metadata(source)
        .with_context(|| format!("reading {}", source.display()))?
        .file_type();
    if source_type.is_symlink() || !source_type.is_dir() {
        bail!("legacy Rayfish state directory is unavailable");
    }
    if source == destination {
        bail!("legacy and extension state directories are the same");
    }
    if destination.exists()
        && fs::symlink_metadata(destination)
            .with_context(|| format!("reading {}", destination.display()))?
            .file_type()
            .is_symlink()
    {
        bail!("extension state directory must not be a symbolic link");
    }
    if destination.join(MIGRATION_MARKER).is_file() {
        return Ok(());
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
    let staging = tempfile::Builder::new()
        .prefix(".rayfish-migration-")
        .tempdir_in(parent)
        .context("creating migration staging directory")?;
    copy_directory(source, staging.path())?;
    fs::write(staging.path().join(MIGRATION_MARKER), "migrated\n")
        .context("writing migration marker")?;
    if destination.exists() {
        fs::remove_dir(destination)
            .with_context(|| format!("removing empty {}", destination.display()))?;
    }
    fs::rename(staging.path(), destination).with_context(|| {
        format!(
            "moving migrated state from {} to {}",
            staging.path().display(),
            destination.display()
        )
    })
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
    fn completed_migration_is_not_repeated() {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("legacy");
        let destination = root.path().join("extension");
        fs::create_dir(&source).unwrap();
        fs::write(source.join("secret_key"), "original").unwrap();
        copy_legacy_state(&source, &destination).unwrap();
        fs::write(source.join("secret_key"), "changed").unwrap();
        copy_legacy_state(&source, &destination).unwrap();
        assert_eq!(
            fs::read_to_string(destination.join("secret_key")).unwrap(),
            "original"
        );
    }

    #[cfg(unix)]
    #[test]
    fn failed_copy_removes_staging_and_leaves_destination_empty() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("legacy");
        let destination = root.path().join("extension");
        fs::create_dir(&source).unwrap();
        fs::create_dir(&destination).unwrap();
        symlink("missing", source.join("symlink")).unwrap();
        assert!(copy_legacy_state(&source, &destination).is_err());
        assert!(fs::read_dir(&destination).unwrap().next().is_none());
        assert_eq!(fs::read_dir(root.path()).unwrap().count(), 2);
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

    #[cfg(unix)]
    #[test]
    fn refuses_a_symlinked_legacy_directory() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().expect("temporary directory should exist");
        let source = root.path().join("legacy");
        let linked_source = root.path().join("linked-legacy");
        let destination = root.path().join("extension");
        fs::create_dir(&source).expect("legacy tree should exist");
        symlink(&source, &linked_source).expect("legacy symlink should exist");

        assert!(copy_legacy_state(&linked_source, &destination).is_err());
        assert!(!destination.exists());
    }
}
