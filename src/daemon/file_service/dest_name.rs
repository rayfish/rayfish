//! Name and path decisions for a received file's destination. Free of
//! platform calls, so the rules both platform writers follow are tested on
//! every host.

use std::ffi::OsStr;
use std::io;
use std::path::{Component, Path};

/// How many `name (n).ext` alternatives to try before giving up on a name.
pub(super) const MAX_NAME_ATTEMPTS: u32 = 1000;

/// `report.pdf`, then `report (1).pdf`, `report (2).pdf`, ... A leading dot
/// is part of the stem, so `.profile` becomes `.profile (1)`.
pub(super) fn numbered_name(file_name: &str, attempt: u32) -> String {
    if attempt == 0 {
        return file_name.to_string();
    }
    match file_name.rfind('.') {
        Some(dot) if dot > 0 => {
            let (stem, ext) = file_name.split_at(dot);
            format!("{stem} ({attempt}){ext}")
        }
        _ => format!("{file_name} ({attempt})"),
    }
}

/// How many leading components of `path` are its prefix and root, which the
/// walk up to an existing directory never strips: `/` on Unix, `C:\` or
/// `\\server\share\` on Windows. At least one, so the walk always stops.
pub(super) fn root_len(path: &Path) -> usize {
    path.components()
        .take_while(|c| matches!(c, Component::Prefix(_) | Component::RootDir))
        .count()
        .max(1)
}

/// The components of `path` past its first `existing`, which are the
/// directories still to create. Each must be a plain name: anything else
/// (`..` above all) would leave the directory that was checked.
pub(super) fn missing_names(path: &Path, existing: usize) -> io::Result<Vec<&OsStr>> {
    path.components()
        .skip(existing)
        .map(|component| match component {
            Component::Normal(name) => Ok(name),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("'{}' leaves the directory it names", path.display()),
            )),
        })
        .collect()
}

/// A peer's file name in a form one Windows directory entry can hold, or
/// `None` when nothing usable is left.
///
/// The name is already a single component (`is_safe_file_name`), but Windows
/// gives more characters a meaning than Unix does. A `:` in particular names
/// an alternate data stream: `notes.txt:x` written by the daemon would land in
/// a stream of somebody else's `notes.txt`. Those characters become `_`.
/// Trailing dots and spaces, which Windows strips from a normal path, are
/// dropped, and a device name (`CON`, `NUL.txt`) gets a leading `_` so the
/// file is one Explorer can open and delete.
#[cfg(any(windows, test))]
pub(super) fn windows_file_name(name: &str) -> Option<String> {
    const RESERVED: &[&str] = &["CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"];
    let cleaned: String = name
        .chars()
        .map(|c| {
            if c < ' ' || matches!(c, '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*') {
                '_'
            } else {
                c
            }
        })
        .collect();
    let cleaned = cleaned.trim_end_matches(['.', ' ']);
    if cleaned.is_empty() {
        return None;
    }
    let stem = cleaned.split('.').next().unwrap_or(cleaned).trim_end();
    let numbered_device = match stem.as_bytes() {
        [a, b, c, digit] => {
            let prefix = [*a, *b, *c];
            (prefix.eq_ignore_ascii_case(b"COM") || prefix.eq_ignore_ascii_case(b"LPT"))
                && digit.is_ascii_digit()
        }
        _ => false,
    };
    if numbered_device || RESERVED.iter().any(|r| stem.eq_ignore_ascii_case(r)) {
        return Some(format!("_{cleaned}"));
    }
    Some(cleaned.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numbered_names_keep_the_extension() {
        assert_eq!(numbered_name("a.txt", 0), "a.txt");
        assert_eq!(numbered_name("a.txt", 2), "a (2).txt");
        assert_eq!(numbered_name("a.tar.gz", 1), "a.tar (1).gz");
        assert_eq!(numbered_name(".profile", 1), ".profile (1)");
        assert_eq!(numbered_name("README", 1), "README (1)");
    }

    #[test]
    fn missing_names_are_plain_components_only() {
        let path = Path::new("/srv/project/new/sub");
        assert_eq!(root_len(path), 1);
        assert_eq!(
            missing_names(path, 3).unwrap(),
            [OsStr::new("new"), OsStr::new("sub")]
        );
        assert!(missing_names(path, 4).unwrap() == [OsStr::new("sub")]);
        assert!(missing_names(path, 5).unwrap().is_empty());
        let escape = Path::new("/srv/missing/../x");
        assert_eq!(
            missing_names(escape, 2).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn windows_names_cannot_reach_a_stream_or_a_device() {
        assert_eq!(
            windows_file_name("report.pdf").as_deref(),
            Some("report.pdf")
        );
        assert_eq!(
            windows_file_name("notes.txt:hidden").as_deref(),
            Some("notes.txt_hidden")
        );
        assert_eq!(
            windows_file_name("Meeting 10:30 <draft>?.txt").as_deref(),
            Some("Meeting 10_30 _draft__.txt")
        );
        assert_eq!(windows_file_name("tab\there").as_deref(), Some("tab_here"));
        assert_eq!(
            windows_file_name("trailing. . ").as_deref(),
            Some("trailing")
        );
        assert_eq!(windows_file_name("CON").as_deref(), Some("_CON"));
        assert_eq!(windows_file_name("nul.txt").as_deref(), Some("_nul.txt"));
        assert_eq!(windows_file_name("com1.log").as_deref(), Some("_com1.log"));
        assert_eq!(windows_file_name("Lpt9").as_deref(), Some("_Lpt9"));
        assert_eq!(
            windows_file_name("console.txt").as_deref(),
            Some("console.txt")
        );
        assert_eq!(windows_file_name("com10").as_deref(), Some("com10"));
        assert_eq!(windows_file_name("aaé").as_deref(), Some("aaé"));
        assert_eq!(windows_file_name("..."), None);
        assert_eq!(windows_file_name(" "), None);
    }
}
