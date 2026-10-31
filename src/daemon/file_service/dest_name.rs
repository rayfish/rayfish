//! Name and path decisions for a received file's destination. Free of
//! platform calls, so the rules both platform writers follow are tested on
//! every host.

use std::ffi::OsStr;
use std::io;
use std::path::{Component, Path};

use iroh::EndpointId;

use crate::control;

/// How many `name (n).ext` alternatives to try before giving up on a name.
pub(super) const MAX_NAME_ATTEMPTS: u32 = 1000;

/// Longest name, in bytes, a received file is saved under before a number
/// is added. One directory entry holds 255 bytes on Linux and macOS and 255
/// UTF-16 units on Windows, never fewer than the UTF-8 bytes, so a byte count
/// is safe on both. Room is left for the ` (999)` that [`numbered_name`] adds
/// at most.
const MAX_SAVED_NAME: usize = 255 - " (999)".len();

/// Longest extension kept when a name is cut to fit.
const MAX_KEPT_EXTENSION: usize = 32;

/// A peer's file name cut to fit one directory entry, numbered or not. The
/// offer may name a file longer than this filesystem allows (APFS takes 255
/// characters, not bytes), which would only fail once the whole file had
/// downloaded. Cut at a character boundary, keeping a short extension.
pub(super) fn fitted_name(file_name: &str) -> String {
    if file_name.len() <= MAX_SAVED_NAME {
        return file_name.to_string();
    }
    let ext = match file_name.rfind('.') {
        Some(dot) if dot > 0 && file_name.len() - dot <= MAX_KEPT_EXTENSION => &file_name[dot..],
        _ => "",
    };
    let stem = &file_name[..file_name.len() - ext.len()];
    let cut = stem.floor_char_boundary(MAX_SAVED_NAME - ext.len());
    format!("{}{ext}", &stem[..cut])
}

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

/// The name a file being received has until it is complete, one per offer.
///
/// Derived from the sender and the offer, which together name one receive, so
/// a receive that starts again after a crash finds what it left and writes
/// over it, instead of picking a fresh name and leaving the leftover for good.
/// Two receives into one directory never share one. Short, so it fits however
/// long the real name is; a leading dot keeps it out of most file listings.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct TempName(String);

impl TempName {
    pub(super) fn for_offer(sender: &EndpointId, offer: control::FileOfferId) -> Self {
        let mut hasher = blake3::Hasher::new_derive_key("rayfish received file temporary name");
        hasher.update(sender.as_bytes());
        hasher.update(&offer.0);
        let hex = hasher.finalize().to_hex();
        Self(format!(".rayfish-{}.part", &hex.as_str()[..32]))
    }

    pub(super) fn as_str(&self) -> &str {
        &self.0
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
    fn long_names_are_cut_to_fit_with_their_number() {
        assert_eq!(fitted_name("report.pdf"), "report.pdf");
        // 300 bytes of two-byte characters, as APFS allows.
        let long = format!("{}.txt", "é".repeat(148));
        assert_eq!(long.len(), 300);
        let fitted = fitted_name(&long);
        assert!(fitted.len() <= MAX_SAVED_NAME, "{}", fitted.len());
        assert!(fitted.ends_with(".txt"), "{fitted}");
        assert!(fitted.starts_with("éé"), "{fitted}");
        let last = numbered_name(&fitted, MAX_NAME_ATTEMPTS - 1);
        assert!(last.len() <= 255, "{}", last.len());
        assert!(last.ends_with(" (999).txt"), "{last}");
        // An extension too long to be one is cut like the rest.
        let odd = format!("a.{}", "x".repeat(400));
        assert_eq!(fitted_name(&odd).len(), MAX_SAVED_NAME);
        assert!(numbered_name(&fitted_name(&odd), 999).len() <= 255);
        // Exactly at the limit, nothing changes.
        let edge = "y".repeat(MAX_SAVED_NAME);
        assert_eq!(fitted_name(&edge), edge);
    }

    #[test]
    fn a_temporary_name_belongs_to_one_offer() {
        let sender = iroh::SecretKey::generate().public();
        let offer = control::FileOfferId::new();
        let name = TempName::for_offer(&sender, offer);
        assert_eq!(name, TempName::for_offer(&sender, offer));
        assert_ne!(
            name,
            TempName::for_offer(&sender, control::FileOfferId::new())
        );
        let other = iroh::SecretKey::generate().public();
        assert_ne!(name, TempName::for_offer(&other, offer));
        assert!(name.as_str().starts_with(".rayfish-"), "{name:?}");
        assert!(name.as_str().ends_with(".part"), "{name:?}");
        assert_eq!(name.as_str().len(), 46);
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
