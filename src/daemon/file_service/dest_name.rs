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
/// at most, and the `_` [`windows_file_name`] puts before a device name.
const MAX_SAVED_NAME: usize = 255 - " (999)".len() - "_".len();

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
    // Windows counts the superscripts `¹²³` as port digits too.
    let numbered_device = stem.get(..3).is_some_and(|prefix| {
        let mut digit = stem[3..].chars();
        (prefix.eq_ignore_ascii_case("COM") || prefix.eq_ignore_ascii_case("LPT"))
            && matches!(
                (digit.next(), digit.next()),
                (Some(d), None) if d.is_ascii_digit() || matches!(d, '¹' | '²' | '³')
            )
    });
    if numbered_device || RESERVED.iter().any(|r| stem.eq_ignore_ascii_case(r)) {
        return Some(format!("_{cleaned}"));
    }
    Some(cleaned.to_string())
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

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
        assert_eq!(windows_file_name("COM¹.txt").as_deref(), Some("_COM¹.txt"));
        assert_eq!(
            windows_file_name("console.txt").as_deref(),
            Some("console.txt")
        );
        assert_eq!(windows_file_name("com10").as_deref(), Some("com10"));
        assert_eq!(windows_file_name("aaé").as_deref(), Some("aaé"));
        assert_eq!(windows_file_name("..."), None);
        assert_eq!(windows_file_name(" "), None);
    }

    /// Names as a peer could offer them: the characters that matter to the
    /// rules (dots, spaces, Windows-reserved, multi-byte), sometimes after a
    /// device name, often long enough to be cut.
    fn offered_name() -> impl Strategy<Value = String> {
        let c = prop_oneof![
            any::<char>(),
            prop::sample::select(vec![
                '.', ' ', ':', '*', '?', '"', '<', '|', 'é', '語', '\t'
            ]),
            Just('a'),
        ];
        let device = prop::sample::select(vec!["", "", "CON", "nul", "Com1", "LPT9", "COM¹"]);
        let body = prop_oneof![
            prop::collection::vec(c, 1..140).prop_map(|chars| chars.into_iter().collect()),
            (240usize..260).prop_map(|n| format!(".{}", "a".repeat(n))),
        ];
        (device, body).prop_map(|(device, body): (&str, String)| format!("{device}{body}"))
    }

    /// Names Windows gives a device, whatever follows the first dot. The
    /// superscript digits count as digits there.
    fn is_windows_device(name: &str) -> bool {
        let stem = name.split('.').next().unwrap_or(name).trim_end();
        let upper = stem.to_ascii_uppercase();
        if ["CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"].contains(&upper.as_str()) {
            return true;
        }
        let mut chars = upper.chars();
        let prefix: String = chars.by_ref().take(3).collect();
        let digit: Vec<char> = chars.collect();
        (prefix == "COM" || prefix == "LPT")
            && matches!(digit.as_slice(), [d] if d.is_ascii_digit() || matches!(d, '¹' | '²' | '³'))
    }

    const ATTEMPTS: [u32; 6] = [0, 1, 9, 10, 100, MAX_NAME_ATTEMPTS - 1];

    proptest! {
        /// A safe offered name stays one plain component after it is cut and
        /// numbered, and every numbered name fits one directory entry.
        #[test]
        fn saved_names_stay_one_entry(name in offered_name()) {
            prop_assume!(super::super::is_safe_file_name(&name));
            let fitted = fitted_name(&name);
            prop_assert!(fitted.len() <= MAX_SAVED_NAME);
            if name.len() <= MAX_SAVED_NAME {
                prop_assert_eq!(&fitted, &name);
            }
            for attempt in ATTEMPTS {
                let numbered = numbered_name(&fitted, attempt);
                prop_assert!(super::super::is_safe_file_name(&numbered), "{numbered:?}");
                prop_assert!(numbered.len() <= 255, "{} bytes", numbered.len());
            }
        }

        /// On Windows the saved name, and every numbered one, has no stream
        /// or reserved character, no trailing dot or space, is not a device,
        /// and fits 255 UTF-16 units.
        #[test]
        fn windows_names_stay_plain_files(name in offered_name()) {
            prop_assume!(super::super::is_safe_file_name(&name));
            let Some(cleaned) = windows_file_name(&fitted_name(&name)) else {
                return Ok(());
            };
            for attempt in ATTEMPTS {
                let saved = numbered_name(&cleaned, attempt);
                prop_assert!(
                    !saved.chars().any(|c| c < ' ' || "<>:\"/\\|?*".contains(c)),
                    "{saved:?}"
                );
                prop_assert!(!saved.ends_with(['.', ' ']), "{saved:?}");
                prop_assert!(!is_windows_device(&saved), "{saved:?}");
                let units = saved.encode_utf16().count();
                prop_assert!(units <= 255, "{saved:?} is {units} UTF-16 units");
            }
        }
    }
}
