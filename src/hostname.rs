//! Hostname generation, validation, and collision handling for Magic DNS.

use rand::RngExt;

use crate::network_name::NOUNS_B;

pub fn generate_hostname() -> String {
    let mut rng = rand::rng();
    NOUNS_B[rng.random_range(0..NOUNS_B.len())].to_string()
}

pub fn is_valid_hostname(name: &str) -> bool {
    if name.is_empty() || name.len() > 63 {
        return false;
    }
    if name.starts_with('-') || name.ends_with('-') {
        return false;
    }
    name.chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

/// Decide the hostname to assign an admitted peer.
///
/// `authoritative` names come from an invite binding (`ray invite --hostname`):
/// they are assigned verbatim, and a clash with a *different* identity is
/// rejected — no silent rename — so no peer can claim another's name to inherit
/// its suggested firewall rules. A joiner-chosen (non-authoritative) name keeps
/// collision-resolution (`alice` → `alice-1` → …).
///
/// `taken` must already exclude the joining identity's own current name.
/// Returns `Ok(assigned)` or `Err(conflicting_name)` when an authoritative name
/// is already in use.
pub fn admission_hostname(
    desired: &str,
    taken: &[&str],
    authoritative: bool,
) -> Result<String, String> {
    if authoritative {
        if taken.contains(&desired) {
            return Err(desired.to_string());
        }
        return Ok(desired.to_string());
    }
    Ok(resolve_collision(desired, taken))
}

pub fn resolve_collision(desired: &str, taken: &[&str]) -> String {
    if !taken.contains(&desired) {
        return desired.to_string();
    }
    for i in 1u32.. {
        let candidate = format!("{desired}-{i}");
        if !taken.contains(&candidate.as_str()) {
            return candidate;
        }
    }
    unreachable!()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_hostname_is_valid() {
        for _ in 0..100 {
            let h = generate_hostname();
            assert!(is_valid_hostname(&h), "invalid: {h}");
        }
    }

    #[test]
    fn valid_hostnames() {
        assert!(is_valid_hostname("alice"));
        assert!(is_valid_hostname("my-host"));
        assert!(is_valid_hostname("host2"));
        assert!(is_valid_hostname("a"));
    }

    #[test]
    fn invalid_hostnames() {
        assert!(!is_valid_hostname(""));
        assert!(!is_valid_hostname("-start"));
        assert!(!is_valid_hostname("end-"));
        assert!(!is_valid_hostname("UPPER"));
        assert!(!is_valid_hostname("has space"));
        assert!(!is_valid_hostname("has.dot"));
        let long = "a".repeat(64);
        assert!(!is_valid_hostname(&long));
    }

    #[test]
    fn collision_no_conflict() {
        assert_eq!(resolve_collision("alice", &["bob"]), "alice");
    }

    #[test]
    fn collision_appends_number() {
        assert_eq!(resolve_collision("alice", &["alice"]), "alice-1");
        assert_eq!(resolve_collision("alice", &["alice", "alice-1"]), "alice-2");
    }

    #[test]
    fn admission_authoritative_rejects_collision() {
        // An invite-bound (authoritative) name already taken by someone else is
        // rejected — no silent rename — so a peer can't steal another's name.
        assert_eq!(
            admission_hostname("alice", &["alice"], true),
            Err("alice".to_string())
        );
    }

    #[test]
    fn admission_authoritative_free_name_assigned_as_is() {
        // An authoritative name nobody holds is assigned verbatim (no rename).
        assert_eq!(
            admission_hostname("alice", &["bob"], true),
            Ok("alice".to_string())
        );
    }

    #[test]
    fn admission_free_name_collision_is_renamed() {
        // A joiner-chosen (non-authoritative) name keeps collision-rename.
        assert_eq!(
            admission_hostname("alice", &["alice"], false),
            Ok("alice-1".to_string())
        );
        assert_eq!(
            admission_hostname("alice", &["bob"], false),
            Ok("alice".to_string())
        );
    }
}
