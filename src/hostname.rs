//! Hostname generation, validation, and collision handling for Magic DNS.

use rand::RngExt;

use crate::network_name::NOUNS_B;

/// Placeholder names an OS hands out when it has nothing better, which several
/// machines on one mesh will share. Taking one would put the collision resolver
/// to work naming a fleet `localhost-1`, `localhost-2`, so they are refused and
/// a random name is used instead.
const PLACEHOLDERS: [&str; 3] = ["localhost", "unknown", "android"];

pub fn generate_hostname() -> String {
    let mut rng = rand::rng();
    NOUNS_B[rng.random_range(0..NOUNS_B.len())].to_string()
}

/// The hostname to take on a network when the user named none.
///
/// `configured` is the node's `default_hostname` (`ray up --hostname`), an
/// explicit choice, so it is taken as-is and any clash is left to the
/// coordinator's `-1` suffix. Without one, the name this machine already
/// answers to is the useful default: a `ray status` full of random nouns is a
/// list nobody can match back to a box. A random name is the last resort, for
/// the machine that has no usable name of its own and for the one whose name is
/// already on the roster: `laptop-1` would read as the name of the `laptop`
/// that is already there.
///
/// `taken` is the hostnames already on the network, excluding our own.
pub fn default_hostname(configured: Option<String>, taken: &[&str]) -> String {
    if let Some(name) = configured {
        return name;
    }
    match system_hostname() {
        Some(name) if !taken.contains(&name.as_str()) => name,
        _ => generate_hostname(),
    }
}

/// This machine's own name, in a form Magic DNS can carry, or `None` when the
/// OS has nothing worth using.
pub fn system_hostname() -> Option<String> {
    mesh_form(&raw_system_hostname()?)
}

/// Read the OS hostname. `None` when the call fails or the name is not UTF-8;
/// Android answers `localhost` here, which [`mesh_form`] then refuses.
fn raw_system_hostname() -> Option<String> {
    // HOST_NAME_MAX is 64 on Linux and 255 on macOS, so this cannot truncate.
    let mut buf = [0u8; 512];
    // SAFETY: `buf` is a live, writable array and its true length is what is
    // passed, which is the whole contract of `gethostname`.
    if unsafe { libc::gethostname(buf.as_mut_ptr().cast(), buf.len()) } != 0 {
        return None;
    }
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    String::from_utf8(buf[..end].to_vec()).ok()
}

/// Fold an OS hostname into a mesh one, or `None` if nothing usable is left.
///
/// An OS hostname is allowed to be things a mesh hostname is not: uppercase, a
/// full FQDN, or (on macOS) a sentence with spaces and an apostrophe in it. So
/// only the first label is kept, it is lowercased, and every other character
/// becomes a hyphen: `Alice's MacBook.local` -> `alice-s-macbook`.
fn mesh_form(raw: &str) -> Option<String> {
    let label = raw.split('.').next().unwrap_or(raw).to_ascii_lowercase();
    let mut name = String::with_capacity(label.len());
    for c in label.chars() {
        match c.is_ascii_lowercase() || c.is_ascii_digit() {
            true => name.push(c),
            // Runs collapse, or `My  Box` would come out as `my--box`.
            false if !name.ends_with('-') => name.push('-'),
            false => {}
        }
    }
    let name = name.trim_matches('-');
    let name: String = name.chars().take(63).collect();
    let name = name.trim_end_matches('-').to_string();
    match is_valid_hostname(&name) && !PLACEHOLDERS.contains(&name.as_str()) {
        true => Some(name),
        false => None,
    }
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
/// rejected (no silent rename) so no peer can claim another's name to inherit
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
    fn an_os_hostname_is_folded_into_a_mesh_one() {
        assert_eq!(mesh_form("build-box"), Some("build-box".to_string()));
        // Only the first label, and lowercased.
        assert_eq!(mesh_form("Build.example.com"), Some("build".to_string()));
        // macOS lets a hostname be a sentence.
        assert_eq!(
            mesh_form("Alice's MacBook Pro.local"),
            Some("alice-s-macbook-pro".to_string())
        );
        // Runs of junk collapse to one hyphen, and the edges are trimmed.
        assert_eq!(mesh_form("__my  box__"), Some("my-box".to_string()));
        // 63 characters is the limit, and cutting at it must not leave a
        // trailing hyphen behind.
        let long = format!("{}-{}", "a".repeat(62), "b".repeat(20));
        assert_eq!(mesh_form(&long), Some("a".repeat(62)));
    }

    #[test]
    fn a_hostname_no_machine_owns_is_refused() {
        // Placeholders half the fleet would share.
        assert_eq!(mesh_form("localhost"), None);
        assert_eq!(mesh_form("localhost.localdomain"), None);
        assert_eq!(mesh_form("Unknown"), None);
        // Nothing usable left after folding.
        assert_eq!(mesh_form(""), None);
        assert_eq!(mesh_form("???"), None);
        assert_eq!(mesh_form(".config"), None);
    }

    #[test]
    fn the_default_hostname_prefers_the_configured_name_then_this_machines() {
        // An explicit `ray up --hostname` wins outright, collision or not: the
        // coordinator's `-1` suffix is what handles that case.
        assert_eq!(
            default_hostname(Some("laptop".into()), &["laptop"]),
            "laptop"
        );

        // Without one, this machine's own name, unless the roster already has
        // it, in which case a name that is at least nobody else's.
        let Some(mine) = system_hostname() else {
            return;
        };
        assert_eq!(default_hostname(None, &["someone-else"]), mine);
        let taken = default_hostname(None, &[mine.as_str()]);
        assert_ne!(taken, mine);
        assert!(is_valid_hostname(&taken), "invalid: {taken}");
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
        // rejected (no silent rename) so a peer can't steal another's name.
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
