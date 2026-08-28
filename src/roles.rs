//! Coordinator-assigned roles: the label a firewall rule targets when it means
//! a *class* of nodes rather than one machine.
//!
//! A hostname names exactly one node, so a suggested-firewall subject keyed by
//! hostname can never say "every sentry". Enumerating the class instead (a
//! `groups:` list in a `ray apply` spec) is expanded on the admin's machine
//! before publishing, so a node that joins later is not covered until someone
//! re-runs `ray apply`.
//!
//! A role fixes both. It rides the *reusable* join key, so one key minted with
//! `create --role sentry` admits a whole autoscaling group, and it is stored on the
//! member in the signed blob, so [`crate::firewall::materialize_suggestions`]
//! resolves it on every node at every blob update. Scaling the fleet needs no
//! re-apply.
//!
//! **A role is never a self-claim.** The coordinator takes it from the redeemed
//! key, exactly as it takes an authoritative hostname from an invite binding;
//! `ray join --role` only *requests* a subset of what the key already permits.
//! That is what makes a role-keyed rule safe in a way a rule keyed on a
//! self-chosen hostname is not: an unbound invite takes the joiner's own
//! `--hostname` at face value (see [`crate::invite::Invite::hostname`]).

use std::collections::BTreeSet;

use anyhow::{Result, bail};

/// Most roles one key or member may carry. The coordinator assigns them, so
/// this bounds how much a single mint can add to the signed blob.
pub const MAX_ROLES: usize = 8;

/// Longest role name. Long enough for `nonvalidating-sentry`, short enough that
/// [`MAX_ROLES`] of them stay negligible on the wire.
pub const MAX_ROLE_LEN: usize = 32;

/// Check one role name: 1..=[`MAX_ROLE_LEN`] chars of `[a-z0-9-]`, starting
/// alphanumeric.
///
/// Lowercase-only is not cosmetic. A `role:` selector in a `ray apply` spec is
/// compared byte for byte against these names, and the `config` crate preserves
/// the case its keys were written in, so nothing folds the two sides together on
/// its own: a role minted with capitals would silently never match its own rule.
/// [`normalize`] lowercases what the CLI hands in, and `apply::validate_names`
/// rejects a spec key that is not already canonical, so both sides meet in the
/// same case.
///
/// `:` is rejected along with everything else outside the set, which is what
/// stops a role named `role:sentry` from nesting the
/// [`ray_proto::policy::ROLE_PREFIX`] inside itself.
pub fn validate_role(name: &str) -> Result<()> {
    if name.is_empty() {
        bail!("a role name cannot be empty");
    }
    if name.len() > MAX_ROLE_LEN {
        bail!(
            "role '{name}' is {} chars; the limit is {MAX_ROLE_LEN}",
            name.len()
        );
    }
    if !name.starts_with(|c: char| c.is_ascii_lowercase() || c.is_ascii_digit()) {
        bail!("role '{name}' must start with a lowercase letter or digit");
    }
    if let Some(bad) = name
        .chars()
        .find(|c| !(c.is_ascii_lowercase() || c.is_ascii_digit() || *c == '-'))
    {
        bail!("role '{name}' contains '{bad}'; use lowercase letters, digits and '-'");
    }
    Ok(())
}

/// Lowercase, validate and dedupe a list of role names into the canonical set
/// stored on a key or member. A [`BTreeSet`] sorts, which keeps
/// `canonical_group_bytes` canonical: two mints listing the same roles in
/// different orders hash to the same blob.
pub fn normalize(names: &[String]) -> Result<BTreeSet<String>> {
    let mut out = BTreeSet::new();
    for raw in names {
        let name = raw.trim().to_ascii_lowercase();
        validate_role(&name)?;
        out.insert(name);
    }
    if out.len() > MAX_ROLES {
        bail!("{} roles given; the limit is {MAX_ROLES}", out.len());
    }
    Ok(out)
}

/// Canonicalize a role set that arrived over the wire.
///
/// The joiner normalizes what it asks for before sending, but an older or
/// hand-rolled client need not have, and [`grant`] compares by exact set
/// difference: an un-normalized `Sentry` reads as outside a key that grants
/// `sentry` and fails the join for no reason the operator can see. A name that
/// is still not a role after trimming and lowercasing is an error, so a
/// malformed request is refused rather than quietly dropped.
pub fn canonicalize(roles: &BTreeSet<String>) -> Result<BTreeSet<String>> {
    normalize(&roles.iter().cloned().collect::<Vec<_>>())
}

/// Narrow the roles a redeemed credential permits to the subset the joiner
/// asked for.
///
/// An empty request means "everything the key carries", which is the common
/// case: Terraform bakes one `--role sentry` key into user-data and the
/// instances run a bare `ray join <code>`. A request naming anything the key
/// does not permit is an **error**, not a silent trim: a provisioner that asks
/// for `validator` on a sentry key has a bug, and seating it quietly as a
/// sentry would hide that until someone wondered why the firewall never opened.
pub fn grant(
    permitted: &BTreeSet<String>,
    requested: &BTreeSet<String>,
) -> Result<BTreeSet<String>> {
    if requested.is_empty() {
        return Ok(permitted.clone());
    }
    let outside: Vec<&str> = requested
        .difference(permitted)
        .map(String::as_str)
        .collect();
    if !outside.is_empty() {
        bail!(
            "this key does not grant {}; it grants {}",
            outside.join(", "),
            render(permitted)
        );
    }
    Ok(requested.clone())
}

/// Render a role set for a human: `sentry, eu` (empty reads as `-`).
pub fn render(roles: &BTreeSet<String>) -> String {
    if roles.is_empty() {
        return "-".to_string();
    }
    roles.iter().cloned().collect::<Vec<_>>().join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_names_validate() {
        for ok in ["sentry", "validator", "non-validating", "s3", "a"] {
            assert!(validate_role(ok).is_ok(), "{ok} should validate");
        }
    }

    #[test]
    fn bad_names_are_rejected() {
        for bad in ["", "-lead", "Sentry", "role:sentry", "a b", "sen_try", "é"] {
            assert!(validate_role(bad).is_err(), "{bad:?} should not validate");
        }
    }

    #[test]
    fn a_name_at_the_limit_passes_and_one_over_fails() {
        let at = "a".repeat(MAX_ROLE_LEN);
        let over = "a".repeat(MAX_ROLE_LEN + 1);
        assert!(validate_role(&at).is_ok());
        assert!(validate_role(&over).is_err());
    }

    /// The mint side takes free-form CLI input, so it canonicalizes; the spec
    /// side is validated to be canonical already (`apply::validate_role_key`).
    /// Both land on the same name or a `--role Sentry` key would never match
    /// its rule.
    #[test]
    fn normalize_lowercases_trims_and_dedupes() {
        let got = normalize(&[
            "Sentry".to_string(),
            " sentry ".to_string(),
            "EU".to_string(),
        ])
        .unwrap();
        assert_eq!(
            got,
            ["eu".to_string(), "sentry".to_string()]
                .into_iter()
                .collect::<BTreeSet<_>>()
        );
    }

    /// Ordering must not reach the blob: the set sorts, so two mints listing the
    /// same roles differently produce identical canonical bytes.
    #[test]
    fn normalize_is_order_independent() {
        let a = normalize(&["sentry".to_string(), "eu".to_string()]).unwrap();
        let b = normalize(&["eu".to_string(), "sentry".to_string()]).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn too_many_roles_is_rejected() {
        let many: Vec<String> = (0..=MAX_ROLES).map(|i| format!("r{i}")).collect();
        assert!(normalize(&many).is_err());
        let just_enough: Vec<String> = (0..MAX_ROLES).map(|i| format!("r{i}")).collect();
        assert!(normalize(&just_enough).is_ok());
    }

    /// Dedupe happens before the count check, so a repeated role is not a way to
    /// trip the limit.
    #[test]
    fn duplicates_do_not_count_towards_the_limit() {
        let dupes: Vec<String> = std::iter::repeat_n("sentry".to_string(), MAX_ROLES + 4).collect();
        assert_eq!(normalize(&dupes).unwrap().len(), 1);
    }

    fn set(names: &[&str]) -> BTreeSet<String> {
        names.iter().map(|s| s.to_string()).collect()
    }

    /// The Terraform shape: one key, a bare `ray join`, every instance seated
    /// with everything the key carries.
    #[test]
    fn an_empty_request_takes_the_whole_key() {
        let permitted = set(&["sentry", "eu"]);
        assert_eq!(grant(&permitted, &BTreeSet::new()).unwrap(), permitted);
    }

    #[test]
    fn a_subset_request_narrows_the_grant() {
        let permitted = set(&["sentry", "eu"]);
        assert_eq!(
            grant(&permitted, &set(&["sentry"])).unwrap(),
            set(&["sentry"])
        );
    }

    /// The property the whole design rests on: asking for a role the key does
    /// not carry fails the join instead of granting it.
    #[test]
    fn a_role_outside_the_key_is_refused() {
        let err = grant(&set(&["sentry"]), &set(&["validator"])).unwrap_err();
        assert!(err.to_string().contains("validator"), "{err}");
    }

    /// Refused as a whole, not trimmed to the permitted part: a half-granted
    /// join would look like it worked.
    #[test]
    fn a_partly_permitted_request_is_refused_entirely() {
        assert!(grant(&set(&["sentry"]), &set(&["sentry", "validator"])).is_err());
    }

    /// A key with no roles grants none, and cannot be talked into any.
    #[test]
    fn a_key_without_roles_grants_nothing() {
        assert!(
            grant(&BTreeSet::new(), &BTreeSet::new())
                .unwrap()
                .is_empty()
        );
        assert!(grant(&BTreeSet::new(), &set(&["sentry"])).is_err());
    }

    /// The join path's half of the case rule: a key minted `--role Sentry` is
    /// stored as `sentry`, so a request spelled `Sentry` has to land there too
    /// or `grant` refuses a role the key actually carries.
    #[test]
    fn canonicalize_matches_what_the_mint_stored() {
        let permitted = normalize(&["Sentry".to_string()]).unwrap();
        let requested = canonicalize(&set(&["Sentry"])).unwrap();
        assert_eq!(grant(&permitted, &requested).unwrap(), set(&["sentry"]));
    }

    #[test]
    fn canonicalize_rejects_a_name_that_is_not_a_role() {
        assert!(canonicalize(&set(&["not a role"])).is_err());
    }

    #[test]
    fn render_reads_as_a_list() {
        assert_eq!(render(&BTreeSet::new()), "-");
        let roles: BTreeSet<String> = ["sentry".to_string(), "eu".to_string()].into();
        assert_eq!(render(&roles), "eu, sentry");
    }
}
