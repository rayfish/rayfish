//! One-time invite codes (coordinator-only).
//!
//! An invite is a single-use, expiring credential that lets a new machine join a
//! closed network without live operator approval. The coordinator mints invites
//! and is the *only* node that can verify and burn them: the ledger lives on the
//! coordinator's machine at `~/.config/rayfish/invites/<network>.toml` and is
//! never published into the GroupBlob.
//!
//! The invite *code* handed to a joiner is `bs58(network_pubkey || coordinator ||
//! secret || checksum)` (see [`encode_invite_code`]). The joiner decodes it, dials
//! the coordinator directly, and presents the secret; the coordinator hashes the
//! secret, looks it up in the ledger, and burns it. Codes minted before the
//! checksum existed still decode.

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use iroh::EndpointId;
use serde::{Deserialize, Serialize};

/// Length of the random invite secret, in bytes (128 bits).
pub const SECRET_LEN: usize = 16;

/// Lifecycle state of a single invite.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum InviteStatus {
    /// Minted and not yet used.
    Pending,
    /// Consumed by a machine (single-use; burned).
    Redeemed { by: EndpointId, at: u64 },
    /// Revoked by the coordinator before being used.
    Revoked,
}

/// A single invite record. `secret_hash` (not the secret) is persisted, like a
/// password hash: the raw secret only ever exists in the code handed to the joiner.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Invite {
    /// Short human id: the first 8 hex chars of `blake3(secret)`.
    pub id: String,
    /// Full hex `blake3(secret)`, used to match a presented secret.
    pub secret_hash: String,
    /// Unix seconds when minted.
    pub created: u64,
    /// Unix seconds after which the invite is no longer redeemable.
    pub expires: u64,
    pub status: InviteStatus,
    /// Hostname the coordinator assigns authoritatively on redemption (trusted
    /// networks). `None` = the joiner's `--hostname` claim is used as before.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    /// Roles the coordinator assigns on redemption. Unlike [`Self::hostname`]
    /// there is no "the joiner's claim stands" fallback: a role is only ever
    /// what the credential grants.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub roles: BTreeSet<String>,
}

/// What redeeming a credential grants the joiner. Everything here is the
/// coordinator's assignment, never the joiner's claim, which is what lets a
/// firewall rule key on it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Grant {
    /// Hostname to assign authoritatively. `None` leaves the joiner's own
    /// `--hostname` claim standing (and subject to collision-rename).
    pub hostname: Option<String>,
    /// Roles to assign, already validated at mint time.
    pub roles: BTreeSet<String>,
}

/// On-disk container (so the toml file has a stable `[[invites]]` shape).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct InviteFile {
    #[serde(default)]
    invites: Vec<Invite>,
}

/// A flattened, display-ready view of an invite (used for `ray invite list`).
pub struct InviteView {
    pub id: String,
    /// One of `pending`, `redeemed`, `revoked`, `expired`.
    pub status: String,
    pub created: u64,
    pub expires: u64,
    /// Short id of the redeemer, when redeemed.
    pub redeemer: Option<String>,
    /// Hostname the coordinator assigns on redemption (trusted networks).
    pub hostname: Option<String>,
}

/// The coordinator's invite ledger for one network, backed by a toml file.
pub struct InviteStore {
    path: PathBuf,
    invites: Vec<Invite>,
}

/// Current Unix time in seconds. Invite expiry uses wall-clock time, so a large
/// backward clock adjustment on the coordinator could briefly un-expire an
/// invite (or a forward jump expire one early), acceptable for a TTL credential.
fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Hex blake3 of a secret: the canonical `secret_hash` form the ledger stores
/// and the form gossiped to co-coordinators (as UTF-8 bytes on the wire).
pub(crate) fn hash_secret(secret: &[u8]) -> String {
    blake3::hash(secret).to_hex().to_string()
}

/// Generate a fresh random invite secret.
pub fn generate_secret() -> [u8; SECRET_LEN] {
    rand::random()
}

/// Path to a network's invite ledger: `<config_dir>/invites/<network>.toml`.
pub fn invite_path(network: &str) -> Result<PathBuf> {
    let dir = crate::config::config_dir()?.join("invites");
    Ok(dir.join(format!("{network}.toml")))
}

/// Payload of an invite code, before the checksum: two keys and the secret.
const PAYLOAD_LEN: usize = 32 + 32 + SECRET_LEN;
/// Bytes of blake3 appended as an integrity check (see [`encode_invite_code`]).
const CHECKSUM_LEN: usize = 4;

/// The checksum appended to an invite code: the leading bytes of the payload's
/// blake3 hash. Not a security control (the payload is public and anyone can
/// recompute it), purely error detection so a truncated or mistyped code fails
/// as "invalid invite code" instead of decoding into a plausible-looking
/// invite for a network that doesn't exist.
fn invite_checksum(payload: &[u8]) -> [u8; CHECKSUM_LEN] {
    let hash = blake3::hash(payload);
    let mut out = [0u8; CHECKSUM_LEN];
    out.copy_from_slice(&hash.as_bytes()[..CHECKSUM_LEN]);
    out
}

/// Encode an invite code:
/// `bs58(network_pubkey(32) || coordinator(32) || secret(16) || checksum(4))`.
///
/// base58 carries no error detection of its own, so the trailing checksum is
/// what makes a mangled code fail cleanly: without it, dropping a character
/// divides the encoded number by 58 and can still land on a payload of the
/// right length, which then decodes into a well-formed invite pointing
/// nowhere.
pub fn encode_invite_code(
    network_pubkey: &EndpointId,
    coordinator: &EndpointId,
    secret: &[u8],
) -> String {
    let mut bytes = Vec::with_capacity(PAYLOAD_LEN + CHECKSUM_LEN);
    bytes.extend_from_slice(network_pubkey.as_bytes());
    bytes.extend_from_slice(coordinator.as_bytes());
    bytes.extend_from_slice(secret);
    bytes.extend_from_slice(&invite_checksum(&bytes));
    bs58::encode(&bytes).into_string()
}

/// Decode an invite code into `(network_pubkey, coordinator, secret)`.
///
/// Accepts both the checksummed form and the older unchecksummed one, so codes
/// minted before the checksum existed (and codes minted by a peer still on an
/// older build) keep working. A code carrying a checksum must have a correct
/// one.
pub fn decode_invite_code(code: &str) -> Result<(EndpointId, EndpointId, Vec<u8>)> {
    let bytes = bs58::decode(code.trim())
        .into_vec()
        .map_err(|e| anyhow::anyhow!("invalid invite code: {e}"))?;

    let payload = match bytes.len() {
        PAYLOAD_LEN => &bytes[..],
        len if len == PAYLOAD_LEN + CHECKSUM_LEN => {
            let (payload, checksum) = bytes.split_at(PAYLOAD_LEN);
            if checksum != invite_checksum(payload) {
                bail!("invalid invite code: checksum mismatch (was it copied in full?)");
            }
            payload
        }
        len => bail!(
            "invalid invite code: expected {} bytes, got {len}",
            PAYLOAD_LEN + CHECKSUM_LEN,
        ),
    };

    let net: [u8; 32] = payload[0..32].try_into().unwrap();
    let coord: [u8; 32] = payload[32..64].try_into().unwrap();
    let secret = payload[64..].to_vec();
    let network_pubkey = EndpointId::from_bytes(&net)
        .map_err(|e| anyhow::anyhow!("invalid network key in invite: {e}"))?;
    let coordinator = EndpointId::from_bytes(&coord)
        .map_err(|e| anyhow::anyhow!("invalid coordinator key in invite: {e}"))?;
    Ok((network_pubkey, coordinator, secret))
}

impl InviteStore {
    /// Load a network's ledger, returning an empty store if the file is absent.
    pub fn load(network: &str) -> Result<Self> {
        let path = invite_path(network)?;
        Self::from_path(path)
    }

    fn from_path(path: PathBuf) -> Result<Self> {
        let invites = if path.exists() {
            let contents = std::fs::read_to_string(&path)
                .with_context(|| format!("reading {}", path.display()))?;
            let file: InviteFile =
                toml::from_str(&contents).with_context(|| format!("parsing {}", path.display()))?;
            file.invites
        } else {
            Vec::new()
        };
        Ok(Self { path, invites })
    }

    /// Test-only constructor that backs the store with an explicit path.
    #[cfg(test)]
    pub fn with_path(path: impl AsRef<std::path::Path>) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
            invites: Vec::new(),
        }
    }

    fn save(&self) -> Result<()> {
        let file = InviteFile {
            invites: self.invites.clone(),
        };
        let contents = toml::to_string_pretty(&file).context("serializing invites")?;
        // The ledger holds only hashes, never raw secrets, but it does expose
        // invite metadata (expiry, redeemers, bound hostnames); treat it as
        // secret-bearing (owner-only 0600), written atomically.
        crate::config::write_file(&self.path, contents.as_bytes(), true)
    }

    /// Mint a new invite valid for `ttl`, persist it, and return `(secret, id)`.
    /// The raw secret is returned only here so it can be encoded into the code.
    /// `grant` is what redemption assigns: a hostname (trusted networks, so the
    /// holder joins with `ray join <code>` and no `--hostname`) and any roles.
    pub fn mint(&mut self, ttl: Duration, grant: Grant) -> Result<([u8; SECRET_LEN], String)> {
        let secret = generate_secret();
        let secret_hash = hash_secret(&secret);
        let id = secret_hash[..8].to_string();
        let created = now_secs();
        let expires = created.saturating_add(ttl.as_secs());
        self.invites.push(Invite {
            id: id.clone(),
            secret_hash,
            created,
            expires,
            status: InviteStatus::Pending,
            hostname: grant.hostname,
            roles: grant.roles,
        });
        self.save()?;
        Ok((secret, id))
    }

    /// Verify a presented secret and burn it (single-use). Errors if the secret is
    /// unknown, already used, revoked, or expired. Returns what the invite
    /// grants (hostname, roles) so the coordinator can assign it.
    pub fn redeem(&mut self, secret: &[u8], by: EndpointId) -> Result<Grant> {
        let hash = hash_secret(secret);
        let now = now_secs();
        let invite = self
            .invites
            .iter_mut()
            .find(|i| i.secret_hash == hash)
            .context("invalid invite")?;
        match &invite.status {
            InviteStatus::Pending => {}
            InviteStatus::Redeemed { .. } => bail!("invite already used"),
            InviteStatus::Revoked => bail!("invite revoked"),
        }
        if now >= invite.expires {
            bail!("invite expired");
        }
        let grant = Grant {
            hostname: invite.hostname.clone(),
            roles: invite.roles.clone(),
        };
        invite.status = InviteStatus::Redeemed { by, at: now };
        self.save()?;
        Ok(grant)
    }

    /// Un-burn an invite: revert a `Redeemed` record back to `Pending`. Used when
    /// admission fails *after* the secret was burned (e.g. a hostname/IP collision
    /// rejects the join), so the legitimate holder isn't locked out. No-op for an
    /// unknown or non-`Redeemed` secret. Must be called under the same lock as
    /// [`redeem`].
    pub fn restore(&mut self, secret: &[u8]) -> Result<()> {
        let hash = hash_secret(secret);
        if let Some(invite) = self.invites.iter_mut().find(|i| i.secret_hash == hash)
            && matches!(invite.status, InviteStatus::Redeemed { .. })
        {
            invite.status = InviteStatus::Pending;
            self.save()?;
        }
        Ok(())
    }

    /// Revoke an unused invite by id (exact match, or unambiguous prefix).
    pub fn revoke(&mut self, id: &str) -> Result<()> {
        let matches: Vec<usize> = self
            .invites
            .iter()
            .enumerate()
            .filter(|(_, i)| i.id == id || i.id.starts_with(id))
            .map(|(idx, _)| idx)
            .collect();
        let idx = match matches.as_slice() {
            [] => bail!("no invite matching '{id}'"),
            [idx] => *idx,
            _ => bail!("ambiguous invite id '{id}'"),
        };
        if matches!(self.invites[idx].status, InviteStatus::Redeemed { .. }) {
            bail!("cannot revoke an already-used invite");
        }
        self.invites[idx].status = InviteStatus::Revoked;
        self.save()?;
        Ok(())
    }

    /// Insert an invite known only by its hash (shared from another coordinator).
    /// Idempotent: a no-op if an entry with this `id` already exists.
    /// The `secret_hash` is the full hex blake3 of the secret (same format as
    /// `mint` stores internally). This lets a co-coordinator redeem an invite it
    /// did not mint, when the originating coordinator shares the hash out-of-band.
    pub fn record_shared(&mut self, id: String, secret_hash: String, expires: u64) -> Result<()> {
        if self.invites.iter().any(|i| i.id == id) {
            return Ok(());
        }
        self.invites.push(Invite {
            id,
            secret_hash,
            created: now_secs(),
            expires,
            status: InviteStatus::Pending,
            hostname: None,
            roles: BTreeSet::new(),
        });
        self.save()
    }

    /// Mark the invite whose `secret_hash` matches `secret_hash` as redeemed.
    /// Returns `true` if state changed (was `Pending`), `false` if already
    /// `Redeemed`/`Revoked` or absent. Used by a co-coordinator that learns the
    /// invite was consumed by another coordinator in the same network.
    pub fn burn_by_hash(&mut self, secret_hash: &str) -> Result<bool> {
        let mut changed = false;
        for inv in self.invites.iter_mut() {
            if inv.secret_hash == secret_hash {
                if matches!(inv.status, InviteStatus::Pending) {
                    inv.status = InviteStatus::Redeemed {
                        by: EndpointId::from_bytes(&[0u8; 32]).expect("zero bytes are a valid key"),
                        at: now_secs(),
                    };
                    changed = true;
                }
                break;
            }
        }
        if changed {
            self.save()?;
        }
        Ok(changed)
    }

    /// Display view of all invites; lazily reports expired-but-pending as `expired`
    /// without mutating the stored status.
    pub fn list(&self) -> Vec<InviteView> {
        let now = now_secs();
        self.invites
            .iter()
            .map(|i| {
                let (status, redeemer) = match &i.status {
                    InviteStatus::Redeemed { by, .. } => {
                        ("redeemed".to_string(), Some(by.fmt_short().to_string()))
                    }
                    InviteStatus::Revoked => ("revoked".to_string(), None),
                    InviteStatus::Pending if now >= i.expires => ("expired".to_string(), None),
                    InviteStatus::Pending => ("pending".to_string(), None),
                };
                InviteView {
                    id: i.id.clone(),
                    status,
                    created: i.created,
                    expires: i.expires,
                    redeemer,
                    hostname: i.hostname.clone(),
                }
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_id(seed: u8) -> EndpointId {
        let mut key_bytes = [0u8; 32];
        key_bytes[0] = seed;
        iroh::SecretKey::from(key_bytes).public()
    }

    fn temp_store() -> (InviteStore, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("net.toml");
        (InviteStore::with_path(path), dir)
    }

    #[test]
    fn code_roundtrip() {
        let net = test_id(1);
        let coord = test_id(2);
        let secret = generate_secret();
        let code = encode_invite_code(&net, &coord, &secret);
        let (dn, dc, ds) = decode_invite_code(&code).unwrap();
        assert_eq!(dn, net);
        assert_eq!(dc, coord);
        assert_eq!(ds, secret.to_vec());
    }

    #[test]
    fn decode_rejects_bad_length() {
        // A 32-byte bs58 string (a bare room id) is not a valid invite.
        let code = bs58::encode(test_id(1).as_bytes()).into_string();
        assert!(decode_invite_code(&code).is_err());
    }

    /// Codes minted before the checksum was added (and by peers still on an
    /// older build) carry no checksum and must keep working.
    #[test]
    fn decode_accepts_legacy_unchecksummed_code() {
        let (net, coord, secret) = (test_id(1), test_id(2), generate_secret());
        let mut bytes = Vec::new();
        bytes.extend_from_slice(net.as_bytes());
        bytes.extend_from_slice(coord.as_bytes());
        bytes.extend_from_slice(&secret);
        let legacy = bs58::encode(&bytes).into_string();

        let (dn, dc, ds) = decode_invite_code(&legacy).unwrap();
        assert_eq!(dn, net);
        assert_eq!(dc, coord);
        assert_eq!(ds, secret.to_vec());
    }

    #[test]
    fn decode_rejects_corrupted_checksum() {
        let (net, coord, secret) = (test_id(1), test_id(2), generate_secret());
        let mut bytes = Vec::new();
        bytes.extend_from_slice(net.as_bytes());
        bytes.extend_from_slice(coord.as_bytes());
        bytes.extend_from_slice(&secret);
        bytes.extend_from_slice(&[0xff; 4]); // not the real checksum

        let err = decode_invite_code(&bs58::encode(&bytes).into_string()).unwrap_err();
        assert!(err.to_string().contains("checksum"), "got: {err}");
    }

    /// The point of the checksum: a code that lost characters in a paste is
    /// reported as invalid instead of decoding into a plausible invite.
    ///
    /// Bounded at four characters because base58 length is value-dependent:
    /// four dropped characters shrink the payload by at most three bytes, so
    /// the result can't reach the four-bytes-shorter legacy shape, which is
    /// the one case the decoder still accepts unchecked (see
    /// [`decode_invite_code`]).
    #[test]
    fn decode_rejects_truncated_code() {
        let code = encode_invite_code(&test_id(1), &test_id(2), &generate_secret());
        for cut in 1..=4 {
            let truncated = &code[..code.len() - cut];
            assert!(
                decode_invite_code(truncated).is_err(),
                "truncation by {cut} was accepted",
            );
        }
    }

    #[test]
    fn mint_then_redeem_succeeds() {
        let (mut store, _dir) = temp_store();
        let (secret, id) = store
            .mint(Duration::from_secs(3600), Grant::default())
            .unwrap();
        assert_eq!(id.len(), 8);
        store.redeem(&secret, test_id(9)).unwrap();
        // Status is now redeemed.
        let view = store.list();
        assert_eq!(view.len(), 1);
        assert_eq!(view[0].status, "redeemed");
        assert!(view[0].redeemer.is_some());
    }

    #[test]
    fn redeem_is_single_use() {
        let (mut store, _dir) = temp_store();
        let (secret, _id) = store
            .mint(Duration::from_secs(3600), Grant::default())
            .unwrap();
        store.redeem(&secret, test_id(9)).unwrap();
        let err = store.redeem(&secret, test_id(10)).unwrap_err();
        assert!(err.to_string().contains("already used"));
    }

    #[test]
    fn redeem_rejects_expired() {
        let (mut store, _dir) = temp_store();
        // ttl=0 → expires == created == now, so now >= expires immediately.
        let (secret, _id) = store
            .mint(Duration::from_secs(0), Grant::default())
            .unwrap();
        let err = store.redeem(&secret, test_id(9)).unwrap_err();
        assert!(err.to_string().contains("expired"));
    }

    #[test]
    fn redeem_rejects_wrong_secret() {
        let (mut store, _dir) = temp_store();
        store
            .mint(Duration::from_secs(3600), Grant::default())
            .unwrap();
        let err = store.redeem(&generate_secret(), test_id(9)).unwrap_err();
        assert!(err.to_string().contains("invalid invite"));
    }

    #[test]
    fn revoke_then_redeem_fails() {
        let (mut store, _dir) = temp_store();
        let (secret, id) = store
            .mint(Duration::from_secs(3600), Grant::default())
            .unwrap();
        store.revoke(&id).unwrap();
        let err = store.redeem(&secret, test_id(9)).unwrap_err();
        assert!(err.to_string().contains("revoked"));
    }

    #[test]
    fn cannot_revoke_used_invite() {
        let (mut store, _dir) = temp_store();
        let (secret, id) = store
            .mint(Duration::from_secs(3600), Grant::default())
            .unwrap();
        store.redeem(&secret, test_id(9)).unwrap();
        assert!(store.revoke(&id).is_err());
    }

    #[test]
    fn persists_across_reload() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("net.toml");
        let secret;
        {
            let mut store = InviteStore::with_path(&path);
            let (s, _id) = store
                .mint(Duration::from_secs(3600), Grant::default())
                .unwrap();
            secret = s;
        }
        // Reload from disk and redeem.
        let mut reloaded = InviteStore::from_path(path).unwrap();
        reloaded.redeem(&secret, test_id(7)).unwrap();
    }

    #[test]
    fn list_reports_expired_lazily() {
        let (mut store, _dir) = temp_store();
        store
            .mint(Duration::from_secs(0), Grant::default())
            .unwrap();
        let view = store.list();
        assert_eq!(view[0].status, "expired");
        // Stored status remains Pending (not mutated).
        assert_eq!(store.invites[0].status, InviteStatus::Pending);
    }

    #[test]
    fn mint_with_hostname_returns_it_on_redeem() {
        let (mut store, _dir) = temp_store();
        let (secret, _id) = store
            .mint(
                Duration::from_secs(3600),
                Grant {
                    hostname: Some("ty2-clic01".to_string()),
                    roles: BTreeSet::new(),
                },
            )
            .unwrap();
        let grant = store.redeem(&secret, test_id(9)).unwrap();
        assert_eq!(grant.hostname.as_deref(), Some("ty2-clic01"));
        // The bound hostname is visible in the list.
        let view = store.list();
        assert_eq!(view[0].hostname.as_deref(), Some("ty2-clic01"));
    }

    /// A single-use invite can carry roles too, so `--hostname sentry-01
    /// --role sentry` seats a named node with its policy class in one code.
    #[test]
    fn mint_with_roles_returns_them_on_redeem() {
        let (mut store, _dir) = temp_store();
        let roles: BTreeSet<String> = ["sentry".to_string()].into();
        let (secret, _id) = store
            .mint(
                Duration::from_secs(3600),
                Grant {
                    hostname: None,
                    roles: roles.clone(),
                },
            )
            .unwrap();
        let grant = store.redeem(&secret, test_id(9)).unwrap();
        assert_eq!(grant.roles, roles);
        assert!(grant.hostname.is_none());
    }

    #[test]
    fn restore_reinstates_a_burned_invite() {
        let (mut store, _dir) = temp_store();
        let (secret, _id) = store
            .mint(Duration::from_secs(3600), Grant::default())
            .unwrap();
        store.redeem(&secret, test_id(9)).unwrap();
        // After restore the invite is pending again and redeemable once more.
        store.restore(&secret).unwrap();
        assert_eq!(store.list()[0].status, "pending");
        store.redeem(&secret, test_id(10)).unwrap();
        assert_eq!(store.list()[0].status, "redeemed");
    }

    #[test]
    fn restore_is_noop_for_unknown_or_pending() {
        let (mut store, _dir) = temp_store();
        let (secret, _id) = store
            .mint(Duration::from_secs(3600), Grant::default())
            .unwrap();
        // Pending stays pending; an unknown secret is ignored.
        store.restore(&secret).unwrap();
        store.restore(&generate_secret()).unwrap();
        assert_eq!(store.list()[0].status, "pending");
    }

    #[cfg(unix)]
    #[test]
    fn save_sets_owner_only_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("net.toml");
        let mut store = InviteStore::with_path(&path);
        store
            .mint(Duration::from_secs(3600), Grant::default())
            .unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn mint_without_hostname_returns_none_on_redeem() {
        let (mut store, _dir) = temp_store();
        let (secret, _id) = store
            .mint(Duration::from_secs(3600), Grant::default())
            .unwrap();
        let grant = store.redeem(&secret, test_id(9)).unwrap();
        assert!(grant.hostname.is_none());
        assert!(grant.roles.is_empty());
    }

    #[test]
    fn record_shared_then_redeem_then_burn_by_hash() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("net.toml");
        let mut store = InviteStore::with_path(&path);
        let secret = generate_secret();
        // secret_hash is a hex String in the real code.
        let hash = blake3::hash(&secret).to_hex().to_string();

        store
            .record_shared("abcd1234".into(), hash.clone(), u64::MAX)
            .unwrap();
        // A shared entry is redeemable by this (non-minting) coordinator
        // (hostname is None since record_shared has no hostname binding):
        let by = test_id(5);
        assert!(store.redeem(&secret, by).unwrap().hostname.is_none());
        // Burning an already-redeemed hash is a no-op (returns false):
        assert!(!store.burn_by_hash(&hash).unwrap());
    }

    #[test]
    fn burn_by_hash_marks_unredeemed_entry_used() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = InviteStore::with_path(dir.path().join("n.toml"));
        let secret = generate_secret();
        let hash = blake3::hash(&secret).to_hex().to_string();
        store
            .record_shared("id00".into(), hash.clone(), u64::MAX)
            .unwrap();
        assert!(store.burn_by_hash(&hash).unwrap()); // first burn changes state
        assert!(store.redeem(&secret, test_id(9)).is_err()); // now unusable
    }

    #[test]
    fn old_ledger_without_hostname_field_decodes() {
        // A ledger authored before the hostname field existed (no `hostname` key)
        // must still decode, defaulting to None.
        let toml = r#"
[[invites]]
id = "abcd1234"
secret_hash = "abcd1234"
created = 1
expires = 9999999999
status = "Pending"
"#;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("net.toml");
        std::fs::write(&path, toml).unwrap();
        let store = InviteStore::from_path(path).unwrap();
        assert_eq!(store.invites.len(), 1);
        assert!(store.invites[0].hostname.is_none());
    }
}
