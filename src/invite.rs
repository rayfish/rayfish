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

use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use iroh::EndpointId;

use crate::groupkey::ReadKey;
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

/// Version byte on a share code carrying a roster read key.
///
/// The pre-read-key formats had no version byte and were told apart by decoded
/// length alone. That worked while there were two of them; adding a third (and
/// wanting room for a fourth) makes the length a bad discriminator, so the new
/// shapes lead with an explicit one. The legacy lengths keep decoding, so codes
/// minted by an older build still work.
const CODE_V1_INVITE: u8 = 0x01;
const CODE_V1_ROOM: u8 = 0x02;

/// `[0x01] || network(32) || coordinator(32) || read(32) || secret(16) || ck(4)`
const INVITE_V1_PAYLOAD_LEN: usize = 1 + 32 + 32 + 32 + SECRET_LEN;
/// `[0x02] || network(32) || read(32) || ck(4)`
const ROOM_V1_PAYLOAD_LEN: usize = 1 + 32 + 32;

/// What a share code carries. One type for every shape a user can paste into
/// `ray join`: a bare room id, a legacy invite, or either of the versioned forms.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShareCode {
    /// The network public key (room id).
    pub network: EndpointId,
    /// Coordinator to dial first. Only an invite names one.
    pub coordinator: Option<EndpointId>,
    /// The roster read key. Absent on a bare room id and on the legacy invite
    /// forms, which is exactly the set of codes for networks whose blob is not
    /// sealed.
    pub read_key: Option<ReadKey>,
    /// Single-use or reusable invite secret to redeem at admission.
    pub invite_secret: Option<Vec<u8>>,
}

/// Encode a room code: the network id plus its read key, and nothing else.
///
/// This is what `ray create` prints and `ray status` shows: the thing you hand
/// someone so they can find *and read* the network. It is not a credential, and
/// on a closed network it still does not admit anybody.
pub fn encode_room_code(network_pubkey: &EndpointId, read_key: &ReadKey) -> String {
    let mut bytes = Vec::with_capacity(ROOM_V1_PAYLOAD_LEN + CHECKSUM_LEN);
    bytes.push(CODE_V1_ROOM);
    bytes.extend_from_slice(network_pubkey.as_bytes());
    bytes.extend_from_slice(read_key.as_bytes());
    bytes.extend_from_slice(&invite_checksum(&bytes));
    bs58::encode(&bytes).into_string()
}

/// Encode an invite code.
///
/// With a read key: `bs58([0x01] || network(32) || coordinator(32) ||
/// read(32) || secret(16) || checksum(4))`. Without one (a network that predates
/// read keys): the original `bs58(network(32) || coordinator(32) || secret(16)
/// || checksum(4))`, so nothing changes for a network that is not sealed.
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
    read_key: Option<&ReadKey>,
) -> String {
    let mut bytes = Vec::with_capacity(INVITE_V1_PAYLOAD_LEN + CHECKSUM_LEN);
    if let Some(rk) = read_key {
        bytes.push(CODE_V1_INVITE);
        bytes.extend_from_slice(network_pubkey.as_bytes());
        bytes.extend_from_slice(coordinator.as_bytes());
        bytes.extend_from_slice(rk.as_bytes());
    } else {
        bytes.extend_from_slice(network_pubkey.as_bytes());
        bytes.extend_from_slice(coordinator.as_bytes());
    }
    bytes.extend_from_slice(secret);
    bytes.extend_from_slice(&invite_checksum(&bytes));
    bs58::encode(&bytes).into_string()
}

/// Decode anything a user can paste as a network identifier.
///
/// The single entry point for `ray join`'s argument, the mobile `submit_code`,
/// and the deep-link handler, so the three cannot disagree about what a code
/// means. Tries, in order: the versioned share codes, the two legacy invite
/// lengths, then a bare `EndpointId` (hex or base32).
pub fn decode_share_code(code: &str) -> Result<ShareCode> {
    let code = code.trim();
    if let Ok(bytes) = bs58::decode(code).into_vec()
        && let Some(parsed) = decode_share_bytes(&bytes)?
    {
        return Ok(parsed);
    }
    // Not a share code, so the last possibility is a bare room id. A network
    // whose blob is sealed cannot be joined from one, but that is diagnosed
    // later, against the signed record, where the message can say so.
    let network = code
        .parse::<EndpointId>()
        .map_err(|_| anyhow::anyhow!("not a valid room id, invite code, or share code"))?;
    Ok(ShareCode {
        network,
        coordinator: None,
        read_key: None,
        invite_secret: None,
    })
}

/// The base58 half of [`decode_share_code`]. `Ok(None)` means "these bytes are
/// not any share-code shape", which is not an error: the caller falls through to
/// parsing the string as a bare room id. `Err` is reserved for bytes that *are*
/// a share code and are damaged, so a mistyped code says so rather than being
/// reported as an unparseable room id.
fn decode_share_bytes(bytes: &[u8]) -> Result<Option<ShareCode>> {
    let checked = |payload_len: usize| -> Result<&[u8]> {
        let (payload, checksum) = bytes.split_at(payload_len);
        if checksum != invite_checksum(payload) {
            bail!("invalid code: checksum mismatch (was it copied in full?)");
        }
        Ok(payload)
    };

    match (bytes.len(), bytes.first()) {
        (len, Some(&CODE_V1_ROOM)) if len == ROOM_V1_PAYLOAD_LEN + CHECKSUM_LEN => {
            let payload = checked(ROOM_V1_PAYLOAD_LEN)?;
            Ok(Some(ShareCode {
                network: endpoint_at(payload, 1, "network")?,
                coordinator: None,
                read_key: Some(read_key_at(payload, 33)),
                invite_secret: None,
            }))
        }
        (len, Some(&CODE_V1_INVITE)) if len == INVITE_V1_PAYLOAD_LEN + CHECKSUM_LEN => {
            let payload = checked(INVITE_V1_PAYLOAD_LEN)?;
            Ok(Some(ShareCode {
                network: endpoint_at(payload, 1, "network")?,
                coordinator: Some(endpoint_at(payload, 33, "coordinator")?),
                read_key: Some(read_key_at(payload, 65)),
                invite_secret: Some(payload[97..].to_vec()),
            }))
        }
        // The two pre-read-key invite forms: unchecksummed, then checksummed.
        (len, _) if len == PAYLOAD_LEN || len == PAYLOAD_LEN + CHECKSUM_LEN => {
            let payload = if len == PAYLOAD_LEN {
                bytes
            } else {
                checked(PAYLOAD_LEN)?
            };
            Ok(Some(ShareCode {
                network: endpoint_at(payload, 0, "network")?,
                coordinator: Some(endpoint_at(payload, 32, "coordinator")?),
                read_key: None,
                invite_secret: Some(payload[64..].to_vec()),
            }))
        }
        _ => Ok(None),
    }
}

fn endpoint_at(payload: &[u8], offset: usize, what: &str) -> Result<EndpointId> {
    let raw: [u8; 32] = payload[offset..offset + 32]
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid {what} key in code"))?;
    EndpointId::from_bytes(&raw).map_err(|e| anyhow::anyhow!("invalid {what} key in code: {e}"))
}

fn read_key_at(payload: &[u8], offset: usize) -> ReadKey {
    let mut raw = [0u8; 32];
    raw.copy_from_slice(&payload[offset..offset + 32]);
    ReadKey::from_bytes(raw)
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
    /// `hostname` (trusted networks) is assigned authoritatively on redemption,
    /// so the holder joins with `ray join <code>` and no `--hostname`.
    pub fn mint(
        &mut self,
        ttl: Duration,
        hostname: Option<String>,
    ) -> Result<([u8; SECRET_LEN], String)> {
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
            hostname,
        });
        self.save()?;
        Ok((secret, id))
    }

    /// Verify a presented secret and burn it (single-use). Errors if the secret is
    /// unknown, already used, revoked, or expired. Returns the invite's intended
    /// hostname (trusted networks) so the coordinator can assign it.
    pub fn redeem(&mut self, secret: &[u8], by: EndpointId) -> Result<Option<String>> {
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
        let hostname = invite.hostname.clone();
        invite.status = InviteStatus::Redeemed { by, at: now };
        self.save()?;
        Ok(hostname)
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

    fn test_read_key(seed: u8) -> ReadKey {
        let mut b = [0u8; 32];
        b[0] = seed;
        ReadKey::from_bytes(b)
    }

    #[test]
    fn code_roundtrip() {
        let net = test_id(1);
        let coord = test_id(2);
        let secret = generate_secret();
        let rk = test_read_key(3);
        let code = encode_invite_code(&net, &coord, &secret, Some(&rk));
        let got = decode_share_code(&code).unwrap();
        assert_eq!(got.network, net);
        assert_eq!(got.coordinator, Some(coord));
        assert_eq!(got.invite_secret, Some(secret.to_vec()));
        assert_eq!(got.read_key, Some(rk));
    }

    /// A network with no read key still mints the original code shape, so a
    /// coordinator that has not migrated hands out what it always did.
    #[test]
    fn code_without_a_read_key_keeps_the_legacy_shape() {
        let (net, coord, secret) = (test_id(1), test_id(2), generate_secret());
        let code = encode_invite_code(&net, &coord, &secret, None);
        assert_eq!(
            bs58::decode(&code).into_vec().unwrap().len(),
            PAYLOAD_LEN + CHECKSUM_LEN
        );
        let got = decode_share_code(&code).unwrap();
        assert_eq!(got.network, net);
        assert_eq!(got.read_key, None);
    }

    #[test]
    fn room_code_roundtrip() {
        let net = test_id(1);
        let rk = test_read_key(7);
        let got = decode_share_code(&encode_room_code(&net, &rk)).unwrap();
        assert_eq!(got.network, net);
        assert_eq!(got.read_key, Some(rk));
        assert_eq!(got.coordinator, None);
        assert_eq!(got.invite_secret, None);
    }

    /// A bare room id is a share code with nothing in it but the network, which
    /// is what keeps a pre-read-key network joinable from the string its owner
    /// already published.
    #[test]
    fn bare_room_id_decodes() {
        let net = test_id(1);
        let got = decode_share_code(&net.to_string()).unwrap();
        assert_eq!(got.network, net);
        assert_eq!(got.read_key, None);
        assert_eq!(got.coordinator, None);
    }

    /// The nasty case for "try base58, else parse as a room id": a room id is 64
    /// hex characters, and hex that happens to contain none of base58's excluded
    /// characters (`0`, `O`, `I`, `l`) *is* a valid base58 string. It decodes to
    /// ~47 bytes, which matches no share-code shape, so the fallback still has to
    /// be reached. Search for such a key rather than hoping a fixed one has the
    /// property.
    #[test]
    fn a_room_id_that_is_also_valid_base58_still_parses() {
        let excluded = ['0', 'O', 'I', 'l'];
        let id = (0u32..20_000)
            .map(|seed| {
                let mut b = [0u8; 32];
                b[..4].copy_from_slice(&seed.to_le_bytes());
                iroh::SecretKey::from(b).public()
            })
            .find(|id| {
                let hex = id.to_string();
                !hex.chars().any(|c| excluded.contains(&c)) && bs58::decode(&hex).into_vec().is_ok()
            })
            .expect("a 64-char hex id avoiding 0/O/I/l exists well inside this sample");

        let got = decode_share_code(&id.to_string()).unwrap();
        assert_eq!(got.network, id);
        assert_eq!(got.read_key, None);
    }

    #[test]
    fn decode_rejects_bad_length() {
        // Random bytes of no recognised shape are neither a share code nor a
        // room id.
        let code = bs58::encode([7u8; 40]).into_string();
        assert!(decode_share_code(&code).is_err());
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

        let got = decode_share_code(&legacy).unwrap();
        assert_eq!(got.network, net);
        assert_eq!(got.coordinator, Some(coord));
        assert_eq!(got.invite_secret, Some(secret.to_vec()));
        assert_eq!(got.read_key, None);
    }

    #[test]
    fn decode_rejects_corrupted_checksum() {
        let (net, coord, secret) = (test_id(1), test_id(2), generate_secret());
        let mut bytes = Vec::new();
        bytes.extend_from_slice(net.as_bytes());
        bytes.extend_from_slice(coord.as_bytes());
        bytes.extend_from_slice(&secret);
        bytes.extend_from_slice(&[0xff; 4]); // not the real checksum

        let err = decode_share_code(&bs58::encode(&bytes).into_string()).unwrap_err();
        assert!(err.to_string().contains("checksum"), "got: {err}");
    }

    /// The point of the checksum: a code that lost characters in a paste is
    /// reported as invalid instead of decoding into a plausible invite.
    ///
    /// Bounded at four characters because base58 length is value-dependent:
    /// four dropped characters shrink the payload by at most three bytes, so
    /// the result can't reach the four-bytes-shorter legacy shape, which is
    /// the one case the decoder still accepts unchecked (see
    /// [`decode_share_code`]).
    #[test]
    fn decode_rejects_truncated_code() {
        let code = encode_invite_code(&test_id(1), &test_id(2), &generate_secret(), None);
        for cut in 1..=4 {
            let truncated = &code[..code.len() - cut];
            assert!(
                decode_share_code(truncated).is_err(),
                "truncation by {cut} was accepted",
            );
        }
    }

    /// The pairing ticket decoder runs first in mobile's `submit_code`, so a
    /// share code that decoded as one would be routed to the pairing path.
    #[test]
    fn share_codes_do_not_collide_with_pairing_tickets() {
        let rk = test_read_key(5);
        for code in [
            encode_room_code(&test_id(1), &rk),
            encode_invite_code(&test_id(1), &test_id(2), &generate_secret(), Some(&rk)),
            encode_invite_code(&test_id(1), &test_id(2), &generate_secret(), None),
        ] {
            let len = bs58::decode(&code).into_vec().unwrap().len();
            assert_ne!(len, 64, "{code} is pairing-ticket length");
        }
    }

    #[test]
    fn mint_then_redeem_succeeds() {
        let (mut store, _dir) = temp_store();
        let (secret, id) = store.mint(Duration::from_secs(3600), None).unwrap();
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
        let (secret, _id) = store.mint(Duration::from_secs(3600), None).unwrap();
        store.redeem(&secret, test_id(9)).unwrap();
        let err = store.redeem(&secret, test_id(10)).unwrap_err();
        assert!(err.to_string().contains("already used"));
    }

    #[test]
    fn redeem_rejects_expired() {
        let (mut store, _dir) = temp_store();
        // ttl=0 → expires == created == now, so now >= expires immediately.
        let (secret, _id) = store.mint(Duration::from_secs(0), None).unwrap();
        let err = store.redeem(&secret, test_id(9)).unwrap_err();
        assert!(err.to_string().contains("expired"));
    }

    #[test]
    fn redeem_rejects_wrong_secret() {
        let (mut store, _dir) = temp_store();
        store.mint(Duration::from_secs(3600), None).unwrap();
        let err = store.redeem(&generate_secret(), test_id(9)).unwrap_err();
        assert!(err.to_string().contains("invalid invite"));
    }

    #[test]
    fn revoke_then_redeem_fails() {
        let (mut store, _dir) = temp_store();
        let (secret, id) = store.mint(Duration::from_secs(3600), None).unwrap();
        store.revoke(&id).unwrap();
        let err = store.redeem(&secret, test_id(9)).unwrap_err();
        assert!(err.to_string().contains("revoked"));
    }

    #[test]
    fn cannot_revoke_used_invite() {
        let (mut store, _dir) = temp_store();
        let (secret, id) = store.mint(Duration::from_secs(3600), None).unwrap();
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
            let (s, _id) = store.mint(Duration::from_secs(3600), None).unwrap();
            secret = s;
        }
        // Reload from disk and redeem.
        let mut reloaded = InviteStore::from_path(path).unwrap();
        reloaded.redeem(&secret, test_id(7)).unwrap();
    }

    #[test]
    fn list_reports_expired_lazily() {
        let (mut store, _dir) = temp_store();
        store.mint(Duration::from_secs(0), None).unwrap();
        let view = store.list();
        assert_eq!(view[0].status, "expired");
        // Stored status remains Pending (not mutated).
        assert_eq!(store.invites[0].status, InviteStatus::Pending);
    }

    #[test]
    fn mint_with_hostname_returns_it_on_redeem() {
        let (mut store, _dir) = temp_store();
        let (secret, _id) = store
            .mint(Duration::from_secs(3600), Some("ty2-clic01".to_string()))
            .unwrap();
        let hostname = store.redeem(&secret, test_id(9)).unwrap();
        assert_eq!(hostname.as_deref(), Some("ty2-clic01"));
        // The bound hostname is visible in the list.
        let view = store.list();
        assert_eq!(view[0].hostname.as_deref(), Some("ty2-clic01"));
    }

    #[test]
    fn restore_reinstates_a_burned_invite() {
        let (mut store, _dir) = temp_store();
        let (secret, _id) = store.mint(Duration::from_secs(3600), None).unwrap();
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
        let (secret, _id) = store.mint(Duration::from_secs(3600), None).unwrap();
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
        store.mint(Duration::from_secs(3600), None).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn mint_without_hostname_returns_none_on_redeem() {
        let (mut store, _dir) = temp_store();
        let (secret, _id) = store.mint(Duration::from_secs(3600), None).unwrap();
        let hostname = store.redeem(&secret, test_id(9)).unwrap();
        assert!(hostname.is_none());
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
        assert!(store.redeem(&secret, by).unwrap().is_none());
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
