//! DHT-based network record publishing and resolution.
//!
//! Each network has a single pkarr record containing the group blob hash and
//! seed peer list. Only the coordinator (holder of the per-network secret key)
//! can publish or update the record.
//!
//! ## What still needs this under Tor
//!
//! A Tor node needs no discovery to be *reached*: a v3 onion address is an
//! ed25519 public key and so is an `EndpointId`, so a peer's address is derived
//! from its identity arithmetically (see [`crate::transport::NodePosture`]).
//! This module is the other plane, and it does not go away, because a network
//! key is not a peer. Which entry path a user takes decides whether they touch
//! it at all:
//!
//! - `ray join <invite-code>` needs nothing here. The invite already carries the
//!   coordinator's `EndpointId`, so its onion address is computed locally and
//!   dialed. This is the entry path to prefer on a Tor node.
//! - `ray join <bare-network-key>` needs this. The network key names a network,
//!   not a peer, so the record is the only thing that supplies the seed peers'
//!   `EndpointId`s.
//! - `ray connect <contact-id>` needs this. A contact id is deliberately a
//!   separate, rotatable key from the transport identity, and the
//!   `_rayfish_contact` record is what maps one to the other. The onion address
//!   derives from the *transport* key, so the lookup cannot be skipped.
//!
//! That is why a Tor posture still needs a pkarr server, and why the requests to
//! it go through Tor's SOCKS proxy rather than in the clear: see [`PkarrClient`].

use anyhow::{Context as _, Result, ensure};
use iroh::{
    EndpointId, SecretKey, address_lookup::PkarrRelayClient, dns::DnsResolver, endpoint::Endpoint,
};
use iroh_dns::pkarr::SignedPacket;
use url::Url;

use crate::transport::NodePosture;

const RECORD_NAME: &str = "_rayfish";
const RECORD_VERSION: &str = "v1";
pub(crate) const RECORD_TTL: u32 = 300;
const PKARR_RELAY_URL: &str = "https://dns.iroh.link/pkarr";

/// Cap on a single record resolution. The relay is plain HTTPS and iroh's
/// client sets no total timeout, so a blackholed relay (or a host whose DNS
/// stopped resolving the relay's own name) would otherwise leave `ray join`
/// hanging with nothing on screen.
const RESOLVE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);
/// Bound publication too: snapshot commits wait behind an in-flight publish so
/// an older record cannot land after a newer recovery pointer.
const PUBLISH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

/// Process-wide pkarr relay URL, set once at daemon startup from the
/// `discovery-dns` config. The discovery server is a set-once constant for the
/// daemon's lifetime, so a `OnceLock` avoids threading it through every
/// `create_pkarr_client` caller.
static PKARR_OVERRIDE: std::sync::OnceLock<String> = std::sync::OnceLock::new();

/// Point the pkarr client at the configured `discovery-dns` server (first URL
/// wins). No-op when unset, keeping the n0 default. Called once in build_daemon.
pub fn set_discovery_override(o: &crate::config::ServerOverride) {
    if let Ok(urls) = crate::config::discovery_urls(o)
        && let Some(first) = urls.into_iter().next()
    {
        let _ = PKARR_OVERRIDE.set(first);
    }
}

/// The pkarr relay URL in effect: the configured override, else the n0 default.
pub fn effective_pkarr_url() -> String {
    PKARR_OVERRIDE
        .get()
        .cloned()
        .unwrap_or_else(|| PKARR_RELAY_URL.to_string())
}

/// Process-wide node posture, set once at daemon startup, for the same reason
/// [`PKARR_OVERRIDE`] is: `create_pkarr_client` is called from a dozen places
/// across the daemon, and threading a value that never changes through all of
/// them would be noise at every call site to serve one decision made once.
static POSTURE: std::sync::OnceLock<NodePosture> = std::sync::OnceLock::new();

/// Record the posture before anything publishes or resolves. Called once in
/// `build_daemon`; a second call is ignored, as with the discovery override.
pub fn set_posture(posture: NodePosture) {
    let _ = POSTURE.set(posture);
}

fn posture() -> NodePosture {
    POSTURE.get().copied().unwrap_or(NodePosture::Open)
}

/// Tor's SOCKS5 port. Matches `iroh_tor_transport`'s `DEFAULT_SOCKS_PORT`, which
/// is what the transport half of a Tor posture already dials through.
const TOR_SOCKS_PORT: u16 = 9050;

/// How the record plane talks to the pkarr server.
///
/// Two variants because the transport posture decides the answer and the two
/// have nothing in common underneath. iroh's [`PkarrRelayClient`] is built from
/// a TLS config and a DNS resolver, not from a connector, so there is no proxy
/// to hand it; reaching a pkarr server through Tor means owning the two HTTP
/// calls instead. They are small: the pkarr relay API is a `GET` and a `PUT` of
/// a signed packet at `/<z32-pubkey>`, and `SignedPacket` already has both
/// payload codecs.
///
/// This exists because the record plane is a *separate* client from the
/// endpoint's transports. Clearing the endpoint's IP transports stops it dialing
/// peers in the clear, and does nothing at all about this: without the SOCKS
/// variant, a Tor node would still hit the pkarr server over plain HTTPS from its
/// real address, every time it published or resolved, which is most of what
/// private mode exists to prevent.
pub enum PkarrClient {
    /// Plain HTTPS, using the endpoint's TLS config and resolver.
    Direct(PkarrRelayClient),
    /// Through Tor's SOCKS5 proxy, with remote DNS so the relay's hostname is
    /// never resolved on this machine either.
    Socks {
        http: reqwest::Client,
        relay_url: Url,
    },
}

impl PkarrClient {
    pub async fn publish(&self, packet: &SignedPacket) -> Result<()> {
        match self {
            Self::Direct(c) => c
                .publish(packet)
                .await
                .map_err(|e| anyhow::anyhow!("pkarr publish failed: {e}")),
            Self::Socks { http, relay_url } => {
                let url = record_url(relay_url, &packet.public_key().to_z32())?;
                let resp = http
                    .put(url)
                    .body(packet.to_relay_payload())
                    .send()
                    .await
                    .context("pkarr publish over Tor failed")?;
                ensure!(
                    resp.status().is_success(),
                    "pkarr publish over Tor rejected: HTTP {}",
                    resp.status()
                );
                Ok(())
            }
        }
    }

    pub async fn resolve(&self, key: EndpointId) -> Result<SignedPacket> {
        match self {
            Self::Direct(c) => c
                .resolve(key)
                .await
                .map_err(|e| anyhow::anyhow!("pkarr resolve failed: {e}")),
            Self::Socks { http, relay_url } => {
                let url = record_url(relay_url, &key.to_z32())?;
                let resp = http
                    .get(url)
                    .send()
                    .await
                    .context("pkarr resolve over Tor failed")?;
                ensure!(
                    resp.status().is_success(),
                    "pkarr resolve over Tor: HTTP {}",
                    resp.status()
                );
                let payload = resp.bytes().await.context("reading pkarr response")?;
                SignedPacket::from_relay_payload(&key, &payload)
                    .map_err(|e| anyhow::anyhow!("invalid pkarr payload: {e}"))
            }
        }
    }
}

/// `{relay}/{z32}`, the one path shape the pkarr relay API has.
fn record_url(relay_url: &Url, z32: &str) -> Result<Url> {
    let mut url = relay_url.clone();
    url.path_segments_mut()
        .map_err(|_| anyhow::anyhow!("pkarr relay URL cannot have a path: {relay_url}"))?
        .push(z32);
    Ok(url)
}

/// pkarr record name for a user's contact key (`ray connect`). Published under
/// the contact key, it maps the contact id to the user's current transport
/// EndpointId so a peer can dial them without knowing the transport id.
const CONTACT_RECORD_NAME: &str = "_rayfish_contact";

// ---------------------------------------------------------------------------
// Pkarr client
// ---------------------------------------------------------------------------

/// Build the record-plane client for the posture this daemon started in.
///
/// The signature is unchanged from when it returned iroh's client directly, so
/// the dozen call sites across `daemon/mesh/` and `daemon/` pass it straight
/// through and none of them had to learn about Tor.
pub fn create_pkarr_client(ep: &Endpoint) -> Result<PkarrClient> {
    let relay_url: Url = effective_pkarr_url().parse().expect("relay URL is valid");

    if posture().is_tor_only() {
        // `socks5h` rather than `socks5`: the `h` is what makes the proxy resolve
        // the hostname. Without it reqwest would resolve the pkarr server's name
        // locally first, which is a clearnet DNS query naming the one server this
        // node talks to, defeating the point of proxying the request that follows.
        let proxy = reqwest::Proxy::all(format!("socks5h://127.0.0.1:{TOR_SOCKS_PORT}"))
            .context("building the Tor SOCKS proxy for pkarr")?;
        // reqwest is built with `rustls-no-provider`, so `build()` *panics* (it
        // does not return an error) unless a process-default CryptoProvider is
        // already installed. In the daemon that panic is fatal: the panic hook
        // restores DNS and aborts. Install ring first, exactly as
        // `update::build_http_client` does; `install_default` errors only when one
        // is already set, which is harmless.
        let _ = rustls::crypto::ring::default_provider().install_default();
        let http = reqwest::Client::builder()
            .proxy(proxy)
            .build()
            .context("building the pkarr client for Tor")?;
        return Ok(PkarrClient::Socks { http, relay_url });
    }

    let tls_config = ep.tls_config().clone();
    let dns_resolver: DnsResolver = ep
        .dns_resolver()
        .context("endpoint has no DNS resolver")?
        .clone();
    Ok(PkarrClient::Direct(PkarrRelayClient::new(
        relay_url,
        tls_config,
        dns_resolver,
    )))
}

// ---------------------------------------------------------------------------
// Network record encoding / decoding
// ---------------------------------------------------------------------------

/// Encodes a network record into a signed pkarr packet.
///
/// The record contains the group blob hash, a list of seed peers, and the
/// publishing coordinator's mesh protocol version (`m,<v>` =
/// [`transport::MESH_PROTOCOL_VERSION`]). The version lets a joiner detect an
/// incompatible mesh protocol *before* dialing (where the versioned ALPN would
/// otherwise reject it opaquely), so it can surface a precise "run ray update"
/// error. The record is network-key-signed, so the version can't be spoofed.
pub fn encode_network_record(
    key: &SecretKey,
    blob_hash: &blake3::Hash,
    seed_peers: &[EndpointId],
) -> Result<SignedPacket> {
    let mut values = vec![
        RECORD_VERSION.to_string(),
        format!("h,{blob_hash}"),
        format!("m,{}", crate::transport::MESH_PROTOCOL_VERSION),
    ];
    for peer in seed_peers {
        values.push(format!("p,{peer}"));
    }
    SignedPacket::from_txt_strings(key, RECORD_NAME, values, RECORD_TTL)
        .map_err(|e| anyhow::anyhow!("failed to build network record: {e}"))
}

/// Extracts the coordinator's advertised mesh protocol version (`m,<v>`) from a
/// network record, if present. Returns `None` for older records published before
/// the version was added: callers treat that as "unknown, fall through to the
/// ALPN gate" rather than blocking.
pub fn mesh_version_from_record(packet: &SignedPacket) -> Option<u32> {
    packet
        .txt_records(RECORD_NAME)
        .iter()
        .find_map(|r| r.strip_prefix("m,").and_then(|v| v.parse::<u32>().ok()))
}

/// Verify a signed network record received out-of-band (handed to us over the
/// mesh, not resolved from the DHT) really is signed by `network_pubkey`.
/// [`SignedPacket::from_bytes`] checks the ed25519 signature; this additionally
/// pins the signer to the expected network key, so a peer can't hand us a
/// validly-signed record for a *different* network. The returned packet is then
/// safe to [`decode_network_record`] and trust exactly like the DHT copy.
pub fn verify_network_record(bytes: &[u8], network_pubkey: EndpointId) -> Result<SignedPacket> {
    let packet = SignedPacket::from_bytes(bytes)
        .map_err(|e| anyhow::anyhow!("invalid signed record: {e}"))?;
    ensure!(
        packet.public_key() == network_pubkey,
        "signed record is for a different network key"
    );
    Ok(packet)
}

pub fn decode_network_record(packet: &SignedPacket) -> Result<(blake3::Hash, Vec<EndpointId>)> {
    let records = packet.txt_records(RECORD_NAME);
    ensure!(!records.is_empty(), "no network records found");
    ensure!(
        records[0] == RECORD_VERSION,
        "unsupported record version: {}",
        records[0]
    );

    let mut blob_hash = None;
    let mut peers = Vec::new();

    for record in &records[1..] {
        if let Some(hash_str) = record.strip_prefix("h,") {
            blob_hash = Some(
                hash_str
                    .parse::<blake3::Hash>()
                    .context("invalid blob hash")?,
            );
        } else if let Some(id_str) = record.strip_prefix("p,") {
            peers.push(
                id_str
                    .parse::<EndpointId>()
                    .context("invalid peer endpoint ID")?,
            );
        }
    }

    Ok((blob_hash.context("missing blob hash (h,)")?, peers))
}

// ---------------------------------------------------------------------------
// Contact record encoding / decoding (ray connect)
// ---------------------------------------------------------------------------

/// Encode a contact record: maps the contact key to the user's current
/// transport EndpointId. Signed by (and published under) the contact key, so
/// only its holder can publish it. Carries nothing else: no roster, hostname,
/// or member identities.
pub fn encode_contact_record(
    contact_key: &SecretKey,
    endpoint: EndpointId,
) -> Result<SignedPacket> {
    let values = vec![RECORD_VERSION.to_string(), format!("e,{endpoint}")];
    SignedPacket::from_txt_strings(contact_key, CONTACT_RECORD_NAME, values, RECORD_TTL)
        .map_err(|e| anyhow::anyhow!("failed to build contact record: {e}"))
}

pub fn decode_contact_record(packet: &SignedPacket) -> Result<EndpointId> {
    let records = packet.txt_records(CONTACT_RECORD_NAME);
    ensure!(!records.is_empty(), "no contact records found");
    ensure!(
        records[0] == RECORD_VERSION,
        "unsupported record version: {}",
        records[0]
    );
    for record in &records[1..] {
        if let Some(id_str) = record.strip_prefix("e,") {
            return id_str
                .parse::<EndpointId>()
                .context("invalid contact endpoint ID");
        }
    }
    anyhow::bail!("missing contact endpoint (e,)")
}

// ---------------------------------------------------------------------------
// Publish / resolve
// ---------------------------------------------------------------------------

pub async fn publish_network(
    client: &PkarrClient,
    key: &SecretKey,
    blob_hash: &blake3::Hash,
    seed_peers: &[EndpointId],
) -> Result<Vec<u8>> {
    let packet = encode_network_record(key, blob_hash, seed_peers)?;
    match tokio::time::timeout(PUBLISH_TIMEOUT, client.publish(&packet)).await {
        Ok(Ok(())) => Ok(packet.as_bytes().to_vec()),
        Ok(Err(e)) => Err(anyhow::anyhow!("failed to publish network record: {e:#}")),
        Err(_) => Err(anyhow::anyhow!(
            "timed out publishing network record after {}s",
            PUBLISH_TIMEOUT.as_secs()
        )),
    }
}

/// Resolves the raw signed network record packet. Use this when you need fields
/// beyond `(blob_hash, seed_peers)`, e.g. [`mesh_version_from_record`] for the
/// pre-dial compatibility check. Decode the standard fields with
/// [`decode_network_record`].
pub async fn resolve_network_packet(
    client: &PkarrClient,
    network_pubkey: EndpointId,
) -> Result<SignedPacket> {
    // `{e:#}` rather than `{e}`: the top-level Display of iroh's lookup error is
    // the bare "Service 'pkarr' failed", which says nothing. The alternate form
    // renders the source chain, so a DNS failure resolving the relay reads as
    // such instead of looking like the network record is missing.
    let resolve = client.resolve(network_pubkey);
    match tokio::time::timeout(RESOLVE_TIMEOUT, resolve).await {
        Ok(Ok(packet)) => Ok(packet),
        Ok(Err(e)) => Err(anyhow::anyhow!("{e:#}")),
        Err(_) => Err(anyhow::anyhow!(
            "timed out after {}s",
            RESOLVE_TIMEOUT.as_secs()
        )),
    }
}

pub async fn resolve_network(
    client: &PkarrClient,
    network_pubkey: EndpointId,
) -> Result<(blake3::Hash, Vec<EndpointId>)> {
    let packet = resolve_network_packet(client, network_pubkey).await?;
    decode_network_record(&packet)
}

/// Publish this user's contact record (`contact_key -> current endpoint`).
pub async fn publish_contact(
    client: &PkarrClient,
    contact_key: &SecretKey,
    endpoint: EndpointId,
) -> Result<()> {
    let packet = encode_contact_record(contact_key, endpoint)?;
    client
        .publish(&packet)
        .await
        .map_err(|e| anyhow::anyhow!("failed to publish contact record: {e:#}"))
}

/// Resolve a contact id to the holder's current transport EndpointId.
pub async fn resolve_contact(
    client: &PkarrClient,
    contact_pubkey: EndpointId,
) -> Result<EndpointId> {
    let packet = client
        .resolve(contact_pubkey)
        .await
        .map_err(|e| anyhow::anyhow!("failed to resolve contact record: {e:#}"))?;
    decode_contact_record(&packet)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {

    /// The SOCKS half of the record plane, against a live Tor daemon and the
    /// default pkarr server. Ignored by default: it needs `tor` running on
    /// 127.0.0.1:9050 and it talks to the public network.
    ///
    /// Run with: `cargo test -- --ignored pkarr_over_tor`
    ///
    /// Asserts we get an *HTTP* answer for a key nobody published, which is the
    /// distinction that matters: a 404 means the request reached the pkarr server
    /// through Tor, where a transport error would mean the proxy, the TLS stack
    /// or the `socks` feature is not doing its job. Resolving a random key
    /// publishes nothing and leaves no trace on the server.
    #[tokio::test]
    #[ignore = "needs a Tor daemon with SocksPort 9050"]
    async fn pkarr_over_tor_reaches_the_server() {
        let relay_url: Url = effective_pkarr_url().parse().unwrap();
        let proxy = reqwest::Proxy::all(format!("socks5h://127.0.0.1:{TOR_SOCKS_PORT}")).unwrap();
        let _ = rustls::crypto::ring::default_provider().install_default();
        let http = reqwest::Client::builder().proxy(proxy).build().unwrap();
        let client = PkarrClient::Socks { http, relay_url };

        let err = client
            .resolve(SecretKey::generate().public())
            .await
            .expect_err("a key nobody published cannot resolve");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("HTTP"),
            "expected an HTTP status from the server, got a transport failure: {msg}"
        );
    }
    use super::*;
    use iroh::SecretKey;

    #[test]
    fn effective_url_defaults_when_unset() {
        // The OnceLock is process-global; this binary never sets it, so the
        // default holds. (We avoid asserting the set path here to keep tests
        // order-independent.)
        assert_eq!(effective_pkarr_url(), PKARR_RELAY_URL);
    }

    #[test]
    fn network_record_roundtrip() {
        let key = SecretKey::generate();
        let hash = blake3::hash(b"test data");
        let peers = vec![
            SecretKey::generate().public(),
            SecretKey::generate().public(),
        ];
        let packet = encode_network_record(&key, &hash, &peers).unwrap();
        let (decoded_hash, decoded_peers) = decode_network_record(&packet).unwrap();
        assert_eq!(decoded_hash, hash);
        assert_eq!(decoded_peers, peers);
    }

    #[test]
    fn network_record_empty_peers() {
        let key = SecretKey::generate();
        let hash = blake3::hash(b"test");
        let packet = encode_network_record(&key, &hash, &[]).unwrap();
        let (decoded_hash, decoded_peers) = decode_network_record(&packet).unwrap();
        assert_eq!(decoded_hash, hash);
        assert!(decoded_peers.is_empty());
    }

    #[test]
    fn network_record_carries_mesh_version() {
        let key = SecretKey::generate();
        let hash = blake3::hash(b"test");
        let packet = encode_network_record(&key, &hash, &[]).unwrap();
        // A fresh record advertises this build's mesh protocol version, and the
        // standard hash/peers decode is unaffected by the added field.
        assert_eq!(
            mesh_version_from_record(&packet),
            Some(crate::transport::MESH_PROTOCOL_VERSION)
        );
        assert_eq!(decode_network_record(&packet).unwrap().0, hash);
    }

    #[test]
    fn mesh_version_absent_on_older_record() {
        // A record published before the `m,` field existed (only version + hash).
        let key = SecretKey::generate();
        let hash = blake3::hash(b"test");
        let values = vec![RECORD_VERSION.to_string(), format!("h,{hash}")];
        let packet = SignedPacket::from_txt_strings(&key, RECORD_NAME, values, RECORD_TTL).unwrap();
        assert_eq!(mesh_version_from_record(&packet), None);
    }

    #[test]
    fn verify_network_record_round_trips() {
        let key = SecretKey::generate();
        let hash = blake3::hash(b"test");
        let peer = SecretKey::generate().public();
        let bytes = encode_network_record(&key, &hash, &[peer])
            .unwrap()
            .as_bytes()
            .to_vec();
        // Correct key: verifies and decodes to the same hash + seeds.
        let packet = verify_network_record(&bytes, key.public()).unwrap();
        let (got_hash, got_peers) = decode_network_record(&packet).unwrap();
        assert_eq!(got_hash, hash);
        assert_eq!(got_peers, vec![peer]);
    }

    #[test]
    fn verify_network_record_rejects_wrong_key() {
        let key = SecretKey::generate();
        let hash = blake3::hash(b"test");
        let bytes = encode_network_record(&key, &hash, &[])
            .unwrap()
            .as_bytes()
            .to_vec();
        // A validly-signed record for a *different* network must be refused, so a
        // peer can't hand us a record for a network it controls.
        let other = SecretKey::generate().public();
        assert!(verify_network_record(&bytes, other).is_err());
    }

    #[test]
    fn verify_network_record_rejects_garbage() {
        let key = SecretKey::generate();
        assert!(verify_network_record(b"not a signed packet", key.public()).is_err());
    }

    #[test]
    fn record_version_check() {
        let key = SecretKey::generate();
        let hash = blake3::hash(b"test");
        let packet = encode_network_record(&key, &hash, &[]).unwrap();
        let records = packet.txt_records("_rayfish");
        assert_eq!(records[0], "v1");
    }

    #[test]
    fn decode_rejects_unknown_version() {
        let key = SecretKey::generate();
        let values = vec!["v99".to_string()];
        let packet = SignedPacket::from_txt_strings(&key, "_rayfish", values, 300).unwrap();
        let result = decode_network_record(&packet);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("unsupported record version")
        );
    }

    #[test]
    fn decode_rejects_empty_packet() {
        let key = SecretKey::generate();
        let values = vec!["v1".to_string()];
        let packet = SignedPacket::from_txt_strings(&key, "_other", values, 300).unwrap();
        let result = decode_network_record(&packet);
        assert!(result.is_err());
    }

    #[test]
    fn contact_record_roundtrip() {
        let contact = SecretKey::generate();
        let endpoint = SecretKey::generate().public();
        let packet = encode_contact_record(&contact, endpoint).unwrap();
        let decoded = decode_contact_record(&packet).unwrap();
        assert_eq!(decoded, endpoint);
    }

    #[test]
    fn contact_record_rejects_unknown_version() {
        let key = SecretKey::generate();
        let endpoint = SecretKey::generate().public();
        let values = vec!["v99".to_string(), format!("e,{endpoint}")];
        let packet =
            SignedPacket::from_txt_strings(&key, CONTACT_RECORD_NAME, values, 300).unwrap();
        let result = decode_contact_record(&packet);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("unsupported record version")
        );
    }

    #[test]
    fn contact_record_rejects_missing_endpoint() {
        let key = SecretKey::generate();
        let values = vec!["v1".to_string()];
        let packet =
            SignedPacket::from_txt_strings(&key, CONTACT_RECORD_NAME, values, 300).unwrap();
        let result = decode_contact_record(&packet);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("missing contact endpoint")
        );
    }

    #[test]
    fn decode_rejects_missing_hash() {
        let key = SecretKey::generate();
        let peer = SecretKey::generate().public();
        let values = vec!["v1".to_string(), format!("p,{peer}")];
        let packet = SignedPacket::from_txt_strings(&key, "_rayfish", values, 300).unwrap();
        let result = decode_network_record(&packet);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("missing blob hash")
        );
    }
}
