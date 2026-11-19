//! The endpoint's own lookups (relays, pkarr) ask encrypted public DNS first
//! and the network's nameservers only when that fails.
//!
//! Some networks rewrite plain DNS answers, such as a hotel filter that sends
//! every relay name to its block page. A rewritten answer is not a failure, so
//! racing the network's nameservers, or asking them first, lets it win and the
//! node reaches no relay. Encrypted answers cannot be rewritten in transit.
//!
//! An answer from the first tier is final, "no such name" and "no records of
//! this type" included; only a timeout or an unreachable server moves on.
//! Otherwise an empty A answer for an IPv6-only relay would ask the network
//! for A, and a block page's IPv4 address could win iroh's connection race.
//!
//! Names under a relay or discovery server the operator configured go to the
//! network first instead. Those can be split-horizon names, with a private
//! address only the local DNS knows, which public DNS would hide.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::Duration;

use futures::future::BoxFuture;
use iroh::dns::{BoxIter, DnsError, DnsResolver, Resolver, TxtRecordData};

/// How long the first tier has before the second is asked. iroh gives a whole
/// lookup three seconds, so the second tier keeps the rest.
const FIRST_WAIT: Duration = Duration::from_millis(1500);
/// The second tier's share of the lookup.
const SECOND_WAIT: Duration = Duration::from_millis(1500);

/// A resolver that asks `encrypted`, then `network` when that fails, except
/// for names under `local_names`, which ask `network` first.
pub(super) fn resolver(
    encrypted: DnsResolver,
    network: DnsResolver,
    local_names: Vec<String>,
) -> DnsResolver {
    let local_names = local_names
        .into_iter()
        .map(|name| normalize(&name).to_owned())
        .collect();
    DnsResolver::custom(EncryptedFirst {
        encrypted,
        network,
        local_names: Arc::new(local_names),
    })
}

#[derive(Debug, Clone)]
struct EncryptedFirst {
    encrypted: DnsResolver,
    network: DnsResolver,
    /// Lowercase, without a trailing dot.
    local_names: Arc<Vec<String>>,
}

fn normalize(name: &str) -> String {
    name.trim_end_matches('.').to_ascii_lowercase()
}

impl EncryptedFirst {
    /// The tier to ask first and the one to ask when it fails, for `host`.
    fn tiers(&self, host: &str) -> (DnsResolver, DnsResolver) {
        let host = normalize(host);
        let local = self.local_names.iter().any(|name| {
            host == *name
                || host
                    .strip_suffix(name.as_str())
                    .is_some_and(|rest| rest.ends_with('.'))
        });
        if local {
            (self.network.clone(), self.encrypted.clone())
        } else {
            (self.encrypted.clone(), self.network.clone())
        }
    }
}

/// Whether `error` means the first tier never got an answer, so the second
/// should be asked. An answer, even "no such name", is final.
fn unanswered(error: &DnsError) -> bool {
    !matches!(error, DnsError::NxDomain { .. })
}

/// Runs `$lookup` on the first tier for the host, then on the second when the
/// first got no answer, keeping the records `$pick` takes.
macro_rules! tiered {
    ($self:ident, $lookup:ident, $host:ident, $pick:expr) => {{
        let (first, second) = $self.tiers(&$host);
        Box::pin(async move {
            let found: Vec<_> = match first.$lookup(&$host, FIRST_WAIT).await {
                Ok(found) => found.filter_map($pick).collect(),
                Err(error) if unanswered(&error) => {
                    tracing::debug!(%error, host = %$host, "DNS got no answer, asking the other tier");
                    second
                        .$lookup(&$host, SECOND_WAIT)
                        .await?
                        .filter_map($pick)
                        .collect()
                }
                Err(error) => return Err(error),
            };
            Ok(Box::new(found.into_iter()) as BoxIter<_>)
        })
    }};
}

impl Resolver for EncryptedFirst {
    fn lookup_ipv4(&self, host: String) -> BoxFuture<'static, Result<BoxIter<Ipv4Addr>, DnsError>> {
        tiered!(self, lookup_ipv4, host, |ip| match ip {
            IpAddr::V4(ip) => Some(ip),
            IpAddr::V6(_) => None,
        })
    }

    fn lookup_ipv6(&self, host: String) -> BoxFuture<'static, Result<BoxIter<Ipv6Addr>, DnsError>> {
        tiered!(self, lookup_ipv6, host, |ip| match ip {
            IpAddr::V6(ip) => Some(ip),
            IpAddr::V4(_) => None,
        })
    }

    fn lookup_txt(
        &self,
        host: String,
    ) -> BoxFuture<'static, Result<BoxIter<TxtRecordData>, DnsError>> {
        tiered!(self, lookup_txt, host, Some)
    }

    fn clear_cache(&self) {
        self.encrypted.clear_cache();
        self.network.clear_cache();
    }

    /// A network change brings new nameservers and new sockets. Each inner
    /// resolver swaps in its own fresh replacement; neither does I/O here.
    fn reset(&self) -> Box<dyn Resolver> {
        self.encrypted.reset();
        self.network.reset();
        Box::new(self.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// What a [`Fixed`] resolver says to every A query.
    #[derive(Debug, Clone, Copy)]
    enum Says {
        Address(Ipv4Addr),
        NoRecords,
        NoSuchName,
        Nothing,
    }

    /// Gives `says` to every A query and counts the queries it saw.
    #[derive(Debug, Clone)]
    struct Fixed {
        says: Says,
        queries: Arc<AtomicUsize>,
    }

    impl Fixed {
        fn resolver(says: Says) -> (DnsResolver, Arc<AtomicUsize>) {
            let queries = Arc::new(AtomicUsize::new(0));
            let resolver = DnsResolver::custom(Self {
                says,
                queries: queries.clone(),
            });
            (resolver, queries)
        }
    }

    impl Resolver for Fixed {
        fn lookup_ipv4(
            &self,
            _host: String,
        ) -> BoxFuture<'static, Result<BoxIter<Ipv4Addr>, DnsError>> {
            self.queries.fetch_add(1, Ordering::SeqCst);
            let says = self.says;
            Box::pin(async move {
                match says {
                    Says::Address(ip) => Ok(Box::new(std::iter::once(ip)) as BoxIter<_>),
                    Says::NoRecords => Ok(Box::new(std::iter::empty()) as BoxIter<_>),
                    Says::NoSuchName => Err(n0_error::e!(DnsError::NxDomain)),
                    Says::Nothing => Err(n0_error::e!(DnsError::Timeout)),
                }
            })
        }
        fn lookup_ipv6(
            &self,
            _host: String,
        ) -> BoxFuture<'static, Result<BoxIter<Ipv6Addr>, DnsError>> {
            Box::pin(async { Err(n0_error::e!(DnsError::Timeout)) })
        }
        fn lookup_txt(
            &self,
            _host: String,
        ) -> BoxFuture<'static, Result<BoxIter<TxtRecordData>, DnsError>> {
            Box::pin(async { Err(n0_error::e!(DnsError::Timeout)) })
        }
        fn clear_cache(&self) {}
        fn reset(&self) -> Box<dyn Resolver> {
            Box::new(self.clone())
        }
    }

    const REAL: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
    const REWRITTEN: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 1);

    /// Looks up `host` with `encrypted` and `network`, returning what was found
    /// and how many queries the network saw.
    async fn lookup(
        host: &str,
        encrypted: Says,
        network: Says,
        local_names: &[&str],
    ) -> (Result<Vec<Ipv4Addr>, DnsError>, usize) {
        let (encrypted, _) = Fixed::resolver(encrypted);
        let (network, network_queries) = Fixed::resolver(network);
        let local_names = local_names.iter().map(|name| (*name).to_owned()).collect();
        let found = resolver(encrypted, network, local_names)
            .lookup_ipv4(host, Duration::from_secs(3))
            .await
            .map(|found| {
                found
                    .filter_map(|ip| match ip {
                        IpAddr::V4(ip) => Some(ip),
                        IpAddr::V6(_) => None,
                    })
                    .collect()
            });
        (found, network_queries.load(Ordering::SeqCst))
    }

    #[tokio::test]
    async fn an_encrypted_answer_beats_a_rewritten_one() {
        let (found, asked) = lookup(
            "relay.example",
            Says::Address(REAL),
            Says::Address(REWRITTEN),
            &[],
        )
        .await;
        assert_eq!(found.expect("encrypted DNS answers"), [REAL]);
        assert_eq!(asked, 0);
    }

    #[tokio::test]
    async fn the_network_answers_when_encrypted_dns_is_unreachable() {
        let (found, _) = lookup("relay.example", Says::Nothing, Says::Address(REAL), &[]).await;
        assert_eq!(found.expect("the network answers"), [REAL]);
    }

    #[tokio::test]
    async fn an_encrypted_negative_answer_is_final() {
        for says in [Says::NoRecords, Says::NoSuchName] {
            let (found, asked) = lookup("relay.example", says, Says::Address(REWRITTEN), &[]).await;
            assert!(found.map_or(true, |found| found.is_empty()), "{says:?}");
            assert_eq!(asked, 0, "{says:?}");
        }
    }

    #[tokio::test]
    async fn a_configured_name_asks_the_network_first() {
        for host in [
            "relay.home.example",
            "eu.relay.home.example.",
            "RELAY.home.example",
        ] {
            let (found, asked) = lookup(
                host,
                Says::Address(REWRITTEN),
                Says::Address(REAL),
                &["relay.home.example"],
            )
            .await;
            assert_eq!(found.expect("the network answers"), [REAL], "{host}");
            assert_eq!(asked, 1, "{host}");
        }
        let (found, asked) = lookup(
            "otherrelay.home.example",
            Says::Address(REAL),
            Says::Address(REWRITTEN),
            &["relay.home.example"],
        )
        .await;
        assert_eq!(found.expect("encrypted DNS answers"), [REAL]);
        assert_eq!(asked, 0);
    }
}
