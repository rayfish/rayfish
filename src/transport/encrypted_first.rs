//! The endpoint's own lookups (relays, pkarr) ask encrypted public DNS first
//! and the network's nameservers only when that fails.
//!
//! Some networks rewrite plain DNS answers, such as a hotel filter that sends
//! every relay name to its block page. A rewritten answer is not a failure, so
//! racing the network's nameservers, or asking them first, lets it win and the
//! node reaches no relay. Encrypted answers cannot be rewritten in transit.
//!
//! Any failure falls back, NXDOMAIN included: a self-hosted relay can have a
//! name only the local network's DNS knows.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use futures::future::BoxFuture;
use iroh::dns::{BoxIter, DnsError, DnsResolver, Resolver, TxtRecordData};

/// How long encrypted DNS has before the network's nameservers are asked.
/// iroh gives a whole lookup three seconds, so the network keeps the rest.
const ENCRYPTED_WAIT: Duration = Duration::from_millis(1500);
/// The network's share of the lookup.
const FALLBACK_WAIT: Duration = Duration::from_millis(1500);

/// A resolver that asks `encrypted`, then `fallback` when that fails.
pub(super) fn resolver(encrypted: DnsResolver, fallback: DnsResolver) -> DnsResolver {
    DnsResolver::custom(EncryptedFirst {
        encrypted,
        fallback,
    })
}

#[derive(Debug, Clone)]
struct EncryptedFirst {
    encrypted: DnsResolver,
    fallback: DnsResolver,
}

/// Runs `$lookup` on the encrypted resolver, then on the fallback when that
/// fails, keeping the records `$pick` takes.
macro_rules! encrypted_first {
    ($self:ident, $lookup:ident, $host:ident, $pick:expr) => {{
        let encrypted = $self.encrypted.clone();
        let fallback = $self.fallback.clone();
        Box::pin(async move {
            let found: Vec<_> = match encrypted.$lookup(&$host, ENCRYPTED_WAIT).await {
                Ok(found) => found.filter_map($pick).collect(),
                Err(error) => {
                    tracing::debug!(%error, host = %$host, "encrypted DNS failed, asking the network");
                    fallback
                        .$lookup(&$host, FALLBACK_WAIT)
                        .await?
                        .filter_map($pick)
                        .collect()
                }
            };
            Ok(Box::new(found.into_iter()) as BoxIter<_>)
        })
    }};
}

impl Resolver for EncryptedFirst {
    fn lookup_ipv4(&self, host: String) -> BoxFuture<'static, Result<BoxIter<Ipv4Addr>, DnsError>> {
        encrypted_first!(self, lookup_ipv4, host, |ip| match ip {
            IpAddr::V4(ip) => Some(ip),
            IpAddr::V6(_) => None,
        })
    }

    fn lookup_ipv6(&self, host: String) -> BoxFuture<'static, Result<BoxIter<Ipv6Addr>, DnsError>> {
        encrypted_first!(self, lookup_ipv6, host, |ip| match ip {
            IpAddr::V6(ip) => Some(ip),
            IpAddr::V4(_) => None,
        })
    }

    fn lookup_txt(
        &self,
        host: String,
    ) -> BoxFuture<'static, Result<BoxIter<TxtRecordData>, DnsError>> {
        encrypted_first!(self, lookup_txt, host, Some)
    }

    fn clear_cache(&self) {
        self.encrypted.clear_cache();
        self.fallback.clear_cache();
    }

    /// A network change brings new nameservers and new sockets. Each inner
    /// resolver swaps in its own fresh replacement; neither does I/O here.
    fn reset(&self) -> Box<dyn Resolver> {
        self.encrypted.reset();
        self.fallback.reset();
        Box::new(self.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Answers every A query with `answer`, or fails when it is `None`, and
    /// counts the queries it saw.
    #[derive(Debug, Clone)]
    struct Fixed {
        answer: Option<Ipv4Addr>,
        queries: Arc<AtomicUsize>,
    }

    impl Fixed {
        fn resolver(answer: Option<Ipv4Addr>) -> (DnsResolver, Arc<AtomicUsize>) {
            let queries = Arc::new(AtomicUsize::new(0));
            let resolver = DnsResolver::custom(Self {
                answer,
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
            let answer = self.answer;
            Box::pin(async move {
                match answer {
                    Some(ip) => Ok(Box::new(std::iter::once(ip)) as BoxIter<_>),
                    None => Err(n0_error::e!(DnsError::Timeout)),
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

    #[tokio::test]
    async fn an_encrypted_answer_beats_a_rewritten_one() {
        let (encrypted, _) = Fixed::resolver(Some(REAL));
        let (network, network_queries) = Fixed::resolver(Some(REWRITTEN));
        let resolver = resolver(encrypted, network);
        let found: Vec<_> = resolver
            .lookup_ipv4("relay.example", Duration::from_secs(3))
            .await
            .expect("encrypted DNS answers")
            .collect();
        assert_eq!(found, [REAL]);
        assert_eq!(network_queries.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn the_network_answers_when_encrypted_dns_fails() {
        let (encrypted, _) = Fixed::resolver(None);
        let (network, _) = Fixed::resolver(Some(REAL));
        let resolver = resolver(encrypted, network);
        let found: Vec<_> = resolver
            .lookup_ipv4("relay.example", Duration::from_secs(3))
            .await
            .expect("the network answers")
            .collect();
        assert_eq!(found, [REAL]);
    }
}
