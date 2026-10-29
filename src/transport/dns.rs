//! The endpoint's DNS sockets must work before the exit tunnel is reachable.

use std::fmt::{self, Debug, Formatter};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use futures::future::BoxFuture;
use hickory_resolver::Resolver as HickoryResolver;
use hickory_resolver::config::{CLOUDFLARE, GOOGLE, NameServerConfig, ResolverConfig};
use hickory_resolver::net::runtime::{
    RuntimeProvider, TokioRuntimeProvider, iocompat::AsyncIoTokioAsStd,
};
use hickory_resolver::proto::rr::RData;
use iroh::dns::{BoxIter, DnsError, DnsResolver, Resolver, TxtRecordData};
use n0_error::StdResultExt;
use socket2::{Domain, SockRef};
use tokio::net::{TcpSocket, UdpSocket};
use tokio::time::timeout;

use super::dns_socket::{UnderlayTcp, UnderlayUdp};
use super::{LoopPrevention, SocketConfigurator};

#[derive(Clone, Default)]
struct UnderlayRuntime(TokioRuntimeProvider);

impl RuntimeProvider for UnderlayRuntime {
    type Handle = <TokioRuntimeProvider as RuntimeProvider>::Handle;
    type Timer = <TokioRuntimeProvider as RuntimeProvider>::Timer;
    type Udp = UnderlayUdp;
    type Tcp = AsyncIoTokioAsStd<UnderlayTcp>;

    fn create_handle(&self) -> Self::Handle {
        self.0.create_handle()
    }

    fn connect_tcp(
        &self,
        server: SocketAddr,
        bind: Option<SocketAddr>,
        wait: Option<Duration>,
    ) -> BoxFuture<'static, io::Result<Self::Tcp>> {
        Box::pin(async move {
            let socket = if server.is_ipv4() {
                TcpSocket::new_v4()?
            } else {
                TcpSocket::new_v6()?
            };
            LoopPrevention.configure(SockRef::from(&socket), Domain::for_address(server))?;
            let bind = bind.unwrap_or_else(|| {
                if server.is_ipv4() {
                    SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))
                } else {
                    SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0))
                }
            });
            socket.bind(bind)?;
            socket.set_nodelay(true)?;
            let stream = timeout(
                wait.unwrap_or(Duration::from_secs(5)),
                UnderlayTcp::connect(socket, server),
            )
            .await??;
            Ok(AsyncIoTokioAsStd(stream))
        })
    }

    fn bind_udp(
        &self,
        local: SocketAddr,
        server: SocketAddr,
    ) -> BoxFuture<'static, io::Result<Self::Udp>> {
        Box::pin(async move {
            let socket = UdpSocket::bind(local).await?;
            LoopPrevention.configure(SockRef::from(&socket), Domain::for_address(local))?;
            UnderlayUdp::new(socket, server).await
        })
    }
}

#[derive(Clone)]
struct UnderlayResolver {
    resolver: HickoryResolver<UnderlayRuntime>,
    config: ResolverConfig,
}

impl Debug for UnderlayResolver {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("UnderlayResolver").finish_non_exhaustive()
    }
}

impl Resolver for UnderlayResolver {
    fn lookup_ipv4(&self, host: String) -> BoxFuture<'static, Result<BoxIter<Ipv4Addr>, DnsError>> {
        let resolver = self.resolver.clone();
        Box::pin(async move {
            let lookup = resolver.ipv4_lookup(host).await.anyerr()?;
            let addresses: Vec<_> = lookup
                .answers()
                .iter()
                .filter_map(|r| match &r.data {
                    RData::A(ip) => Some(ip.0),
                    _ => None,
                })
                .collect();
            Ok(Box::new(addresses.into_iter()) as BoxIter<_>)
        })
    }
    fn lookup_ipv6(&self, host: String) -> BoxFuture<'static, Result<BoxIter<Ipv6Addr>, DnsError>> {
        let resolver = self.resolver.clone();
        Box::pin(async move {
            let lookup = resolver.ipv6_lookup(host).await.anyerr()?;
            let addresses: Vec<_> = lookup
                .answers()
                .iter()
                .filter_map(|r| match &r.data {
                    RData::AAAA(ip) => Some(ip.0),
                    _ => None,
                })
                .collect();
            Ok(Box::new(addresses.into_iter()) as BoxIter<_>)
        })
    }
    fn lookup_txt(
        &self,
        host: String,
    ) -> BoxFuture<'static, Result<BoxIter<TxtRecordData>, DnsError>> {
        let resolver = self.resolver.clone();
        Box::pin(async move {
            let lookup = resolver.txt_lookup(host).await.anyerr()?;
            let records: Vec<_> = lookup
                .answers()
                .iter()
                .filter_map(|r| match &r.data {
                    RData::TXT(txt) => Some(TxtRecordData::from(txt.txt_data.to_vec())),
                    _ => None,
                })
                .collect();
            Ok(Box::new(records.into_iter()) as BoxIter<_>)
        })
    }
    fn clear_cache(&self) {
        self.resolver.clear_cache();
    }
    fn reset(&self) -> Box<dyn Resolver> {
        let mut builder =
            HickoryResolver::builder_with_config(self.config.clone(), UnderlayRuntime::default());
        *builder.options_mut() = self.resolver.options().clone();
        let resolver = builder.build().unwrap_or_else(|error| {
            tracing::warn!(%error, "cannot reset control-plane DNS; retaining the existing resolver");
            self.resolver.clone()
        });
        Box::new(Self {
            resolver,
            config: self.config.clone(),
        })
    }
}

pub(super) fn resolver(
    nameservers: &[IpAddr],
    allow_fallback: bool,
) -> anyhow::Result<DnsResolver> {
    let mut config = ResolverConfig::default();
    for ip in nameservers {
        config.add_name_server(NameServerConfig::udp_and_tcp(*ip));
    }
    if allow_fallback {
        for group in [&CLOUDFLARE, &GOOGLE] {
            // Each provider's primary IPv4 and IPv6 addresses, over HTTPS.
            for server in group.https().take(2) {
                config.add_name_server(server);
            }
        }
    }
    let mut builder =
        HickoryResolver::builder_with_config(config.clone(), UnderlayRuntime::default());
    builder.options_mut().negative_max_ttl = Some(Duration::ZERO);
    if allow_fallback {
        // Race at most four configured servers and four encrypted fallbacks.
        // Dropped port-53 packets must not hold every slot until the outer timeout.
        builder.options_mut().num_concurrent_reqs = 8;
    }
    let resolver = builder.build()?;
    Ok(DnsResolver::custom(UnderlayResolver { resolver, config }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore = "run tests/transport-dns-fallback.sh"]
    async fn public_discovery_dns_survives_blocked_plain_dns() {
        use std::env;

        use iroh::dns::{DNS_TIMEOUT, NameserverConfig as IrohNameserverConfig};

        assert_eq!(env::var("RAYFISH_BLOCK_PLAIN_DNS_TEST").as_deref(), Ok("1"));
        let primary = [
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
        ];
        let stock = DnsResolver::builder()
            .add_nameserver_configs(primary.into_iter().map(IrohNameserverConfig::udp))
            .build();
        assert!(
            stock
                .lookup_ipv4("example.com", Duration::from_secs(10))
                .await
                .expect("the stock resolver reaches its encrypted fallback")
                .next()
                .is_some()
        );
        let strict = resolver(&primary, false).expect("explicit replacement builds");
        assert!(
            strict
                .lookup_ipv4("example.com", Duration::from_secs(2))
                .await
                .is_err(),
            "explicit replacement cannot reach a public fallback"
        );
        let underlay = resolver(&primary, true).expect("underlay resolver builds");
        assert!(
            underlay
                .lookup_ipv4("example.com", DNS_TIMEOUT)
                .await
                .expect("underlay DNS must retain encrypted fallback")
                .next()
                .is_some()
        );
        underlay.reset();
        assert!(
            underlay
                .lookup_ipv4("example.org", DNS_TIMEOUT)
                .await
                .expect("encrypted fallback survives a network reset")
                .next()
                .is_some()
        );
    }

    #[tokio::test]
    async fn a_peer_published_after_a_dns_miss_is_found_after_reset() {
        use tokio::task::JoinSet;

        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("local DNS binds");
        let address = socket.local_addr().expect("bound socket has an address");
        let mut server = JoinSet::new();
        server.spawn(async move {
            let mut query = [0; 512];
            for negative in [true, false] {
                let (_, peer) = socket
                    .recv_from(&mut query)
                    .await
                    .expect("receive DNS query");
                let mut end = 12;
                while query[end] != 0 {
                    end += usize::from(query[end]) + 1;
                }
                let mut response = query[..end + 5].to_vec();
                response[2..4].copy_from_slice(if negative {
                    &[0x85, 0x83]
                } else {
                    &[0x85, 0x80]
                });
                response[6..12].copy_from_slice(if negative {
                    &[0, 0, 0, 1, 0, 0]
                } else {
                    &[0, 1, 0, 0, 0, 0]
                });
                response.extend_from_slice(&[0xc0, 0x0c]);
                if negative {
                    // SOA with a five-minute negative TTL, before the peer publishes.
                    response.extend_from_slice(&[0, 6, 0, 1, 0, 0, 1, 44, 0, 22, 0, 0]);
                    for value in [1u32, 300, 300, 300, 300] {
                        response.extend_from_slice(&value.to_be_bytes());
                    }
                } else {
                    response.extend_from_slice(&[0, 1, 0, 1, 0, 0, 1, 44, 0, 4, 203, 0, 113, 1]);
                }
                socket
                    .send_to(&response, peer)
                    .await
                    .expect("send DNS response");
            }
        });
        let mut nameserver = NameServerConfig::udp(address.ip());
        nameserver.connections[0].port = address.port();
        let config = ResolverConfig::from_name_servers(vec![nameserver]);
        let mut builder =
            HickoryResolver::builder_with_config(config.clone(), UnderlayRuntime::default());
        builder.options_mut().negative_max_ttl = Some(Duration::ZERO);
        let resolver = UnderlayResolver {
            resolver: builder.build().expect("test resolver config is valid"),
            config,
        }
        .reset();
        assert!(
            resolver
                .lookup_ipv4("new-peer.example.".to_owned())
                .await
                .is_err()
        );
        let found: Vec<_> = resolver
            .lookup_ipv4("new-peer.example.".to_owned())
            .await
            .expect("a previously missing record must be queried again")
            .collect();
        assert_eq!(found, [Ipv4Addr::new(203, 0, 113, 1)]);
        server
            .join_next()
            .await
            .expect("DNS server task exists")
            .expect("DNS server completed");
    }

    #[tokio::test]
    async fn empty_replacement_cannot_use_a_fallback_after_reset() {
        let resolver = resolver(&[], false).expect("an empty resolver config is valid");
        assert!(
            resolver
                .lookup_ipv4("example.com", Duration::from_secs(1))
                .await
                .is_err()
        );
        resolver.reset();
        assert!(
            resolver
                .lookup_ipv6("example.com", Duration::from_secs(1))
                .await
                .is_err()
        );
    }
}
