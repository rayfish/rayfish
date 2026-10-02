//! The endpoint's DNS sockets must work before the exit tunnel is reachable.

use std::fmt::{self, Debug, Formatter};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use futures::future::BoxFuture;
use hickory_resolver::Resolver as HickoryResolver;
use hickory_resolver::config::{NameServerConfig, ResolverConfig};
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
        let resolver =
            HickoryResolver::builder_with_config(self.config.clone(), UnderlayRuntime::default())
                .build()
                .unwrap_or_else(|_| self.resolver.clone());
        Box::new(Self {
            resolver,
            config: self.config.clone(),
        })
    }
}

pub(super) fn resolver(nameservers: &[Ipv4Addr]) -> anyhow::Result<DnsResolver> {
    let mut config = ResolverConfig::default();
    for ip in nameservers {
        config.add_name_server(NameServerConfig::udp_and_tcp(IpAddr::V4(*ip)));
    }
    let mut builder =
        HickoryResolver::builder_with_config(config.clone(), UnderlayRuntime::default());
    builder.options_mut().negative_max_ttl = Some(Duration::ZERO);
    let resolver = builder.build()?;
    Ok(DnsResolver::custom(UnderlayResolver { resolver, config }))
}
