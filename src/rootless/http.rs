//! HTTP/1 forward proxy and CONNECT tunnels, sharing the SOCKS5 credentials.
//! Hyper owns HTTP framing; every upstream connection is owned by its client task.

use std::convert::Infallible;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use bytes::Bytes;
use http_body_util::{BodyExt, Full, combinators::UnsyncBoxBody};
use hyper::body::Incoming;
use hyper::client::conn::http1::{self as client, Connection};
use hyper::header::{
    CONNECTION, HOST, HeaderMap, HeaderName, HeaderValue, PROXY_AUTHENTICATE, PROXY_AUTHORIZATION,
};
use hyper::server::conn::http1 as server;
use hyper::service::service_fn;
use hyper::upgrade::OnUpgrade;
use hyper::{Method, Request, Response, StatusCode, Uri};
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::io::{AsyncRead, AsyncWrite, copy_bidirectional};
use tokio::sync::mpsc;
use tokio::task::JoinSet;

use super::Target;
use super::proxy::Password;

const MAX_UPSTREAMS: usize = 16;
const HEADER_TIMEOUT: Duration = Duration::from_secs(15);
const DIAL_TIMEOUT: Duration = Duration::from_secs(30);
type ProxyBody = UnsyncBoxBody<Bytes, hyper::Error>;

struct Tunnel<R> {
    upgrade: OnUpgrade,
    remote: R,
}

pub(super) async fn serve<S, D, F, R>(io: S, password: Arc<Password>, dial: D) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    R: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    D: Fn(Target) -> F + Clone + Send + Sync + 'static,
    F: Future<Output = Result<R>> + Send,
{
    let (upstreams, mut upstream_rx) = mpsc::channel::<Connection<TokioIo<R>, Incoming>>(1);
    let (tunnels, mut tunnel_rx) = mpsc::channel(1);
    let service = service_fn(move |request| {
        let password = Arc::clone(&password);
        let dial = dial.clone();
        let upstreams = upstreams.clone();
        let tunnels = tunnels.clone();
        async move { Ok::<_, Infallible>(proxy(request, &password, dial, upstreams, tunnels).await) }
    });
    let connection = server::Builder::new()
        .timer(TokioTimer::new())
        .header_read_timeout(HEADER_TIMEOUT)
        .max_headers(64)
        .max_buf_size(16 * 1024)
        .serve_connection(TokioIo::new(io), service)
        .with_upgrades();
    tokio::pin!(connection);
    let mut tasks = JoinSet::new();
    let result = loop {
        tokio::select! {
            result = &mut connection => break result,
            Some(upstream) = upstream_rx.recv(), if tasks.len() < MAX_UPSTREAMS => { tasks.spawn(upstream); },
            Some(result) = tasks.join_next(), if !tasks.is_empty() => {
                match result {
                    Ok(Err(error)) => tracing::debug!(%error, "HTTP upstream connection ended"),
                    Err(error) => return Err(error).context("HTTP upstream task failed"),
                    Ok(Ok(())) => {},
                }
            }
        }
    };
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    result.context("HTTP proxy client connection ended")?;
    if let Ok(Tunnel {
        upgrade,
        mut remote,
    }) = tunnel_rx.try_recv()
    {
        let mut client = TokioIo::new(upgrade.await?);
        copy_bidirectional(&mut client, &mut remote).await?;
    }
    Ok(())
}

async fn proxy<D, F, R>(
    mut request: Request<Incoming>,
    password: &Password,
    dial: D,
    upstreams: mpsc::Sender<Connection<TokioIo<R>, Incoming>>,
    tunnels: mpsc::Sender<Tunnel<R>>,
) -> Response<ProxyBody>
where
    R: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    D: Fn(Target) -> F,
    F: Future<Output = Result<R>>,
{
    if !authenticated(request.headers(), password) {
        let mut response = failure(
            StatusCode::PROXY_AUTHENTICATION_REQUIRED,
            "Proxy authentication required\n",
        );
        response.headers_mut().insert(
            PROXY_AUTHENTICATE,
            HeaderValue::from_static("Basic realm=\"Rayfish\""),
        );
        return response;
    }
    let target = match target(&request) {
        Ok(target) => target,
        Err(_) => {
            return failure(
                StatusCode::BAD_REQUEST,
                "Expected an HTTP URL or CONNECT authority\n",
            );
        }
    };
    let remote = match tokio::time::timeout(DIAL_TIMEOUT, dial(target)).await {
        Ok(Ok(remote)) => remote,
        _ => {
            return failure(
                StatusCode::BAD_GATEWAY,
                "Unable to connect to the mesh destination\n",
            );
        }
    };
    if request.method() == Method::CONNECT {
        if tunnels
            .send(Tunnel {
                upgrade: hyper::upgrade::on(&mut request),
                remote,
            })
            .await
            .is_err()
        {
            return failure(StatusCode::BAD_GATEWAY, "Proxy connection closed\n");
        }
        return Response::new(body(Bytes::new()));
    }
    // The URI authority selects both the mesh destination and the upstream Host header.
    let host = match request
        .uri()
        .authority()
        .and_then(|authority| HeaderValue::from_str(authority.as_str()).ok())
    {
        Some(host) => host,
        None => return failure(StatusCode::BAD_REQUEST, "Invalid HTTP authority\n"),
    };
    *request.uri_mut() = request
        .uri()
        .path_and_query()
        .cloned()
        .map(Uri::from)
        .unwrap_or_default();
    strip_hop_headers(request.headers_mut());
    request.headers_mut().insert(HOST, host);
    request
        .headers_mut()
        .insert(CONNECTION, HeaderValue::from_static("close"));
    let (mut sender, connection) = match client::handshake(TokioIo::new(remote)).await {
        Ok(connection) => connection,
        Err(_) => {
            return failure(
                StatusCode::BAD_GATEWAY,
                "Unable to open an HTTP connection\n",
            );
        }
    };
    if upstreams.send(connection).await.is_err() {
        return failure(StatusCode::BAD_GATEWAY, "Proxy connection closed\n");
    }
    match sender.send_request(request).await {
        Ok(mut response) => {
            strip_hop_headers(response.headers_mut());
            response.map(BodyExt::boxed_unsync)
        }
        Err(_) => failure(StatusCode::BAD_GATEWAY, "Mesh HTTP request failed\n"),
    }
}

fn target(request: &Request<Incoming>) -> Result<Target> {
    let uri = request.uri();
    let authority = uri.authority().context("missing proxy authority")?;
    anyhow::ensure!(
        !authority.as_str().contains('@'),
        "userinfo is not supported"
    );
    if request.method() == Method::CONNECT {
        anyhow::ensure!(
            uri.scheme().is_none() && uri.path_and_query().is_none(),
            "CONNECT requires authority form"
        );
        anyhow::ensure!(
            !request.headers().contains_key("transfer-encoding")
                && request
                    .headers()
                    .get("content-length")
                    .is_none_or(|value| value == "0"),
            "CONNECT cannot have a body"
        );
        return authority.as_str().parse();
    }
    anyhow::ensure!(uri.scheme_str() == Some("http"), "HTTPS requires CONNECT");
    if authority.port().is_some() {
        authority.as_str().parse()
    } else {
        format!("{authority}:80").parse()
    }
}

fn authenticated(headers: &HeaderMap, password: &Password) -> bool {
    let mut values = headers.get_all(PROXY_AUTHORIZATION).iter();
    let Some(header) = values.next().and_then(|value| value.to_str().ok()) else {
        return false;
    };
    if values.next().is_some() {
        return false;
    }
    let Some((scheme, encoded)) = header.split_once(' ') else {
        return false;
    };
    if !scheme.eq_ignore_ascii_case("Basic") {
        return false;
    }
    let Ok(credentials) = STANDARD.decode(encoded.trim()) else {
        return false;
    };
    credentials
        .strip_prefix(b"ray:")
        .is_some_and(|candidate| password.matches(candidate))
}

fn strip_hop_headers(headers: &mut HeaderMap) {
    let named: Vec<HeaderName> = headers
        .get_all(CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(|name| HeaderName::from_bytes(name.trim().as_bytes()).ok())
        .collect();
    for name in named {
        headers.remove(name);
    }
    for name in [
        "connection",
        "proxy-connection",
        "keep-alive",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
        "proxy-authenticate",
        "proxy-authorization",
    ] {
        headers.remove(name);
    }
}

fn body(bytes: Bytes) -> ProxyBody {
    Full::new(bytes)
        .map_err(|never| match never {})
        .boxed_unsync()
}

fn failure(status: StatusCode, message: &'static str) -> Response<ProxyBody> {
    let mut response = Response::new(body(Bytes::from_static(message.as_bytes())));
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert(CONNECTION, HeaderValue::from_static("close"));
    response
}

#[cfg(test)]
mod tests;
