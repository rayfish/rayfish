use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream, duplex};

fn authorization() -> String {
    format!(
        "Proxy-Authorization: Basic {}\r\n",
        STANDARD.encode("ray:test-password")
    )
}

async fn read_head(stream: &mut DuplexStream) -> String {
    let mut bytes = Vec::new();
    while !bytes.ends_with(b"\r\n\r\n") {
        bytes.push(stream.read_u8().await.unwrap());
        assert!(bytes.len() <= 16 * 1024);
    }
    String::from_utf8(bytes).unwrap()
}

#[tokio::test]
async fn rejects_missing_or_wrong_credentials_before_dialling() {
    tokio::time::timeout(Duration::from_secs(5), async {
        for auth in [String::new(), "Proxy-Authorization: Basic cmF5Ondyb25n\r\n".into()] {
            let (mut client, server) = duplex(4096);
            let attempts = Arc::new(AtomicUsize::new(0));
            let observed = Arc::clone(&attempts);
            let proxy = tokio::spawn(serve(server, Arc::new(Password::for_test(b"test-password")), move |_| {
                observed.fetch_add(1, Ordering::SeqCst);
                async { Err::<DuplexStream, _>(anyhow::anyhow!("unauthenticated request must not dial")) }
            }));
            client.write_all(format!("CONNECT peer.network.ray:443 HTTP/1.1\r\nHost: peer.network.ray:443\r\n{auth}\r\n").as_bytes()).await.unwrap();
            let mut response = String::new();
            client.read_to_string(&mut response).await.unwrap();
            assert!(response.starts_with("HTTP/1.1 407"));
            assert!(response.to_ascii_lowercase().contains("proxy-authenticate: basic"));
            assert_eq!(attempts.load(Ordering::SeqCst), 0);
            proxy.await.unwrap().unwrap();
        }
    }).await.unwrap();
}

#[tokio::test]
async fn forwards_streamed_http_bodies_and_routes_keepalive_requests_independently() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let (mut client, server) = duplex(4096);
        let (remotes, mut connections) = mpsc::channel(2);
        let fixture = tokio::spawn(async move {
            for expected_host in ["first.network.ray:8080", "second.network.ray"] {
                let remote = connections.recv().await.unwrap();
                let service = service_fn(move |request: Request<Incoming>| async move {
                    assert_eq!(request.uri(), "/path?query=value");
                    assert_eq!(request.headers()[HOST], expected_host);
                    for name in ["proxy-authorization", "proxy-connection", "x-request-hop"] {
                        assert!(!request.headers().contains_key(name));
                    }
                    let payload = request.into_body().collect().await.unwrap().to_bytes();
                    let mut response = Response::new(Full::new(payload));
                    response.headers_mut().insert(PROXY_AUTHENTICATE, HeaderValue::from_static("remove-me"));
                    Ok::<_, Infallible>(response)
                });
                server::Builder::new().serve_connection(TokioIo::new(remote), service).await.unwrap();
            }
        });
        let attempts = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&attempts);
        let proxy = tokio::spawn(serve(server, Arc::new(Password::for_test(b"test-password")), move |target| {
            let remotes = remotes.clone();
            let index = observed.fetch_add(1, Ordering::SeqCst);
            assert_eq!(target.to_string(), ["first.network.ray:8080", "second.network.ray:80"][index]);
            async move {
                let (local, remote) = duplex(4096);
                remotes.send(remote).await.unwrap();
                Ok(local)
            }
        }));
        let payload = vec![b'x'; 512 * 1024];
        client.write_all(format!("POST http://first.network.ray:8080/path?query=value HTTP/1.1\r\nHost: wrong.network.ray\r\n{}Connection: x-request-hop\r\nX-Request-Hop: remove-me\r\nProxy-Connection: keep-alive\r\nContent-Length: {}\r\n\r\n", authorization(), payload.len()).as_bytes()).await.unwrap();
        client.write_all(&payload).await.unwrap();
        let response = read_head(&mut client).await;
        assert!(response.starts_with("HTTP/1.1 200"));
        assert!(!response.to_ascii_lowercase().contains("proxy-authenticate"));
        let mut echoed = vec![0; payload.len()];
        client.read_exact(&mut echoed).await.unwrap();
        assert_eq!(echoed, payload);
        // The same proxy connection can carry another authority and a chunked upload.
        client.write_all(format!("POST http://second.network.ray/path?query=value HTTP/1.1\r\nHost: wrong.network.ray\r\n{}Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n5\r\nhello\r\n0\r\n\r\n", authorization()).as_bytes()).await.unwrap();
        assert!(read_head(&mut client).await.starts_with("HTTP/1.1 200"));
        let mut echoed = [0; 5];
        client.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"hello");
        let mut remaining = Vec::new();
        client.read_to_end(&mut remaining).await.unwrap();
        assert!(remaining.is_empty());
        proxy.await.unwrap().unwrap();
        fixture.await.unwrap();
        assert_eq!(attempts.load(Ordering::SeqCst), 2);
    }).await.unwrap();
}

#[tokio::test]
async fn connect_preserves_buffered_tunnel_bytes_and_half_closes() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let (mut client, server) = duplex(4096);
        let (sender, mut receiver) = mpsc::channel::<DuplexStream>(1);
        let fixture = tokio::spawn(async move {
            let mut remote = receiver.recv().await.unwrap();
            let mut request = Vec::new();
            remote.read_to_end(&mut request).await.unwrap();
            assert_eq!(request, b"\x16\x03\x03opaque-tls-bytes");
            remote.write_all(&request).await.unwrap();
            remote.shutdown().await.unwrap();
        });
        let proxy = tokio::spawn(serve(
            server,
            Arc::new(Password::for_test(b"test-password")),
            move |target| {
                assert_eq!(target.to_string(), "[200::1]:443");
                let sender = sender.clone();
                async move {
                    let (local, remote) = duplex(4096);
                    sender.send(remote).await.unwrap();
                    Ok(local)
                }
            },
        ));
        let mut request = format!(
            "CONNECT [200::1]:443 HTTP/1.1\r\nHost: [200::1]:443\r\n{}\r\n",
            authorization()
        )
        .into_bytes();
        request.extend_from_slice(b"\x16\x03\x03opaque-tls-bytes");
        client.write_all(&request).await.unwrap();
        assert!(read_head(&mut client).await.starts_with("HTTP/1.1 200"));
        client.shutdown().await.unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        assert_eq!(response, b"\x16\x03\x03opaque-tls-bytes");
        proxy.await.unwrap().unwrap();
        fixture.await.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn reports_connection_failures_without_accepting_the_tunnel() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let (mut client, server) = duplex(4096);
        let proxy = tokio::spawn(serve(
            server,
            Arc::new(Password::for_test(b"test-password")),
            |_| async { Err::<DuplexStream, _>(anyhow::anyhow!("peer unreachable")) },
        ));
        client
            .write_all(
                format!(
                    "CONNECT peer.network.ray:443 HTTP/1.1\r\nHost: peer.network.ray:443\r\n{}\r\n",
                    authorization()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let mut response = String::new();
        client.read_to_string(&mut response).await.unwrap();
        assert!(response.starts_with("HTTP/1.1 502"));
        proxy.await.unwrap().unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn removes_hop_headers_named_by_each_side() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let (mut client, server) = duplex(4096);
        let (sender, mut receiver) = mpsc::channel::<DuplexStream>(1);
        let fixture = tokio::spawn(async move {
            let mut remote = receiver.recv().await.unwrap();
            let request = read_head(&mut remote).await.to_ascii_lowercase();
            for header in ["x-request-hop", "proxy-authorization", "proxy-connection"] {
                assert!(!request.contains(header));
            }
            remote.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close, x-response-hop\r\nX-Response-Hop: remove-me\r\nProxy-Authenticate: remove-me\r\n\r\nok").await.unwrap();
            remote.shutdown().await.unwrap();
        });
        let proxy = tokio::spawn(serve(server, Arc::new(Password::for_test(b"test-password")), move |_| {
            let sender = sender.clone();
            async move {
                let (local, remote) = duplex(4096);
                sender.send(remote).await.unwrap();
                Ok(local)
            }
        }));
        client.write_all(format!("GET http://peer.network.ray/ HTTP/1.1\r\nHost: peer.network.ray\r\n{}Connection: close, x-request-hop\r\nX-Request-Hop: remove-me\r\nProxy-Connection: keep-alive\r\n\r\n", authorization()).as_bytes()).await.unwrap();
        let response = read_head(&mut client).await.to_ascii_lowercase();
        assert!(response.starts_with("http/1.1 200"));
        assert!(!response.contains("x-response-hop"));
        assert!(!response.contains("proxy-authenticate"));
        let mut body = Vec::new();
        client.read_to_end(&mut body).await.unwrap();
        assert_eq!(body, b"ok");
        fixture.await.unwrap();
        proxy.await.unwrap().unwrap();
    }).await.unwrap();
}

#[tokio::test]
async fn rejects_invalid_proxy_targets_before_dialling() {
    tokio::time::timeout(Duration::from_secs(5), async {
        for request in [
            "GET / HTTP/1.1\r\nHost: peer.network.ray\r\n",
            "GET https://peer.network.ray/ HTTP/1.1\r\nHost: peer.network.ray\r\n",
            "CONNECT peer.network.ray:0 HTTP/1.1\r\nHost: peer.network.ray\r\n",
            "CONNECT user@peer.network.ray:443 HTTP/1.1\r\nHost: peer.network.ray\r\n",
        ] {
            let (mut client, server) = duplex(4096);
            let attempts = Arc::new(AtomicUsize::new(0));
            let observed = Arc::clone(&attempts);
            let proxy = tokio::spawn(serve(
                server,
                Arc::new(Password::for_test(b"test-password")),
                move |_| {
                    observed.fetch_add(1, Ordering::SeqCst);
                    async {
                        Err::<DuplexStream, _>(anyhow::anyhow!("invalid request must not dial"))
                    }
                },
            ));
            client
                .write_all(
                    format!("{request}{}Connection: close\r\n\r\n", authorization()).as_bytes(),
                )
                .await
                .unwrap();
            let mut response = String::new();
            client.read_to_string(&mut response).await.unwrap();
            assert!(response.starts_with("HTTP/1.1 400"), "{response}");
            assert_eq!(attempts.load(Ordering::SeqCst), 0);
            proxy.await.unwrap().unwrap();
        }
    })
    .await
    .unwrap();
}
