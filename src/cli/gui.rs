//! Local browser GUI for the `ray` CLI.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Command as ProcessCommand, Stdio};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::*;

const GUI_HTML: &str = include_str!("gui.html");
const MAX_BODY: usize = 64 * 1024;
const MAX_OUTPUT: usize = 256 * 1024;
const COMMAND_TIMEOUT: Duration = Duration::from_secs(300);

#[derive(Deserialize)]
struct RunRequest {
    args: Vec<String>,
    #[serde(default)]
    json: bool,
}

#[derive(Serialize)]
struct RunResponse {
    command: Vec<String>,
    status: i32,
    success: bool,
    stdout: String,
    stderr: String,
    timed_out: bool,
}

pub(crate) fn cmd_gui(port: u16, no_open: bool) -> Result<()> {
    let listener = TcpListener::bind(("127.0.0.1", port)).context("binding local GUI server")?;
    let addr = listener.local_addr()?;
    let token = gui_token();
    let url = format!("http://{addr}/?token={token}");
    let exe = std::env::current_exe().context("finding current ray executable")?;

    println!("rayfish GUI listening on {url}");
    if !no_open && !open_url(&url) {
        println!("Open that URL in your browser.");
    }

    for stream in listener.incoming() {
        let token = token.clone();
        let exe = exe.clone();
        match stream {
            Ok(stream) => {
                std::thread::spawn(move || {
                    if let Err(err) = handle_client(stream, &token, &exe) {
                        eprintln!("gui request failed: {err:#}");
                    }
                });
            }
            Err(err) => eprintln!("gui connection failed: {err}"),
        }
    }
    Ok(())
}

fn gui_token() -> String {
    hex::encode(rand::random::<[u8; 16]>())
}

fn handle_client(mut stream: TcpStream, token: &str, exe: &std::path::Path) -> Result<()> {
    let req = read_http_request(&mut stream)?;
    match (req.method.as_str(), req.path.as_str()) {
        ("GET", "/") | ("GET", "/index.html") => {
            if !query_has_token(&req.target, token) {
                return respond_text(&mut stream, 403, "text/plain; charset=utf-8", "bad token");
            }
            let body = GUI_HTML.replace("__TOKEN__", token);
            respond_text(&mut stream, 200, "text/html; charset=utf-8", &body)
        }
        ("POST", "/run") => {
            if req.header("x-rayfish-token") != Some(token) {
                return respond_text(
                    &mut stream,
                    403,
                    "application/json",
                    r#"{"error":"bad token"}"#,
                );
            }
            let run: RunRequest = serde_json::from_slice(&req.body).context("invalid JSON body")?;
            let args = prepare_ray_args(run.args, run.json)?;
            let response = run_ray_command(exe, args)?;
            let body = serde_json::to_string(&response)?;
            respond_text(&mut stream, 200, "application/json", &body)
        }
        _ => respond_text(&mut stream, 404, "text/plain; charset=utf-8", "not found"),
    }
}

fn prepare_ray_args(mut args: Vec<String>, json: bool) -> Result<Vec<String>> {
    args.retain(|arg| !arg.trim().is_empty());
    if args.first().is_some_and(|arg| arg == "ray") {
        args.remove(0);
    }
    if args.is_empty() {
        anyhow::bail!("enter a ray command");
    }
    let command = args
        .iter()
        .find(|arg| !arg.starts_with('-'))
        .map(String::as_str);
    if matches!(command, Some("gui" | "daemon")) {
        anyhow::bail!("the GUI cannot run `{}`", command.unwrap());
    }
    if json && !args.iter().any(|arg| arg == "--json") {
        args.insert(0, "--json".into());
    }
    Ok(args)
}

fn run_ray_command(exe: &std::path::Path, args: Vec<String>) -> Result<RunResponse> {
    let mut child = ProcessCommand::new(exe)
        .args(&args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("running ray {}", args.join(" ")))?;

    // ponytail: fixed timeout; add streaming/cancel controls if long-running commands need them.
    let deadline = Instant::now() + COMMAND_TIMEOUT;
    let (output, timed_out) = loop {
        if child.try_wait()?.is_some() {
            break (child.wait_with_output()?, false);
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            break (child.wait_with_output()?, true);
        }
        std::thread::sleep(Duration::from_millis(100));
    };

    let status = output
        .status
        .code()
        .unwrap_or(if timed_out { 124 } else { 1 });
    Ok(RunResponse {
        command: args,
        status,
        success: output.status.success() && !timed_out,
        stdout: clamp_output(String::from_utf8_lossy(&output.stdout).into_owned()),
        stderr: clamp_output(String::from_utf8_lossy(&output.stderr).into_owned()),
        timed_out,
    })
}

fn clamp_output(mut text: String) -> String {
    if text.len() > MAX_OUTPUT {
        text.truncate(MAX_OUTPUT);
        text.push_str("\n... output truncated ...\n");
    }
    text
}

struct HttpRequest {
    method: String,
    target: String,
    path: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl HttpRequest {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

fn read_http_request(stream: &mut TcpStream) -> Result<HttpRequest> {
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    let mut buf = Vec::new();
    let mut tmp = [0_u8; 8192];
    let header_end = loop {
        let n = stream.read(&mut tmp)?;
        if n == 0 {
            anyhow::bail!("empty request");
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(pos) = find_header_end(&buf) {
            break pos;
        }
        if buf.len() > MAX_BODY {
            anyhow::bail!("request headers too large");
        }
    };

    let header_text = String::from_utf8_lossy(&buf[..header_end]);
    let mut lines = header_text.lines();
    let first = lines.next().context("missing request line")?;
    let mut first_parts = first.split_whitespace();
    let method = first_parts.next().unwrap_or_default().to_string();
    let target = first_parts.next().unwrap_or_default().to_string();
    let path = target.split('?').next().unwrap_or("/").to_string();
    let headers = lines
        .filter_map(|line| {
            let (key, value) = line.split_once(':')?;
            Some((key.trim().to_string(), value.trim().to_string()))
        })
        .collect::<Vec<_>>();
    let content_len = headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, value)| value.parse::<usize>().ok())
        .unwrap_or(0);
    if content_len > MAX_BODY {
        anyhow::bail!("request body too large");
    }

    let body_start = header_end + 4;
    while buf.len() < body_start + content_len {
        let n = stream.read(&mut tmp)?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
    }
    let body = buf[body_start..buf.len().min(body_start + content_len)].to_vec();
    Ok(HttpRequest {
        method,
        target,
        path,
        headers,
        body,
    })
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

fn query_has_token(target: &str, token: &str) -> bool {
    target
        .split_once('?')
        .map(|(_, query)| {
            query
                .split('&')
                .any(|part| part.strip_prefix("token=") == Some(token))
        })
        .unwrap_or(false)
}

fn respond_text(stream: &mut TcpStream, status: u16, content_type: &str, body: &str) -> Result<()> {
    let reason = match status {
        200 => "OK",
        403 => "Forbidden",
        404 => "Not Found",
        _ => "Error",
    };
    write!(
        stream,
        "HTTP/1.1 {status} {reason}\r\n\
         Content-Type: {content_type}\r\n\
         Content-Length: {}\r\n\
         Cache-Control: no-store\r\n\
         X-Content-Type-Options: nosniff\r\n\
         Connection: close\r\n\
         \r\n\
         {body}",
        body.len()
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prepare_args_strips_binary_name_and_inserts_json() {
        let args = prepare_ray_args(vec!["ray".into(), "status".into()], true).unwrap();
        assert_eq!(args, ["--json", "status"]);
    }

    #[test]
    fn prepare_args_blocks_hidden_process_commands() {
        assert!(prepare_ray_args(vec!["daemon".into()], false).is_err());
        assert!(prepare_ray_args(vec!["--json".into(), "gui".into()], false).is_err());
    }

    #[test]
    fn token_query_must_match() {
        assert!(query_has_token("/?token=abc", "abc"));
        assert!(!query_has_token("/?token=abcd", "abc"));
        assert!(!query_has_token("/", "abc"));
    }
}
