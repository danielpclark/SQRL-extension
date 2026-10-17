//! A tiny plain-HTTP SQRL server for exercising the extension locally.
//!
//! ```text
//! cargo run -p sqrl-test-server -- 127.0.0.1:8080
//! ```
//!
//! Then open <http://localhost:8080/> in a browser with the extension installed. The page
//! shows a `qrl://localhost:8080/cli.sqrl?nut=...` link (plain http is allowed for localhost
//! only) and performs the standard CPS probe against `localhost:25519`, exactly like a real
//! site. `/cli.sqrl` is the SQRL endpoint, `/loggedin?session=` the CPS landing page and
//! `/status?session=` a JSON poll endpoint the page uses for non-CPS logins.

use sqrl_core::server::ReferenceServer;
use sqrl_core::url::query_pairs;
use sqrl_core::util::b64u_encode;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};

fn main() {
    let addr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:8080".to_string());
    let host = std::env::args().nth(2).unwrap_or_else(|| {
        let port = addr.rsplit(':').next().unwrap_or("8080");
        format!("localhost:{port}")
    });
    let mut server = ReferenceServer::new(&host, "/cli.sqrl");
    server.scheme = "qrl".into();
    server.cps_url_prefix = format!("http://{host}/loggedin?session=");
    server.ignore_ip = true;
    if std::env::var("SQRL_ASK").is_ok() {
        server.ask = Some(sqrl_core::protocol::Ask {
            message: "Allow this login from the test server?".into(),
            buttons: vec![
                sqrl_core::protocol::AskButton {
                    label: "Allow".into(),
                    url: None,
                },
                sqrl_core::protocol::AskButton {
                    label: "Deny".into(),
                    url: None,
                },
            ],
        });
    }
    if std::env::var("SQRL_SIN").is_ok() {
        server.sin = Some("0".into());
    }
    let state = Arc::new(Mutex::new(server));
    let listener = TcpListener::bind(&addr).expect("bind");
    eprintln!("SQRL test server listening on http://{addr}/ (SQRL host {host})");
    for stream in listener.incoming().flatten() {
        let state = state.clone();
        std::thread::spawn(move || handle(stream, state));
    }
}

fn handle(mut stream: TcpStream, state: Arc<Mutex<ReferenceServer>>) {
    let peer = stream
        .peer_addr()
        .map(|a| a.ip().to_string())
        .unwrap_or_default();
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut request_line = String::new();
    if reader.read_line(&mut request_line).is_err() || request_line.is_empty() {
        return;
    }
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let target = parts.next().unwrap_or("/").to_string();
    let mut content_length = 0usize;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).is_err() || line == "\r\n" || line == "\n" || line.is_empty()
        {
            break;
        }
        if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
            content_length = v.trim().parse().unwrap_or(0);
        }
    }
    let mut body = vec![0u8; content_length];
    if content_length > 0 {
        let _ = reader.read_exact(&mut body);
    }
    let body = String::from_utf8_lossy(&body).to_string();
    let (path, query) = target
        .split_once('?')
        .map(|(p, q)| (p.to_string(), q.to_string()))
        .unwrap_or((target.clone(), String::new()));
    let params = query_pairs(&query);
    let param = |k: &str| params.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone());

    let (status, ctype, out) = match (method.as_str(), path.as_str()) {
        ("GET", "/") => {
            let mut s = state.lock().unwrap();
            let (session, url) = s.new_login_url(&peer, Some("/?cancelled=1"));
            ("200 OK", "text/html; charset=utf-8", page(&session, &url))
        }
        ("POST", "/cli.sqrl") => {
            let nut = param("nut").unwrap_or_default();
            let mut s = state.lock().unwrap();
            let resp = s.handle(&nut, &body, &peer);
            eprintln!(
                "[cli] nut={nut} -> {}",
                String::from_utf8_lossy(&sqrl_core::util::b64u_decode(&resp).unwrap_or_default())
                    .replace("\r\n", " | ")
            );
            ("200 OK", "text/plain", resp)
        }
        ("GET", "/status") => {
            let session = param("session").unwrap_or_default();
            let s = state.lock().unwrap();
            let auth = s
                .session(&session)
                .and_then(|b| b.authenticated)
                .map(|k| b64u_encode(&k));
            (
                "200 OK",
                "application/json",
                format!(
                    "{{\"authenticated\":{}}}",
                    auth.map(|a| format!("\"{a}\"")).unwrap_or("null".into())
                ),
            )
        }
        ("GET", "/loggedin") => {
            let session = param("session").unwrap_or_default();
            let s = state.lock().unwrap();
            match s.session(&session).and_then(|b| b.authenticated) {
                Some(k) => ("200 OK", "text/html; charset=utf-8", format!("<!doctype html><h1>Logged in</h1><p>Identity: <code>{}</code></p><p><a href=\"/\">Back</a></p>", b64u_encode(&k))),
                None => ("403 Forbidden", "text/html; charset=utf-8", "<!doctype html><h1>Not logged in</h1><p><a href=\"/\">Back</a></p>".to_string()),
            }
        }
        _ => ("404 Not Found", "text/plain", "not found".to_string()),
    };
    let _ = write!(
        stream,
        "HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n{out}",
        out.len()
    );
    let _ = stream.flush();
}

fn page(session: &str, url: &str) -> String {
    let b64 = b64u_encode(url.as_bytes());
    format!(
        r##"<!doctype html>
<html><head><meta charset="utf-8"><title>SQRL test site</title>
<style>body{{font-family:system-ui,sans-serif;max-width:40em;margin:3em auto;line-height:1.5}}a.btn{{display:inline-block;padding:.6em 1.2em;background:#2a6;color:#fff;border-radius:.4em;text-decoration:none}}code{{word-break:break-all}}</style>
</head><body>
<h1>SQRL test site</h1>
<p>This page behaves like a real SQRL-enabled login page. Click the button to sign in with the browser extension.</p>
<p><a class="btn" id="sqrl" href="{url}">Sign in with SQRL</a></p>
<p>SQRL URL: <code>{url}</code></p>
<p id="status">Waiting for login… (polling)</p>
<p id="probe">Probing for a local SQRL client at localhost:25519…</p>
<script>
// Standard same-device (CPS) probe: if a client answers on localhost:25519 the link is
// pointed there so the client can redirect the browser straight into the logged-in session.
var img = new Image();
img.onload = function() {{
  document.getElementById('probe').textContent = 'Local SQRL client detected: using CPS.';
  document.getElementById('sqrl').href = 'http://localhost:25519/' + '{b64}';
}};
img.onerror = function() {{ document.getElementById('probe').textContent = 'No local client answered the probe; using the sqrl:// link.'; }};
img.src = 'http://localhost:25519/' + Math.random().toString(36).slice(2) + '.gif';
// Poll for non-CPS logins (e.g. from a phone).
setInterval(function() {{
  fetch('/status?session={session}').then(r => r.json()).then(j => {{
    if (j.authenticated) {{ location.href = '/loggedin?session={session}'; }}
  }});
}}, 2000);
</script>
</body></html>"##
    )
}
