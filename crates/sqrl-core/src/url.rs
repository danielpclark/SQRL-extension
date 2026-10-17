//! Parsing of `sqrl://` URLs.
//!
//! * The **site key** that all per-site keys are derived from is the lower-cased host name
//!   (user info and port stripped). When the URL carries an `x=N` parameter, the first `N`
//!   characters of the path (including the leading `/`) are appended.
//! * The **POST URL** is the same URL with the scheme replaced by `https` (`qrl://`, the
//!   legacy plain-http scheme, is only accepted for loopback hosts, for development).
//! * `can=` carries a base64url-encoded URL to send the browser to if the user cancels.

use crate::util::b64u_decode;
use crate::{Error, Result};

/// A parsed SQRL URL.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SqrlUrl {
    /// The URL exactly as received (this is what the first `server=` parameter carries).
    pub original: String,
    /// `sqrl` or `qrl` (lower-cased).
    pub scheme: String,
    /// `host[:port]` without user info, as it will be used for the POST URL.
    pub authority: String,
    /// Lower-cased host name.
    pub host: String,
    /// Explicit port, if any.
    pub port: Option<u16>,
    /// The path (starts with `/`; `/` if absent).
    pub path: String,
    /// The raw query string without the leading `?`.
    pub query: String,
    /// The `nut=` value.
    pub nut: Option<String>,
    /// Value of `x=` (path characters included in the site key).
    pub path_extension: usize,
    /// Decoded `can=` cancel URL (relative URLs are resolved against the site).
    pub cancel_url: Option<String>,
    /// Site key string used for key derivation.
    pub site_key: String,
}

impl SqrlUrl {
    /// Parse a `sqrl://` (or loopback-only `qrl://`) URL.
    pub fn parse(input: &str) -> Result<Self> {
        let original = input.trim().to_string();
        let (scheme, rest) = original
            .split_once("://")
            .ok_or_else(|| Error::Format("not a URL".into()))?;
        let scheme = scheme.to_ascii_lowercase();
        if scheme != "sqrl" && scheme != "qrl" {
            return Err(Error::Format(format!("unsupported scheme '{scheme}'")));
        }
        let rest = rest.split('#').next().unwrap_or("");
        let end_of_authority = rest.find(['/', '?']).unwrap_or(rest.len());
        let authority_raw = &rest[..end_of_authority];
        let path_and_query = &rest[end_of_authority..];
        let (path, query) = match path_and_query.split_once('?') {
            Some((p, q)) => (p.to_string(), q.to_string()),
            None => (path_and_query.to_string(), String::new()),
        };
        let path = if path.is_empty() { "/".to_string() } else { path };

        // strip user info
        let hostport = authority_raw.rsplit_once('@').map(|(_, h)| h).unwrap_or(authority_raw);
        let (host, port) = split_host_port(hostport)?;
        if host.is_empty() {
            return Err(Error::Format("missing host".into()));
        }
        let host = host.to_ascii_lowercase();
        if host.contains(|c: char| c.is_ascii_whitespace() || c == '/' || c == '\\') {
            return Err(Error::Format("invalid host".into()));
        }
        let authority = match port {
            Some(p) => format!("{host}:{p}"),
            None => host.clone(),
        };
        if scheme == "qrl" && !is_loopback(&host) {
            return Err(Error::Format("plain-http qrl:// URLs are only allowed for localhost".into()));
        }

        let mut nut = None;
        let mut path_extension = 0usize;
        let mut cancel_url = None;
        for (k, v) in query_pairs(&query) {
            match k.as_str() {
                "nut" => nut = Some(v),
                "x" => path_extension = v.parse::<usize>().map_err(|_| Error::Format("invalid x= parameter".into()))?,
                "can" => {
                    let bytes = b64u_decode(&v)?;
                    let s = String::from_utf8(bytes).map_err(|_| Error::Format("can= is not UTF-8".into()))?;
                    cancel_url = Some(s);
                }
                _ => {}
            }
        }

        let mut site_key = host.clone();
        if path_extension > 0 {
            let take = path_extension.min(path.len());
            // never cut in the middle of a multi-byte character
            let mut cut = take;
            while !path.is_char_boundary(cut) {
                cut -= 1;
            }
            site_key.push_str(&path[..cut]);
        }

        let mut url = Self {
            original,
            scheme,
            authority,
            host,
            port,
            path,
            query,
            nut,
            path_extension,
            cancel_url: None,
            site_key,
        };
        url.cancel_url = cancel_url.map(|c| url.resolve(&c));
        Ok(url)
    }

    /// `https` (or `http` for `qrl://`).
    pub fn http_scheme(&self) -> &'static str {
        if self.scheme == "qrl" {
            "http"
        } else {
            "https"
        }
    }

    /// `https://authority`
    pub fn origin(&self) -> String {
        format!("{}://{}", self.http_scheme(), self.authority)
    }

    /// The URL to POST the first (query) request to.
    pub fn post_url(&self) -> String {
        if self.query.is_empty() {
            format!("{}{}", self.origin(), self.path)
        } else {
            format!("{}{}?{}", self.origin(), self.path, self.query)
        }
    }

    /// The URL to POST a follow-up request to, from the server's `qry=` value.
    ///
    /// `qry` must be a path on the same host (it starts with `/`); absolute URLs pointing
    /// elsewhere are rejected to stop a compromised response redirecting signatures.
    pub fn post_url_for_qry(&self, qry: &str) -> Result<String> {
        let qry = qry.trim();
        if !qry.starts_with('/') || qry.starts_with("//") {
            return Err(Error::Protocol(format!("qry must be a server-relative path, got '{qry}'")));
        }
        Ok(format!("{}{}", self.origin(), qry))
    }

    /// Site key bytes, optionally extended with an "Alt-ID" (`site_key || 0x00 || alt_id`).
    pub fn site_key_bytes(&self, alt_id: Option<&str>) -> Vec<u8> {
        let mut v = self.site_key.as_bytes().to_vec();
        if let Some(alt) = alt_id {
            let alt = alt.trim();
            if !alt.is_empty() {
                v.push(0);
                v.extend_from_slice(alt.as_bytes());
            }
        }
        v
    }

    /// Resolve a possibly-relative URL (from `can=` or `url=`) against this site.
    pub fn resolve(&self, target: &str) -> String {
        let t = target.trim();
        if t.starts_with("https://") || t.starts_with("http://") {
            t.to_string()
        } else if t.starts_with('/') {
            format!("{}{}", self.origin(), t)
        } else {
            format!("{}/{}", self.origin(), t)
        }
    }

    /// Whether an absolute URL (e.g. the CPS `url=`) points at this site's host.
    pub fn is_same_host(&self, target: &str) -> bool {
        let t = target.trim();
        let rest = match t.split_once("://") {
            Some((s, r)) if s.eq_ignore_ascii_case("https") || s.eq_ignore_ascii_case("http") => r,
            _ => return false,
        };
        let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        let hostport = rest[..end].rsplit_once('@').map(|(_, h)| h).unwrap_or(&rest[..end]);
        match split_host_port(hostport) {
            Ok((h, _)) => h.eq_ignore_ascii_case(&self.host),
            Err(_) => false,
        }
    }
}

fn is_loopback(host: &str) -> bool {
    host == "localhost" || host == "127.0.0.1" || host == "[::1]" || host.ends_with(".localhost")
}

fn split_host_port(hostport: &str) -> Result<(String, Option<u16>)> {
    if let Some(rest) = hostport.strip_prefix('[') {
        // IPv6 literal
        let close = rest.find(']').ok_or_else(|| Error::Format("unterminated IPv6 literal".into()))?;
        let host = format!("[{}]", &rest[..close]);
        let after = &rest[close + 1..];
        if after.is_empty() {
            return Ok((host, None));
        }
        let port = after
            .strip_prefix(':')
            .and_then(|p| p.parse::<u16>().ok())
            .ok_or_else(|| Error::Format("invalid port".into()))?;
        return Ok((host, Some(port)));
    }
    match hostport.rsplit_once(':') {
        Some((h, p)) => {
            let port = p.parse::<u16>().map_err(|_| Error::Format("invalid port".into()))?;
            Ok((h.to_string(), Some(port)))
        }
        None => Ok((hostport.to_string(), None)),
    }
}

/// Split a query string into (key, value) pairs. Values are percent-decoded only for the
/// characters SQRL servers may legitimately escape; the `nut` is otherwise used verbatim.
pub fn query_pairs(query: &str) -> Vec<(String, String)> {
    query
        .split('&')
        .filter(|s| !s.is_empty())
        .map(|kv| match kv.split_once('=') {
            Some((k, v)) => (k.to_string(), percent_decode(v)),
            None => (kv.to_string(), String::new()),
        })
        .collect()
}

fn percent_decode(s: &str) -> String {
    if !s.contains('%') {
        return s.to_string();
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(h) = core::str::from_utf8(&bytes[i + 1..(i + 3).min(bytes.len())]) {
                if h.len() == 2 {
                    if let Ok(b) = u8::from_str_radix(h, 16) {
                        out.push(b);
                        i += 3;
                        continue;
                    }
                }
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::b64u_encode;

    #[test]
    fn basic_parse() {
        let u = SqrlUrl::parse("sqrl://WWW.Example.com/cli.sqrl?nut=abc123").unwrap();
        assert_eq!(u.host, "www.example.com");
        assert_eq!(u.site_key, "www.example.com");
        assert_eq!(u.nut.as_deref(), Some("abc123"));
        assert_eq!(u.post_url(), "https://www.example.com/cli.sqrl?nut=abc123");
        assert_eq!(u.post_url_for_qry("/cli.sqrl?nut=def").unwrap(), "https://www.example.com/cli.sqrl?nut=def");
        assert!(u.post_url_for_qry("https://evil.example/cli").is_err());
        assert!(u.post_url_for_qry("//evil.example/cli").is_err());
    }

    #[test]
    fn path_extension_and_port_and_userinfo() {
        let u = SqrlUrl::parse("sqrl://user:pw@Example.com:8443/jimbo/cli.sqrl?x=6&nut=1").unwrap();
        assert_eq!(u.authority, "example.com:8443");
        assert_eq!(u.port, Some(8443));
        assert_eq!(u.site_key, "example.com/jimbo");
        assert_eq!(u.post_url(), "https://example.com:8443/jimbo/cli.sqrl?x=6&nut=1");
        // x larger than the path just takes the whole path
        let u = SqrlUrl::parse("sqrl://example.com/ab?x=99&nut=1").unwrap();
        assert_eq!(u.site_key, "example.com/ab");
        // GRC's own example
        let u = SqrlUrl::parse("sqrl://www.grc.com/sqrl?x=5&nut=Na2MOglf7NyyupQ8-dtj1g").unwrap();
        assert_eq!(u.site_key, "www.grc.com/sqrl");
    }

    #[test]
    fn cancel_url() {
        let can = b64u_encode(b"https://example.com/cancelled");
        let u = SqrlUrl::parse(&format!("sqrl://example.com/cli.sqrl?nut=1&can={can}")).unwrap();
        assert_eq!(u.cancel_url.as_deref(), Some("https://example.com/cancelled"));
        let can = b64u_encode(b"/login?cancel=1");
        let u = SqrlUrl::parse(&format!("sqrl://example.com/cli.sqrl?nut=1&can={can}")).unwrap();
        assert_eq!(u.cancel_url.as_deref(), Some("https://example.com/login?cancel=1"));
    }

    #[test]
    fn qrl_only_for_loopback() {
        let u = SqrlUrl::parse("qrl://localhost:8080/cli.sqrl?nut=1").unwrap();
        assert_eq!(u.post_url(), "http://localhost:8080/cli.sqrl?nut=1");
        assert!(SqrlUrl::parse("qrl://example.com/cli.sqrl?nut=1").is_err());
        assert!(SqrlUrl::parse("https://example.com/cli.sqrl?nut=1").is_err());
        assert!(SqrlUrl::parse("sqrl:///cli.sqrl").is_err());
    }

    #[test]
    fn alt_id_and_same_host() {
        let u = SqrlUrl::parse("sqrl://example.com/cli.sqrl?nut=1").unwrap();
        assert_eq!(u.site_key_bytes(None), b"example.com");
        assert_eq!(u.site_key_bytes(Some("work")), b"example.com\0work");
        assert!(u.is_same_host("https://EXAMPLE.com/loggedin?x=1"));
        assert!(u.is_same_host("https://example.com:8443/"));
        assert!(!u.is_same_host("https://example.org/"));
        assert!(!u.is_same_host("javascript:alert(1)"));
        assert_eq!(u.resolve("/x"), "https://example.com/x");
    }

    #[test]
    fn ipv6_authority() {
        let u = SqrlUrl::parse("sqrl://[2001:db8::1]:444/cli.sqrl?nut=1").unwrap();
        assert_eq!(u.host, "[2001:db8::1]");
        assert_eq!(u.port, Some(444));
        assert_eq!(u.site_key, "[2001:db8::1]");
    }
}
