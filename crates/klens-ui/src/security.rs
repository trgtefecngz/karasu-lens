//! Centralized security gate (`security_guard`) and UTF-8-safe URL/query decoding.
//!
//! Security guarantees (evaluated BEFORE every route handler):
//! 1. Strict `Host` header validation (`127.0.0.1:<port>` or `localhost:<port>`) — blocks DNS rebinding.
//! 2. Random session token with 256 bits of OS entropy (`generate_session_token`) handed off via
//!    `GET /?token=<t>` into an `HttpOnly; SameSite=Strict; Path=/` cookie with immediate URL stripping.
//! 3. Triple CSRF gate on every mutating request (`POST`/`PUT`/`DELETE`, including `/api/shutdown`):
//!    - Valid `Origin` header (`http://127.0.0.1:<port>` or `http://localhost:<port>`)
//!    - Valid `klens_session` cookie (constant-time equality)
//!    - Custom header `X-Klens-Request: 1`

use std::collections::BTreeMap;
use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use tiny_http::{Method, Request};

use crate::error::UiError;

/// Session cookie name set via `HttpOnly; SameSite=Strict; Path=/`.
pub const SESSION_COOKIE_NAME: &str = "klens_session";

/// Custom header required on all mutating (`POST`/`PUT`/`DELETE`) API requests.
pub const CUSTOM_REQUEST_HEADER: &str = "X-Klens-Request";

/// Expected value of [`CUSTOM_REQUEST_HEADER`].
pub const CUSTOM_REQUEST_HEADER_VALUE: &str = "1";

static TOKEN_SEQ: AtomicU64 = AtomicU64::new(0);

/// Decision returned by [`security_guard`] before routing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuardOutcome {
    /// Request passed all applicable security checks and may proceed to routing.
    Allow { authenticated: bool },
    /// `GET /?token=<valid>` matched: set `HttpOnly; SameSite=Strict; Path=/` cookie
    /// and redirect to `/` to strip the token from the address bar.
    SetSessionCookieAndRedirect,
}

/// Generate a 64-hex-char (BLAKE3-256) random session token without external RNG crates or
/// `unsafe` code.
///
/// Entropy: std seeds `RandomState` keys from the OS CSPRNG (`ProcessPrng` on Windows,
/// `getrandom` on Unix) once per thread — 128 bits; later instances on the same thread only
/// increment a counter. Keys are therefore taken from two threads (256 bits of OS entropy),
/// plus 32 `/dev/urandom` bytes on Unix, clocks, PID and a counter, all mixed through BLAKE3.
pub fn generate_session_token() -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"klens-ui-session-token-v1");

    hasher.update(&random_state_entropy());
    let other_thread = std::thread::spawn(random_state_entropy)
        .join()
        .unwrap_or_default();
    hasher.update(&other_thread);

    // Mix direct OS `/dev/urandom` bytes on Unix platforms when accessible.
    #[cfg(unix)]
    {
        use std::io::Read;
        if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
            let mut buf = [0u8; 32];
            if f.read_exact(&mut buf).is_ok() {
                hasher.update(&buf);
            }
        }
    }

    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0u128, |d| d.as_nanos());
    hasher.update(&nanos.to_le_bytes());
    hasher.update(&std::process::id().to_le_bytes());
    let seq = TOKEN_SEQ.fetch_add(1, Ordering::Relaxed);
    hasher.update(&seq.to_le_bytes());

    let instant_bits = Instant::now().elapsed().as_nanos();
    hasher.update(&instant_bits.to_le_bytes());

    hasher.finalize().to_hex().to_string()
}

/// Two hashes from a `RandomState` built on the calling thread. The thread's OS-seeded
/// 128-bit keys determine both outputs, so together they carry those 128 bits.
fn random_state_entropy() -> [u8; 16] {
    let state = RandomState::new();
    let hash = |round: u64| {
        let mut h = state.build_hasher();
        h.write_u64(round);
        h.finish().to_le_bytes()
    };
    let mut out = [0u8; 16];
    out[..8].copy_from_slice(&hash(0));
    out[8..].copy_from_slice(&hash(1));
    out
}

/// Constant-time equality comparison for secret tokens to prevent timing side channels.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (&x, &y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Validate `Host` header strictly against `127.0.0.1:<port>` or `localhost:<port>`.
pub fn is_allowed_host(host: &str, port: u16) -> bool {
    let trimmed = host.trim();
    let expected_ip = format!("127.0.0.1:{port}");
    let expected_local = format!("localhost:{port}");
    trimmed.eq_ignore_ascii_case(&expected_ip) || trimmed.eq_ignore_ascii_case(&expected_local)
}

/// Validate `Origin` header strictly against `http://127.0.0.1:<port>` or `http://localhost:<port>`.
pub fn is_allowed_origin(origin: &str, port: u16) -> bool {
    let trimmed = origin.trim();
    let expected_ip = format!("http://127.0.0.1:{port}");
    let expected_local = format!("http://localhost:{port}");
    trimmed.eq_ignore_ascii_case(&expected_ip) || trimmed.eq_ignore_ascii_case(&expected_local)
}

/// Extract a named cookie value from a raw `Cookie` header string.
pub fn extract_cookie<'a>(cookie_header: &'a str, name: &str) -> Option<&'a str> {
    for part in cookie_header.split(';') {
        let trimmed = part.trim();
        if let Some((k, v)) = trimmed.split_once('=')
            && k.trim() == name
        {
            return Some(v.trim());
        }
    }
    None
}

/// Look up the first matching HTTP header (case-insensitive ASCII).
pub fn header_value<'a>(request: &'a Request, name: &str) -> Option<&'a str> {
    request
        .headers()
        .iter()
        .find(|h| h.field.as_str().as_str().eq_ignore_ascii_case(name))
        .map(|h| h.value.as_str())
}

/// Central security gate executed BEFORE every route dispatch.
pub fn security_guard(
    request: &Request,
    port: u16,
    expected_token: &str,
) -> Result<GuardOutcome, UiError> {
    // Gate 1: Strict `Host` header check (DNS rebinding defense).
    let host = header_value(request, "Host").ok_or_else(|| {
        UiError::Forbidden("missing Host header (DNS rebinding guard)".to_string())
    })?;
    if !is_allowed_host(host, port) {
        return Err(UiError::Forbidden(format!(
            "forbidden Host header `{host}` (expected 127.0.0.1:{port} or localhost:{port})"
        )));
    }

    let method = request.method();
    let (raw_path, raw_query) = split_url_path_query(request.url());

    // Reject unsupported HTTP verbs early.
    if !matches!(
        method,
        Method::Get | Method::Head | Method::Post | Method::Put | Method::Delete
    ) {
        return Err(UiError::MethodNotAllowed(format!(
            "HTTP method `{method}` is not supported"
        )));
    }

    // Gate 2: Token bootstrap on `GET /?token=<t>` (or `/index.html?token=<t>`).
    if matches!(method, Method::Get)
        && (raw_path == "/" || raw_path == "/index.html")
        && let Some(query_str) = raw_query
    {
        let params = parse_query_params(query_str)?;
        if let Some(provided) = params.get("token") {
            if constant_time_eq(provided.as_bytes(), expected_token.as_bytes()) {
                return Ok(GuardOutcome::SetSessionCookieAndRedirect);
            }
            return Err(UiError::Unauthorized(
                "invalid session bootstrap token".to_string(),
            ));
        }
    }

    // Check session cookie in constant time.
    let authenticated = header_value(request, "Cookie")
        .and_then(|c| extract_cookie(c, SESSION_COOKIE_NAME))
        .is_some_and(|val| constant_time_eq(val.as_bytes(), expected_token.as_bytes()));

    // Gate 3: Triple CSRF gate on ALL mutating requests (POST / PUT / DELETE, including /api/shutdown).
    if matches!(method, Method::Post | Method::Put | Method::Delete) {
        // 3a. Strict `Origin` header check.
        let origin = header_value(request, "Origin").ok_or_else(|| {
            UiError::Forbidden("missing Origin header on mutating request".to_string())
        })?;
        if !is_allowed_origin(origin, port) {
            return Err(UiError::Forbidden(format!(
                "forbidden Origin header `{origin}`"
            )));
        }

        // 3b. Custom `X-Klens-Request: 1` header check.
        let custom_hdr = header_value(request, CUSTOM_REQUEST_HEADER).ok_or_else(|| {
            UiError::Forbidden(format!(
                "missing `{CUSTOM_REQUEST_HEADER}: {CUSTOM_REQUEST_HEADER_VALUE}` header"
            ))
        })?;
        if custom_hdr.trim() != CUSTOM_REQUEST_HEADER_VALUE {
            return Err(UiError::Forbidden(format!(
                "invalid `{CUSTOM_REQUEST_HEADER}` header value"
            )));
        }

        // 3c. Valid `HttpOnly; SameSite=Strict` session cookie check.
        if !authenticated {
            return Err(UiError::Unauthorized(
                "missing or invalid session cookie".to_string(),
            ));
        }

        return Ok(GuardOutcome::Allow {
            authenticated: true,
        });
    }

    // Gate 4: All `/api/*` read endpoints require a valid session cookie.
    if raw_path.starts_with("/api/") && !authenticated {
        return Err(UiError::Unauthorized(
            "session cookie required for API access (open the tokenized URL from terminal)"
                .to_string(),
        ));
    }

    Ok(GuardOutcome::Allow { authenticated })
}

/// Format the `Set-Cookie` header value for the session cookie.
pub fn session_cookie_header_value(token: &str) -> String {
    format!("{SESSION_COOKIE_NAME}={token}; HttpOnly; SameSite=Strict; Path=/")
}

/// Split a request URL target into `(path, Option<query>)`.
pub fn split_url_path_query(url: &str) -> (&str, Option<&str>) {
    match url.split_once('?') {
        Some((path, query)) => (path, Some(query)),
        None => (url, None),
    }
}

/// UTF-8-safe percent-decoding (RFC 3986 / `application/x-www-form-urlencoded` with `+` → space
/// when `plus_as_space == true`). Fails closed with `400 Bad Request` on malformed `%XX` escapes
/// or invalid UTF-8 byte sequences.
pub fn percent_decode_utf8(input: &str, plus_as_space: bool) -> Result<String, UiError> {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;

    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                if i + 2 >= bytes.len() {
                    return Err(UiError::BadRequest(format!(
                        "truncated percent-encoding sequence in `{input}`"
                    )));
                }
                let hi = decode_hex_nibble(bytes[i + 1]).ok_or_else(|| {
                    UiError::BadRequest(format!("invalid hex escape in `{input}`"))
                })?;
                let lo = decode_hex_nibble(bytes[i + 2]).ok_or_else(|| {
                    UiError::BadRequest(format!("invalid hex escape in `{input}`"))
                })?;
                out.push((hi << 4) | lo);
                i += 3;
            }
            b'+' if plus_as_space => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }

    String::from_utf8(out)
        .map_err(|_| UiError::BadRequest("percent-decoded URL parameter is not valid UTF-8".into()))
}

fn decode_hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Parse URL query string into a deterministic map using UTF-8-safe percent decoding.
/// Fails closed if any key/value contains malformed `%XX` or invalid UTF-8.
pub fn parse_query_params(query: &str) -> Result<BTreeMap<String, String>, UiError> {
    let mut map = BTreeMap::new();
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (raw_k, raw_v) = match pair.split_once('=') {
            Some((k, v)) => (k, v),
            None => (pair, ""),
        };
        let key = percent_decode_utf8(raw_k, true)?;
        let value = percent_decode_utf8(raw_v, true)?;
        map.insert(key, value);
    }
    Ok(map)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_token_is_64_hex_chars_and_unique() {
        let t1 = generate_session_token();
        let t2 = generate_session_token();
        assert_eq!(t1.len(), 64);
        assert!(t1.bytes().all(|b| b.is_ascii_hexdigit()));
        assert_ne!(t1, t2);
        assert!(constant_time_eq(t1.as_bytes(), t1.as_bytes()));
        assert!(!constant_time_eq(t1.as_bytes(), t2.as_bytes()));
    }

    #[test]
    fn host_and_origin_validation_blocks_rebinding_and_foreign_origins() {
        assert!(is_allowed_host("127.0.0.1:4729", 4729));
        assert!(is_allowed_host("localhost:4729", 4729));
        assert!(is_allowed_host("LOCALHOST:4729", 4729));
        assert!(!is_allowed_host("evil.com", 4729));
        assert!(!is_allowed_host("evil.com:4729", 4729));
        assert!(!is_allowed_host("127.0.0.1:4730", 4729));
        assert!(!is_allowed_host("127.0.0.1.evil.com:4729", 4729));

        assert!(is_allowed_origin("http://127.0.0.1:4729", 4729));
        assert!(is_allowed_origin("http://localhost:4729", 4729));
        assert!(!is_allowed_origin("https://evil.example", 4729));
        assert!(!is_allowed_origin("http://127.0.0.1:9999", 4729));
        assert!(!is_allowed_origin("null", 4729));
    }

    #[test]
    fn utf8_percent_decode_handles_turkish_and_rejects_malformed() {
        // "Projeler/Çalışma_ğüşiöç" percent-encoded in UTF-8
        let encoded = "C%3A%5CProjeler%5C%C3%87al%C4%B1%C5%9Fma_%C4%9F%C3%BC%C5%9Fi%C3%B6%C3%A7";
        let decoded = percent_decode_utf8(encoded, true).unwrap();
        assert_eq!(decoded, "C:\\Projeler\\Çalışma_ğüşiöç");

        // Malformed escapes fail closed.
        assert!(percent_decode_utf8("abc%2", true).is_err());
        assert!(percent_decode_utf8("abc%ZZ", true).is_err());
        // Invalid UTF-8 byte sequence fails closed.
        assert!(percent_decode_utf8("%FF%FE", true).is_err());
    }
}
