use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Category of detected secret material redacted at the output gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SecretKind {
    PrivateKey,
    AnthropicKey,
    OpenAiKey,
    GitHubToken,
    AwsAccessKey,
    AwsSecretKey,
    GoogleApiKey,
    BearerToken,
    Jwt,
    SlackToken,
    StripeKey,
    NpmToken,
    GitLabToken,
    DatabasePassword,
}

impl SecretKind {
    /// Deterministic replacement placeholder token.
    pub const fn placeholder(self) -> &'static str {
        match self {
            Self::PrivateKey => "[REDACTED:PRIVATE_KEY]",
            Self::AnthropicKey => "[REDACTED:ANTHROPIC_KEY]",
            Self::OpenAiKey => "[REDACTED:OPENAI_KEY]",
            Self::GitHubToken => "[REDACTED:GITHUB_TOKEN]",
            Self::AwsAccessKey => "[REDACTED:AWS_ACCESS_KEY]",
            Self::AwsSecretKey => "[REDACTED:AWS_SECRET_KEY]",
            Self::GoogleApiKey => "[REDACTED:GOOGLE_API_KEY]",
            Self::BearerToken => "[REDACTED:BEARER_TOKEN]",
            Self::Jwt => "[REDACTED:JWT]",
            Self::SlackToken => "[REDACTED:SLACK_TOKEN]",
            Self::StripeKey => "[REDACTED:STRIPE_KEY]",
            Self::NpmToken => "[REDACTED:NPM_TOKEN]",
            Self::GitLabToken => "[REDACTED:GITLAB_TOKEN]",
            Self::DatabasePassword => "[REDACTED:DATABASE_PASSWORD]",
        }
    }
}

/// Output of secret redaction with exact counts per secret category.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedactionResult {
    pub text: String,
    pub redactions_count: usize,
    pub by_kind: BTreeMap<SecretKind, usize>,
}

/// Scan `input` and replace known secret patterns with `[REDACTED:<KIND>]`.
///
/// Runs in linear time without backtracking and preserves normal source code
/// without false positives.
pub fn redact_secrets(input: &str) -> RedactionResult {
    let bytes = input.as_bytes();
    let len = bytes.len();
    let mut out = String::with_capacity(len);
    let mut by_kind: BTreeMap<SecretKind, usize> = BTreeMap::new();
    let mut redactions_count = 0usize;

    let mut i = 0usize;
    while i < len {
        let prev = if i == 0 { None } else { Some(bytes[i - 1]) };

        // 1. PEM Private Key block (multi-line).
        if let Some(end) = match_private_key_block(input, i) {
            record_redaction(
                &mut out,
                &mut by_kind,
                &mut redactions_count,
                SecretKind::PrivateKey,
            );
            i = end;
            continue;
        }

        // 2. AWS_SECRET_ACCESS_KEY & ANTHROPIC_API_KEY assignments (keep key + separator, redact value).
        if is_token_boundary(prev)
            && let Some((val_start, val_end)) = match_aws_secret_assignment(input, i)
        {
            out.push_str(&input[i..val_start]);
            record_redaction(
                &mut out,
                &mut by_kind,
                &mut redactions_count,
                SecretKind::AwsSecretKey,
            );
            i = val_end;
            continue;
        }
        if is_token_boundary(prev)
            && let Some((val_start, val_end)) = match_anthropic_env_assignment(input, i)
        {
            out.push_str(&input[i..val_start]);
            record_redaction(
                &mut out,
                &mut by_kind,
                &mut redactions_count,
                SecretKind::AnthropicKey,
            );
            i = val_end;
            continue;
        }

        // 3. Bearer <token> header (keeps `Bearer `, redacts token).
        if is_token_boundary(prev)
            && let Some((tok_start, tok_end)) = match_bearer_token(input, i)
        {
            out.push_str(&input[i..tok_start]);
            record_redaction(
                &mut out,
                &mut by_kind,
                &mut redactions_count,
                SecretKind::BearerToken,
            );
            i = tok_end;
            continue;
        }

        // 3b. Database connection URL password (keeps scheme, user and host).
        if is_token_boundary(prev)
            && let Some((pw_start, pw_end)) = match_database_url_secret(input, i)
        {
            out.push_str(&input[i..pw_start]);
            record_redaction(
                &mut out,
                &mut by_kind,
                &mut redactions_count,
                SecretKind::DatabasePassword,
            );
            i = pw_end;
            continue;
        }

        // 4. Token-boundary prefixed secrets.
        if is_token_boundary(prev)
            && let Some((kind, end)) = match_prefixed_secret(input, i)
        {
            record_redaction(&mut out, &mut by_kind, &mut redactions_count, kind);
            i = end;
            continue;
        }

        // Advance one UTF-8 character safely.
        let ch = input[i..].chars().next().unwrap();
        out.push(ch);
        i += ch.len_utf8();
    }

    RedactionResult {
        text: out,
        redactions_count,
        by_kind,
    }
}

fn record_redaction(
    out: &mut String,
    by_kind: &mut BTreeMap<SecretKind, usize>,
    total: &mut usize,
    kind: SecretKind,
) {
    out.push_str(kind.placeholder());
    *total += 1;
    *by_kind.entry(kind).or_insert(0) += 1;
}

fn is_token_boundary(prev: Option<u8>) -> bool {
    match prev {
        None => true,
        Some(b) => !(b.is_ascii_alphanumeric() || b == b'_'),
    }
}

fn match_private_key_block(input: &str, start: usize) -> Option<usize> {
    let rest = &input[start..];
    if !rest.starts_with("-----BEGIN ") {
        return None;
    }

    let header_end = rest
        .find("-----")
        .map(|_| rest.find('\n').unwrap_or(rest.len()))?;
    let header_line = &rest[..header_end];
    if !header_line.contains("PRIVATE KEY-----") {
        return None;
    }

    // Look for the matching END marker; if truncated inside a private key block, redact to EOF.
    let search_from = header_end;
    if let Some(rel_end_start) = rest[search_from..].find("-----END ") {
        let abs_end_start = search_from + rel_end_start;
        let tail = &rest[abs_end_start..];
        if let Some(marker_end) = tail.find("PRIVATE KEY-----") {
            return Some(start + abs_end_start + marker_end + "PRIVATE KEY-----".len());
        }
    }

    Some(input.len())
}

fn match_prefixed_secret(input: &str, start: usize) -> Option<(SecretKind, usize)> {
    let rest = &input[start..];

    // Anthropic API key: `sk-ant-...`
    if let Some(after) = rest.strip_prefix("sk-ant-") {
        let n = take_while_bytes(after, |b| {
            b.is_ascii_alphanumeric() || b == b'_' || b == b'-'
        });
        if n >= 20 {
            return Some((SecretKind::AnthropicKey, start + "sk-ant-".len() + n));
        }
    }

    // OpenAI API key: `sk-proj-...`, `sk-svcacct-...`, `sk-live-...`, `sk-test-...`, or `sk-<20+>`
    if let Some(after) = rest.strip_prefix("sk-") {
        let explicit_sub = ["proj-", "svcacct-", "live-", "test-"]
            .iter()
            .find_map(|p| after.strip_prefix(p).map(|tail| (p.len(), tail)));
        if let Some((sub_len, tail)) = explicit_sub {
            let n = take_while_bytes(tail, |b| {
                b.is_ascii_alphanumeric() || b == b'_' || b == b'-'
            });
            if n >= 20 {
                return Some((SecretKind::OpenAiKey, start + "sk-".len() + sub_len + n));
            }
        } else {
            let n = take_while_bytes(after, |b| {
                b.is_ascii_alphanumeric() || b == b'_' || b == b'-'
            });
            if n >= 20 {
                let body = &after[..n];
                let alnum_count = body.bytes().filter(u8::is_ascii_alphanumeric).count();
                let has_digit = body.bytes().any(|b| b.is_ascii_digit());
                let has_upper = body.bytes().any(|b| b.is_ascii_uppercase());
                let has_lower = body.bytes().any(|b| b.is_ascii_lowercase());
                if alnum_count >= 20 && (has_digit || (has_upper && has_lower)) {
                    return Some((SecretKind::OpenAiKey, start + "sk-".len() + n));
                }
            }
        }
    }

    // GitHub classic & fine-grained tokens.
    for prefix in ["ghp_", "gho_", "ghu_", "ghs_", "ghr_"] {
        if let Some(after) = rest.strip_prefix(prefix) {
            let n = take_while_bytes(after, |b| b.is_ascii_alphanumeric());
            if n >= 20 {
                return Some((SecretKind::GitHubToken, start + prefix.len() + n));
            }
        }
    }
    if let Some(after) = rest.strip_prefix("github_pat_") {
        let n = take_while_bytes(after, |b| b.is_ascii_alphanumeric() || b == b'_');
        if n >= 20 {
            return Some((SecretKind::GitHubToken, start + "github_pat_".len() + n));
        }
    }

    // AWS Access Key ID: `AKIA` or `ASIA` + 16 uppercase alphanumerics.
    for prefix in ["AKIA", "ASIA"] {
        if let Some(after) = rest.strip_prefix(prefix) {
            let n = take_while_bytes(after, |b| b.is_ascii_uppercase() || b.is_ascii_digit());
            if n == 16 {
                let next_byte = after.as_bytes().get(16).copied();
                if next_byte.is_none_or(|b| !b.is_ascii_alphanumeric()) {
                    return Some((SecretKind::AwsAccessKey, start + prefix.len() + 16));
                }
            }
        }
    }

    // Google API Key: `AIza` + 35 chars of `[0-9A-Za-z_-]`.
    if let Some(after) = rest.strip_prefix("AIza") {
        let n = take_while_bytes(after, |b| {
            b.is_ascii_alphanumeric() || b == b'_' || b == b'-'
        });
        if n == 35 {
            let next_byte = after.as_bytes().get(35).copied();
            if next_byte.is_none_or(|b| !(b.is_ascii_alphanumeric() || b == b'_' || b == b'-')) {
                return Some((SecretKind::GoogleApiKey, start + 4 + 35));
            }
        }
    }

    // JWT: three base64url segments, header and payload both JSON objects (`eyJ`).
    if let Some(n) = match_jwt(rest) {
        return Some((SecretKind::Jwt, start + n));
    }

    // Slack bot/user/app tokens.
    for prefix in [
        "xoxb-", "xoxp-", "xoxa-", "xoxr-", "xoxs-", "xoxe-", "xapp-",
    ] {
        if let Some(after) = rest.strip_prefix(prefix) {
            let n = take_while_bytes(after, |b| b.is_ascii_alphanumeric() || b == b'-');
            if n >= 20 && after[..n].bytes().any(|b| b.is_ascii_digit()) {
                return Some((SecretKind::SlackToken, start + prefix.len() + n));
            }
        }
    }

    // Stripe live secret and restricted keys.
    for prefix in ["sk_live_", "rk_live_"] {
        if let Some(after) = rest.strip_prefix(prefix) {
            let n = take_while_bytes(after, |b| b.is_ascii_alphanumeric());
            if n >= 16 {
                return Some((SecretKind::StripeKey, start + prefix.len() + n));
            }
        }
    }

    // npm access token: `npm_` + 36 alphanumerics.
    if let Some(after) = rest.strip_prefix("npm_") {
        let n = take_while_bytes(after, |b| b.is_ascii_alphanumeric());
        if n == 36 && after.as_bytes().get(36).is_none_or(|b| *b != b'_') {
            return Some((SecretKind::NpmToken, start + "npm_".len() + 36));
        }
    }

    // GitLab personal access token.
    if let Some(after) = rest.strip_prefix("glpat-") {
        let n = take_while_bytes(after, |b| {
            b.is_ascii_alphanumeric() || b == b'_' || b == b'-'
        });
        if n >= 20 {
            return Some((SecretKind::GitLabToken, start + "glpat-".len() + n));
        }
    }

    None
}

fn match_jwt(rest: &str) -> Option<usize> {
    fn segment(s: &str) -> usize {
        take_while_bytes(s, |b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    }
    const MIN_SEGMENT: usize = 10;

    if !rest.starts_with("eyJ") {
        return None;
    }
    let header = segment(rest);
    if header < MIN_SEGMENT || rest.as_bytes().get(header) != Some(&b'.') {
        return None;
    }
    let payload_start = header + 1;
    let payload_rest = &rest[payload_start..];
    if !payload_rest.starts_with("eyJ") {
        return None;
    }
    let payload = segment(payload_rest);
    if payload < MIN_SEGMENT || payload_rest.as_bytes().get(payload) != Some(&b'.') {
        return None;
    }
    let sig_start = payload_start + payload + 1;
    let signature = segment(&rest[sig_start..]);
    (signature >= MIN_SEGMENT).then_some(sig_start + signature)
}

/// Connection URL schemes whose `user:password@` part is a credential.
const DATABASE_URL_SCHEMES: &[&str] = &[
    "postgres://",
    "postgresql://",
    "mysql://",
    "mariadb://",
    "mongodb://",
    "mongodb+srv://",
    "redis://",
    "rediss://",
    "amqp://",
    "amqps://",
    "mssql://",
    "sqlserver://",
];

/// Returns the byte span of the password in `scheme://user:password@host`.
fn match_database_url_secret(input: &str, start: usize) -> Option<(usize, usize)> {
    let rest = &input[start..];
    let scheme_len = DATABASE_URL_SCHEMES
        .iter()
        .find(|scheme| {
            rest.len() >= scheme.len()
                && rest.as_bytes()[..scheme.len()].eq_ignore_ascii_case(scheme.as_bytes())
        })?
        .len();
    let after_scheme = &rest[scheme_len..];
    // The authority runs to the first `/` (or whitespace/quote). Its LAST `@` ends the
    // userinfo, so a raw `@` or `#` inside the password is still fully masked.
    let authority_len = take_while_bytes(after_scheme, |b| {
        !b.is_ascii_whitespace() && !matches!(b, b'/' | b'"' | b'\'' | b'`')
    });
    let userinfo_len = after_scheme[..authority_len].rfind('@')?;
    let userinfo = &after_scheme[..userinfo_len];
    let colon = userinfo.find(':')?;
    let secret_part = &userinfo[colon + 1..];
    if is_documentation_placeholder(secret_part) {
        return None;
    }
    let pw_start = start + scheme_len + colon + 1;
    Some((pw_start, pw_start + secret_part.len()))
}

/// Documentation-style passwords (`password`, `${DB_PASSWORD}`, `<password>`, `****`) are not
/// secrets; masking them would only make examples harder to read.
fn is_documentation_placeholder(value: &str) -> bool {
    const WORDS: &[&str] = &[
        "password",
        "pass",
        "passwd",
        "pwd",
        "secret",
        "changeme",
        "example",
        "yourpassword",
        "your_password",
        "your-password",
    ];
    value.is_empty()
        || value.starts_with(['$', '<', '{', '['])
        || value
            .bytes()
            .all(|b| matches!(b, b'*' | b'x' | b'X' | b'.'))
        || WORDS.iter().any(|w| value.eq_ignore_ascii_case(w))
}

fn match_aws_secret_assignment(input: &str, start: usize) -> Option<(usize, usize)> {
    const KEY: &str = "aws_secret_access_key";
    let rest = &input[start..];
    let bytes = rest.as_bytes();
    if bytes.len() < KEY.len() + 41 {
        return None;
    }
    if !bytes[..KEY.len()].eq_ignore_ascii_case(KEY.as_bytes()) {
        return None;
    }

    let mut pos = KEY.len();
    while pos < bytes.len() && (bytes[pos] == b' ' || bytes[pos] == b'\t') {
        pos += 1;
    }
    if pos >= bytes.len() || (bytes[pos] != b'=' && bytes[pos] != b':') {
        return None;
    }
    pos += 1;
    while pos < bytes.len() && (bytes[pos] == b' ' || bytes[pos] == b'\t') {
        pos += 1;
    }
    if pos < bytes.len() && (bytes[pos] == b'"' || bytes[pos] == b'\'') {
        pos += 1;
    }

    let val_rel_start = pos;
    let tail = &rest[val_rel_start..];
    let n = take_while_bytes(tail, |b| {
        b.is_ascii_alphanumeric() || b == b'/' || b == b'+' || b == b'='
    });
    if n == 40 {
        return Some((start + val_rel_start, start + val_rel_start + 40));
    }

    None
}

fn match_anthropic_env_assignment(input: &str, start: usize) -> Option<(usize, usize)> {
    const KEY: &str = "anthropic_api_key";
    let rest = &input[start..];
    let bytes = rest.as_bytes();
    if bytes.len() < KEY.len() + 13 {
        return None;
    }
    if !bytes[..KEY.len()].eq_ignore_ascii_case(KEY.as_bytes()) {
        return None;
    }

    let mut pos = KEY.len();
    while pos < bytes.len() && (bytes[pos] == b' ' || bytes[pos] == b'\t') {
        pos += 1;
    }
    if pos >= bytes.len() || (bytes[pos] != b'=' && bytes[pos] != b':') {
        return None;
    }
    pos += 1;
    while pos < bytes.len() && (bytes[pos] == b' ' || bytes[pos] == b'\t') {
        pos += 1;
    }
    if pos < bytes.len() && (bytes[pos] == b'"' || bytes[pos] == b'\'') {
        pos += 1;
    }

    let tail = &rest[pos..];
    if tail.starts_with("[REDACTED:") {
        return None;
    }
    let n = take_while_bytes(tail, |b| {
        b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'+' | b'/' | b'=')
    });
    if n >= 12 {
        return Some((start + pos, start + pos + n));
    }
    None
}

fn match_bearer_token(input: &str, start: usize) -> Option<(usize, usize)> {
    let rest = &input[start..];
    let after = rest.strip_prefix("Bearer ")?;
    let n = take_while_bytes(after, |b| {
        b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'~' | b'+' | b'/' | b'-' | b'=')
    });
    if n < 20 {
        return None;
    }

    let token = &after[..n];
    let has_digit = token.bytes().any(|b| b.is_ascii_digit());
    let has_dot = token.contains('.');
    let has_upper = token.bytes().any(|b| b.is_ascii_uppercase());
    let has_lower = token.bytes().any(|b| b.is_ascii_lowercase());
    if has_digit || has_dot || (has_upper && has_lower) {
        let tok_start = start + "Bearer ".len();
        return Some((tok_start, tok_start + n));
    }

    None
}

fn take_while_bytes(s: &str, pred: impl Fn(u8) -> bool) -> usize {
    s.bytes().take_while(|&b| pred(b)).count()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_openai_anthropic_github_aws_google_bearer_and_private_key() {
        // Synthetic test tokens constructed from safe dummy parts.
        let openai = format!("sk-proj-{}", "aB1cD2eF3gH4iJ5kL6mN7oP8");
        let anthropic = format!("sk-ant-api03-{}", "zY9xW8vU7tS6rQ5pO4nM3lK2");
        let github = format!("ghp_{}", "1234567890abcdefghij1234567890abcdef");
        let aws_access = "AKIAIOSFODNN7EXAMPLE";
        let aws_secret = "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
        let google = format!("AIza{}", "SyD-0123456789abcdef_0123456789abcd");
        let bearer = "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTYifQ.sig123456";
        let pem = concat!(
            "-----BEGIN RSA PRIVATE KEY-----\n",
            "MIIEowIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy0AHB7M\n",
            "-----END RSA PRIVATE KEY-----"
        );

        let sample = format!(
            "openai={openai}\nanthropic={anthropic}\ngithub={github}\naws={aws_access}\n{aws_secret}\ngoogle={google}\n{bearer}\n{pem}\n"
        );

        let res = redact_secrets(&sample);
        assert_eq!(res.redactions_count, 8);
        assert!(res.text.contains("[REDACTED:OPENAI_KEY]"));
        assert!(res.text.contains("[REDACTED:ANTHROPIC_KEY]"));
        assert!(res.text.contains("[REDACTED:GITHUB_TOKEN]"));
        assert!(res.text.contains("[REDACTED:AWS_ACCESS_KEY]"));
        assert!(
            res.text
                .contains("AWS_SECRET_ACCESS_KEY=[REDACTED:AWS_SECRET_KEY]")
        );
        assert!(res.text.contains("[REDACTED:GOOGLE_API_KEY]"));
        assert!(
            res.text
                .contains("Authorization: Bearer [REDACTED:BEARER_TOKEN]")
        );
        assert!(res.text.contains("[REDACTED:PRIVATE_KEY]"));

        // Ensure zero raw secret substrings leak into output.
        assert!(!res.text.contains(&openai));
        assert!(!res.text.contains(&anthropic));
        assert!(!res.text.contains(&github));
        assert!(!res.text.contains(aws_access));
        assert!(!res.text.contains("wJalrXUtnFEMI"));
        assert!(!res.text.contains(&google));
        assert!(!res.text.contains("eyJhbGciOiJIUzI1NiJ9"));
        assert!(!res.text.contains("MIIEowIBAAKCAQEA"));
    }

    #[test]
    fn normal_source_code_produces_zero_false_positives() {
        let code = r#"
pub struct AuthConfig {
    pub api_key_env: &'static str,
    pub bearer_scheme: &'static str,
}

impl AuthConfig {
    pub fn default_config() -> Self {
        let sk_prefix = "sk-some-lowercase-css-class-identifier";
        let msg = "Bearer authentication_mechanism handles session cookies";
        let _ = (sk_prefix, msg);
        Self {
            api_key_env: "OPENAI_API_KEY",
            bearer_scheme: "Bearer",
        }
    }
}
"#;
        let res = redact_secrets(code);
        assert_eq!(res.redactions_count, 0);
        assert_eq!(res.text, code);
        assert!(res.by_kind.is_empty());
    }

    #[test]
    fn long_turkish_and_unicode_text_never_panics_on_char_boundaries() {
        // Multi-byte UTF-8 characters (Turkish letters + emoji) exceeding 62 bytes
        // at multiple byte offsets so byte 21 lands mid-codepoint during scanning.
        let turkish = concat!(
            "Şişli'deki geliştiriciler için güvenli, deterministik ve hızlı kod merceği: ",
            "ğüşiöçĞÜŞİÖÇ — ışık hızında çalışan çözümleme motoru 🚀✨ ",
            "bağlam gürültüsünü azaltır ve yanlış alarm üretmez."
        );
        assert!(turkish.len() > 150);

        // Test multiple 1-byte/multi-byte prefixes to exercise every UTF-8 offset alignment.
        for pad in ["", "a", "ab", "ç", "şı", "🚀"] {
            let input = format!("{pad}{turkish}");
            let res = redact_secrets(&input);
            assert_eq!(res.redactions_count, 0);
            assert_eq!(res.text, input);
        }

        // Embedded AWS secret inside long Turkish text is still redacted without panicking.
        let with_secret = format!(
            "{turkish}\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n{turkish}"
        );
        let res = redact_secrets(&with_secret);
        assert_eq!(res.redactions_count, 1);
        assert!(
            res.text
                .contains("AWS_SECRET_ACCESS_KEY=[REDACTED:AWS_SECRET_KEY]")
        );
        assert!(!res.text.contains("wJalrXUtnFEMI"));
    }

    #[test]
    fn redacts_jwt_slack_stripe_npm_gitlab_and_database_url_passwords() {
        // Synthetic test tokens assembled from dummy parts.
        let jwt = format!(
            "{}.{}.{}",
            "eyJhbGciOiJIUzI1NiJ9", "eyJzdWIiOiIxMjM0NTYifQ", "c2lnbmF0dXJlMTIzNDU2"
        );
        let slack = format!("xoxb-{}", "123456789012-1234567890123-AbCdEfGhIjKl");
        let stripe = format!("sk_live_{}", "4eC39HqLyjWDarjtT1zdp7dc");
        let stripe_restricted = format!("rk_live_{}", "4eC39HqLyjWDarjtT1zdp7dc");
        let npm = format!("npm_{}", "aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789");
        let gitlab = format!("glpat-{}", "xYz123AbC456dEf789gH");
        let db_pass = "S3cr3t-Pa55w0rd";
        let pg = format!("postgres://app_user:{db_pass}@db.internal:5432/app");
        let mongo = format!("MONGO_URL=\"mongodb+srv://admin:{db_pass}@cluster0.example.net/db\"");

        let sample = format!(
            "token={jwt}\nslack={slack}\nstripe={stripe}\nrk={stripe_restricted}\n//registry.npmjs.org/:_authToken={npm}\ngitlab={gitlab}\nDATABASE_URL={pg}\n{mongo}\n"
        );
        let res = redact_secrets(&sample);

        for leaked in [
            jwt.as_str(),
            slack.as_str(),
            stripe.as_str(),
            stripe_restricted.as_str(),
            npm.as_str(),
            gitlab.as_str(),
            db_pass,
        ] {
            assert!(!res.text.contains(leaked), "leaked {leaked}: {}", res.text);
        }
        assert!(res.text.contains("token=[REDACTED:JWT]"), "{}", res.text);
        assert!(res.text.contains("slack=[REDACTED:SLACK_TOKEN]"));
        assert!(res.text.contains("stripe=[REDACTED:STRIPE_KEY]"));
        assert!(res.text.contains("rk=[REDACTED:STRIPE_KEY]"));
        assert!(res.text.contains("_authToken=[REDACTED:NPM_TOKEN]"));
        assert!(res.text.contains("gitlab=[REDACTED:GITLAB_TOKEN]"));
        // Only the password is masked; scheme, user and host stay readable.
        assert!(res.text.contains(
            "DATABASE_URL=postgres://app_user:[REDACTED:DATABASE_PASSWORD]@db.internal:5432/app"
        ));
        assert!(res.text.contains(
            "mongodb+srv://admin:[REDACTED:DATABASE_PASSWORD]@cluster0.example.net/db\""
        ));
        assert_eq!(res.redactions_count, 8);
    }

    #[test]
    fn database_password_containing_at_sign_is_fully_masked() {
        let res = redact_secrets("url=postgres://svc:p@ss#w0rd-9@db.local/app?x=a@b");
        assert_eq!(
            res.text,
            "url=postgres://svc:[REDACTED:DATABASE_PASSWORD]@db.local/app?x=a@b"
        );
    }

    #[test]
    fn new_patterns_leave_ordinary_code_and_placeholders_alone() {
        let code = r#"
let xoxo = "hugs-and-kisses";
let short_jwt_like = "eyJ.not.a.token";
let jwt_doc = "eyJhbGciOi...";
run("npm_config_cache");
let stripe_doc = "sk_live_...";
let gl = "glpat-short";
const LOCAL: &str = "postgres://localhost:5432/app";
const EXAMPLE: &str = "postgres://user:password@localhost/db";
const TEMPLATED: &str = "mysql://root:${DB_PASSWORD}@db/app";
const ANGLE: &str = "redis://default:<password>@cache:6379";
const STARS: &str = "amqp://guest:****@mq/";
let url = "https://example.com/path:with@sign";
"#;
        let res = redact_secrets(code);
        assert_eq!(res.redactions_count, 0, "{}", res.text);
        assert_eq!(res.text, code);
    }
}
