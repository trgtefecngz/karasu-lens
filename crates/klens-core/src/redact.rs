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

    None
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
}
