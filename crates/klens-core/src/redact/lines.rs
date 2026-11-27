//! Line-aware masking of PEM private-key blocks, for callers that show only part of a file.

use super::{RedactionResult, SecretKind, match_private_key_block, redact_secrets};

/// Line spans (0-based, inclusive) of every PEM private-key block in `text`, from the
/// `-----BEGIN ... PRIVATE KEY-----` line to its `-----END ... PRIVATE KEY-----` line, or to the
/// last line when the block is unterminated. Lines are counted on `\n`, like `str::lines`.
///
/// Callers that show only part of a file (a line range, a search hit, an error window) must mask
/// these lines *before* slicing: redacting only the slice misses a key body whose `BEGIN` line
/// lies outside it.
pub fn private_key_line_spans(text: &str) -> Vec<(usize, usize)> {
    let bytes = text.as_bytes();
    let mut spans = Vec::new();
    let mut line = 0usize;
    let mut counted_to = 0usize;
    let mut search_from = 0usize;
    let mut line_at = |pos: usize| {
        line += bytes[counted_to..pos]
            .iter()
            .filter(|&&b| b == b'\n')
            .count();
        counted_to = pos;
        line
    };
    while let Some(rel) = text[search_from..].find("-----BEGIN ") {
        let start = search_from + rel;
        let Some(end) = match_private_key_block(text, start) else {
            search_from = start + "-----BEGIN ".len();
            continue;
        };
        let first = line_at(start);
        // `end` is exclusive; the block's last byte decides its last line.
        let last = line_at(end.saturating_sub(1).max(start));
        spans.push((first, last));
        search_from = end;
    }
    spans
}

/// Like [`redact_secrets`], but keeps the line structure: every line of a PEM private-key block
/// becomes its own `[REDACTED:PRIVATE_KEY]` line (one redaction per block), so line numbers
/// computed on the result still match the original text.
pub fn redact_secrets_by_line(text: &str) -> RedactionResult {
    let spans = private_key_line_spans(text);
    if spans.is_empty() {
        return redact_secrets(text);
    }
    let masked = mask_lines(text, &spans);
    let mut result = redact_secrets(&masked);
    result.redactions_count += spans.len();
    *result.by_kind.entry(SecretKind::PrivateKey).or_insert(0) += spans.len();
    result
}

/// Replace every line inside `spans` with the private-key placeholder (line count unchanged).
fn mask_lines(text: &str, spans: &[(usize, usize)]) -> String {
    let placeholder = SecretKind::PrivateKey.placeholder();
    let mut out = String::with_capacity(text.len());
    let mut span_iter = spans.iter().peekable();
    for (idx, line) in text.split('\n').enumerate() {
        if idx > 0 {
            out.push('\n');
        }
        while span_iter.peek().is_some_and(|(_, last)| *last < idx) {
            span_iter.next();
        }
        let inside = span_iter
            .peek()
            .is_some_and(|(first, last)| *first <= idx && idx <= *last);
        out.push_str(if inside { placeholder } else { line });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_key_line_spans_cover_the_whole_block_and_unterminated_tails() {
        let text =
            "a\n-----BEGIN EC PRIVATE KEY-----\nbody1\nbody2\n-----END EC PRIVATE KEY-----\nb\n";
        assert_eq!(private_key_line_spans(text), vec![(1, 4)]);

        let cut = "x\ny\n-----BEGIN PRIVATE KEY-----\nbody\nmore";
        assert_eq!(private_key_line_spans(cut), vec![(2, 4)]);

        let one_line = r#"{"k":"-----BEGIN PRIVATE KEY-----\nAB\n-----END PRIVATE KEY-----"}"#;
        assert_eq!(private_key_line_spans(one_line), vec![(0, 0)]);

        let not_private = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n";
        assert!(private_key_line_spans(not_private).is_empty());
    }

    #[test]
    fn line_preserving_redaction_keeps_line_numbers() {
        let text = "a\n-----BEGIN RSA PRIVATE KEY-----\nbody1\n-----END RSA PRIVATE KEY-----\nghp_abcdefghijklmnopqrstuvwxyz0123456789\nlast\n";
        let res = redact_secrets_by_line(text);
        assert_eq!(res.text.lines().count(), text.lines().count());
        assert!(!res.text.contains("body1"));
        assert_eq!(res.text.lines().nth(5), Some("last"));
        assert_eq!(res.by_kind.get(&SecretKind::PrivateKey), Some(&1));
        assert_eq!(res.by_kind.get(&SecretKind::GitHubToken), Some(&1));
        assert_eq!(res.redactions_count, 2);
        assert!(res.text.ends_with('\n'));
    }
}
