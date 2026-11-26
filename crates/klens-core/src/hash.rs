use std::borrow::Cow;
use std::fs::File;
use std::io::{self, BufReader, Read};
use std::path::Path;

/// Normalize Windows CRLF (`\r\n`) line endings to LF (`\n`).
///
/// Borrows the input without allocation when no `\r` byte is present.
pub fn normalize_line_endings(input: &str) -> Cow<'_, str> {
    if !input.contains('\r') {
        return Cow::Borrowed(input);
    }
    Cow::Owned(input.replace("\r\n", "\n"))
}

/// Compute a lowercase hex BLAKE3 digest of bytes after normalizing `\r\n` to `\n`.
pub fn blake3_normalized_bytes(bytes: &[u8]) -> String {
    let mut hasher = blake3::Hasher::new();
    let mut pending_cr = false;
    feed_normalized(&mut hasher, bytes, &mut pending_cr);
    if pending_cr {
        hasher.update(b"\r");
    }
    hasher.finalize().to_hex().to_string()
}

/// Compute a lowercase hex BLAKE3 digest of raw bytes without line-ending changes.
pub fn blake3_raw_bytes(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}

/// Compute a lowercase hex BLAKE3 digest of UTF-8 text after normalizing `\r\n` to `\n`.
pub fn blake3_text(input: &str) -> String {
    blake3_normalized_bytes(input.as_bytes())
}

/// Compute a deterministic, domain-separated parse cache key combining CRLF-normalized
/// file text with parser identity and parser version:
/// `BLAKE3(normalized_content || 0x00 || parser_id || 0x00 || parser_version)`.
pub fn blake3_parse_cache_key(
    normalized_content: &str,
    parser_id: &str,
    parser_version: &str,
) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(normalized_content.as_bytes());
    hasher.update(&[0u8]);
    hasher.update(parser_id.as_bytes());
    hasher.update(&[0u8]);
    hasher.update(parser_version.as_bytes());
    hasher.finalize().to_hex().to_string()
}

/// Stream a file through BLAKE3 with `\r\n` → `\n` normalization across chunk boundaries.
pub fn blake3_file(path: &Path) -> io::Result<String> {
    let file = File::open(path)?;
    blake3_reader(BufReader::new(file))
}

/// Stream any `Read` source through BLAKE3 with `\r\n` → `\n` normalization.
pub fn blake3_reader<R: Read>(mut reader: R) -> io::Result<String> {
    let mut hasher = blake3::Hasher::new();
    let mut buf = [0u8; 16 * 1024];
    let mut pending_cr = false;

    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        feed_normalized(&mut hasher, &buf[..n], &mut pending_cr);
    }

    if pending_cr {
        hasher.update(b"\r");
    }

    Ok(hasher.finalize().to_hex().to_string())
}

/// Derive a compact, deterministic 16-hex-char project identifier from a canonical root path.
pub fn project_id_from_canonical_root(canonical_root: &Path) -> String {
    let raw = canonical_root.to_string_lossy();
    let stripped = raw.strip_prefix(r"\\?\").unwrap_or(&raw);
    let normalized = stripped.replace('\\', "/");
    let trimmed = if normalized.len() > 1 {
        normalized.trim_end_matches('/')
    } else {
        normalized.as_str()
    };
    let digest = blake3_raw_bytes(trimmed.as_bytes());
    digest[..16].to_string()
}

fn feed_normalized(hasher: &mut blake3::Hasher, chunk: &[u8], pending_cr: &mut bool) {
    let mut start = 0;

    if *pending_cr {
        *pending_cr = false;
        if chunk.first() == Some(&b'\n') {
            // The previous chunk ended with `\r` and this chunk starts with `\n`:
            // emit only `\n` (starting at index 0 includes `\n`).
        } else {
            // Standalone `\r` at chunk boundary; preserve it.
            hasher.update(b"\r");
        }
    }

    let mut i = 0;
    while i < chunk.len() {
        if chunk[i] == b'\r' {
            if i + 1 < chunk.len() {
                if chunk[i + 1] == b'\n' {
                    if start < i {
                        hasher.update(&chunk[start..i]);
                    }
                    hasher.update(b"\n");
                    i += 2;
                    start = i;
                    continue;
                }
            } else {
                // `\r` is the last byte in this chunk; defer decision until next chunk.
                if start < i {
                    hasher.update(&chunk[start..i]);
                }
                *pending_cr = true;
                return;
            }
        }
        i += 1;
    }

    if start < chunk.len() {
        hasher.update(&chunk[start..]);
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    #[test]
    fn crlf_and_lf_produce_identical_hashes() {
        let lf = "fn main() {\n    let x = 1;\n}\n";
        let crlf = "fn main() {\r\n    let x = 1;\r\n}\r\n";
        assert_eq!(blake3_text(lf), blake3_text(crlf));
        assert_eq!(normalize_line_endings(crlf), lf);
        assert!(matches!(normalize_line_endings(lf), Cow::Borrowed(_)));
    }

    #[test]
    fn streaming_normalization_handles_chunk_boundary_crlf() {
        // Build a string > 16 KiB where `\r` lands at byte 16383 and `\n` at byte 16384.
        let mut crlf = vec![b'a'; 16 * 1024 - 1];
        crlf.push(b'\r');
        crlf.push(b'\n');
        crlf.extend_from_slice(b"tail\r\n");

        let mut lf = vec![b'a'; 16 * 1024 - 1];
        lf.push(b'\n');
        lf.extend_from_slice(b"tail\n");

        let h_stream = blake3_reader(Cursor::new(&crlf)).unwrap();
        let h_expected = blake3_raw_bytes(&lf);
        assert_eq!(h_stream, h_expected);
    }

    #[test]
    fn standalone_cr_is_preserved() {
        let data = b"abc\rdef";
        assert_eq!(blake3_normalized_bytes(data), blake3_raw_bytes(data));
    }

    #[test]
    fn parse_cache_key_separates_content_parser_and_version() {
        let k1 = blake3_parse_cache_key("class A {}", "ext-lang-java", "0.1.0");
        let k2 = blake3_parse_cache_key("class A {}", "ext-lang-java", "0.1.0");
        let k_ver = blake3_parse_cache_key("class A {}", "ext-lang-java", "0.2.0");
        let k_parser = blake3_parse_cache_key("class A {}", "ext-lang-ctags", "0.1.0");
        let k_content = blake3_parse_cache_key("class B {}", "ext-lang-java", "0.1.0");
        let k_domain = blake3_parse_cache_key("class A {}ext-lang-java", "", "0.1.0");

        assert_eq!(k1, k2);
        assert_eq!(k1.len(), 64);
        assert_ne!(k1, k_ver);
        assert_ne!(k1, k_parser);
        assert_ne!(k1, k_content);
        assert_ne!(k1, k_domain);
    }
}
