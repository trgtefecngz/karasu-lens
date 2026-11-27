//! ANSI / VT escape sequence, OSC, and carriage-return (`\r`) progress bar cleaner.
//!
//! Runs before any command filter and before token counting so escape codes
//! never pollute summaries or inflate raw token counts (Constitution Articles 4 & 7).

/// Strip all ANSI CSI/OSC/DCS/ESC sequences, normalize `\r\n` to `\n`,
/// collapse bare `\r` progress-bar overwrites, and remove stray C0 control bytes.
///
/// Guarantees that the returned string contains zero `\x1b` (`ESC`) characters
/// and zero `\r` characters.
pub fn strip_ansi(input: &str) -> String {
    let bytes = input.as_bytes();
    let len = bytes.len();
    let mut no_esc = String::with_capacity(len);

    let mut i = 0usize;
    while i < len {
        let b = bytes[i];
        if b == 0x1B {
            i = skip_escape_sequence(bytes, i);
            continue;
        }

        // Preserve UTF-8 multi-byte characters verbatim; filter C0 control bytes
        // except `\n`, `\r` (handled in pass 2), and `\t`.
        if b < 0x20 && b != b'\n' && b != b'\r' && b != b'\t' {
            i += 1;
            continue;
        }
        if b == 0x7F {
            i += 1;
            continue;
        }

        let ch = input[i..].chars().next().unwrap();
        no_esc.push(ch);
        i += ch.len_utf8();
    }

    collapse_carriage_returns(&no_esc)
}

/// Remove ANSI/VT escape sequences (CSI, OSC, DCS, ...) only; every other byte, including `\r`
/// and line endings, is kept as is. Used for `--raw` output, which must stay otherwise verbatim.
pub fn strip_escape_sequences(input: &str) -> String {
    let bytes = input.as_bytes();
    if !bytes.contains(&0x1B) {
        return input.to_string();
    }
    let mut out = String::with_capacity(input.len());
    let mut copied_to = 0usize;
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == 0x1B {
            out.push_str(&input[copied_to..i]);
            i = skip_escape_sequence(bytes, i);
            copied_to = i;
        } else {
            i += 1;
        }
    }
    out.push_str(&input[copied_to..]);
    out
}

/// Redact secrets in raw (`--raw`) command output. Escape sequences are removed first: a colour
/// code right before a token (`\x1b[32mghp_...`) ends in a letter, which would hide the token
/// from the redactor's word-boundary check. The raw log on disk keeps the original bytes.
pub(crate) fn redact_raw_output(raw: &str) -> klens_core::RedactionResult {
    klens_core::redact_secrets(&strip_escape_sequences(raw))
}

/// Returns `true` if `text` contains any ANSI escape byte (`\x1b`).
pub fn contains_ansi(text: &str) -> bool {
    text.as_bytes().contains(&0x1B)
}

/// Skip a single escape sequence starting at `bytes[start] == 0x1B`.
/// Returns the index immediately after the sequence.
fn skip_escape_sequence(bytes: &[u8], start: usize) -> usize {
    let len = bytes.len();
    let next = start + 1;
    if next >= len {
        return len;
    }

    match bytes[next] {
        // CSI: ESC [ <params 0x30..=0x3F>* <intermediates 0x20..=0x2F>* <final 0x40..=0x7E>
        b'[' => {
            let mut i = next + 1;
            while i < len && (0x30..=0x3F).contains(&bytes[i]) {
                i += 1;
            }
            while i < len && (0x20..=0x2F).contains(&bytes[i]) {
                i += 1;
            }
            if i < len && (0x40..=0x7E).contains(&bytes[i]) {
                i + 1
            } else {
                i
            }
        }
        // OSC: ESC ] ... (terminated by BEL 0x07 or ST `ESC \`)
        b']' => skip_string_terminated_sequence(bytes, next + 1),
        // DCS (`P`), SOS (`X`), PM (`^`), APC (`_`): terminated by ST (`ESC \`) or BEL
        b'P' | b'X' | b'^' | b'_' => skip_string_terminated_sequence(bytes, next + 1),
        // Charset designation sequences: ESC ( X, ESC ) X, ESC * X, ESC + X
        // Only consume the 3rd byte when it is printable ASCII so we never split a UTF-8 codepoint.
        b'(' | b')' | b'*' | b'+' => {
            if next + 1 < len && (0x20..=0x7E).contains(&bytes[next + 1]) {
                next + 2
            } else {
                next + 1
            }
        }
        // Standard 2-byte ESC sequence (e.g., ESC =, ESC >, ESC M, ESC c)
        0x20..=0x7E => next + 1,
        // Stray ESC followed by control/UTF-8 byte: drop ESC only
        _ => next,
    }
}

fn skip_string_terminated_sequence(bytes: &[u8], mut i: usize) -> usize {
    let len = bytes.len();
    while i < len {
        if bytes[i] == 0x07 {
            return i + 1;
        }
        if bytes[i] == 0x1B && i + 1 < len && bytes[i + 1] == b'\\' {
            return i + 2;
        }
        // Defensive cap: if an unterminated OSC hits newline, stop before newline
        // so subsequent real log lines are never swallowed.
        if bytes[i] == b'\n' {
            return i;
        }
        i += 1;
    }
    len
}

/// Normalize `\r\n` to `\n` and simulate terminal carriage return on bare `\r`
/// progress-bar updates (`frame1\rframe2\n` -> `frame2\n`).
fn collapse_carriage_returns(input: &str) -> String {
    if !input.as_bytes().contains(&b'\r') {
        return input.to_string();
    }

    let mut out = String::with_capacity(input.len());
    let mut line_buf = String::new();
    let mut pending_overwrite = false;

    let mut chars = input.chars().peekable();
    while let Some(ch) = chars.next() {
        match ch {
            '\r' => {
                if chars.peek() == Some(&'\n') {
                    // Normal Windows CRLF line ending.
                    chars.next();
                    out.push_str(&line_buf);
                    out.push('\n');
                    line_buf.clear();
                    pending_overwrite = false;
                } else {
                    // Bare CR: defer clearing `line_buf` until new text arrives on this line,
                    // so a trailing `\r` at EOF never erases valid content.
                    pending_overwrite = true;
                }
            }
            '\n' => {
                out.push_str(&line_buf);
                out.push('\n');
                line_buf.clear();
                pending_overwrite = false;
            }
            other => {
                if pending_overwrite {
                    line_buf.clear();
                    pending_overwrite = false;
                }
                line_buf.push(other);
            }
        }
    }

    out.push_str(&line_buf);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_csi_colors_and_cursor_controls() {
        let raw = "\x1b[1;31merror[E0308]\x1b[0m: \x1b[1mmismatched types\x1b[0m\n\x1b[34m  --> \x1b[0msrc/main.rs:42:5\n";
        let clean = strip_ansi(raw);
        assert!(!contains_ansi(&clean));
        assert_eq!(
            clean,
            "error[E0308]: mismatched types\n  --> src/main.rs:42:5\n"
        );
    }

    #[test]
    fn strips_osc_hyperlinks_and_window_titles() {
        let raw = "\x1b]0;cargo test\x07\x1b]8;;https://doc.rust-lang.org/error_codes/E0308.html\x1b\\E0308\x1b]8;;\x1b\\: mismatched types\n";
        let clean = strip_ansi(raw);
        assert!(!contains_ansi(&clean));
        assert_eq!(clean, "E0308: mismatched types\n");
    }

    #[test]
    fn collapses_progress_bar_carriage_returns_and_normalizes_crlf() {
        let raw = "Downloading [==>   ] 30%\rDownloading [====> ] 70%\rDownloading [======] 100%\r\nDone\r\n";
        let clean = strip_ansi(raw);
        assert!(!clean.contains('\r'));
        assert_eq!(clean, "Downloading [======] 100%\nDone\n");
    }

    #[test]
    fn preserves_utf8_turkish_and_trailing_cr() {
        let raw = "\x1b[32mBaşarılı: ğüşiöçĞÜŞİÖÇ\x1b[0m\r";
        let clean = strip_ansi(raw);
        assert!(!contains_ansi(&clean));
        assert!(!clean.contains('\r'));
        assert_eq!(clean, "Başarılı: ğüşiöçĞÜŞİÖÇ");
    }

    #[test]
    fn malformed_charset_escape_before_multibyte_utf8_never_panics() {
        assert_eq!(strip_ansi("\x1b(ğ"), "ğ");
        assert_eq!(strip_ansi("\x1b)ş\x1b*ü\x1b+🚀\x1b("), "şü🚀");
        assert_eq!(strip_ansi("\x1b(Bhello"), "hello");
        assert!(!contains_ansi(&strip_ansi("\x1b(ğ")));
    }
}
