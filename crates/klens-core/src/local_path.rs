//! Telling plain local paths from network shares and device paths, before any filesystem call.

/// `true` for a plain local absolute path: `C:\x`, `C:/x`, `\\?\C:\x`, `//?/C:/x`, or (outside
/// Windows) `/x`. Never a network share (`\\host\share`, `//host/share`, `\\?\UNC\...`) or a
/// device path (`\\.\...`).
///
/// Call this before handing an untrusted absolute path (from an AI agent, command output or the
/// Web UI) to the filesystem: on Windows, merely canonicalizing or stat-ing a network path opens
/// an SMB connection, which leaks the user's NTLM credential hash and stalls for ~20 s.
pub fn is_plain_local_absolute(path: &str) -> bool {
    let unverbatim = path
        .strip_prefix(r"\\?\")
        .or_else(|| path.strip_prefix("//?/"))
        .unwrap_or(path);
    if has_windows_drive_prefix(unverbatim) {
        return true;
    }
    !cfg!(windows) && unverbatim.starts_with('/') && !starts_with_two_separators(unverbatim)
}

/// `true` when `path` names (or may name) a network share or a Windows device namespace:
/// anything starting with two path separators (`\\host\share`, `//host/share`, `\\?\UNC\...`,
/// `\\.\pipe\...`), except the local verbatim drive form `\\?\C:\...`.
///
/// Relative paths and ordinary absolute paths return `false`. Use it to refuse a path before any
/// filesystem call when relative input is also allowed.
pub fn is_network_or_device_path(path: &str) -> bool {
    let trimmed = path.trim();
    if !starts_with_two_separators(trimmed) {
        return false;
    }
    let unverbatim = trimmed
        .strip_prefix(r"\\?\")
        .or_else(|| trimmed.strip_prefix("//?/"));
    !unverbatim.is_some_and(has_windows_drive_prefix)
}

fn starts_with_two_separators(path: &str) -> bool {
    let bytes = path.as_bytes();
    bytes.len() >= 2 && matches!(bytes[0], b'/' | b'\\') && matches!(bytes[1], b'/' | b'\\')
}

fn has_windows_drive_prefix(s: &str) -> bool {
    let bytes = s.as_bytes();
    bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':'
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn network_and_device_paths_are_never_plain_local() {
        for p in [
            r"\\192.0.2.1\share\x.rs",
            "//192.0.2.1/share/x.rs",
            r"\\?\UNC\192.0.2.1\share\x.rs",
            "//?/UNC/192.0.2.1/share/x.rs",
            r"\\.\pipe\x",
            r"\/192.0.2.1/share",
            r"/\192.0.2.1\share",
        ] {
            assert!(!is_plain_local_absolute(p), "{p} must not be local");
            assert!(is_network_or_device_path(p), "{p} must be a network path");
        }
    }

    #[test]
    fn local_drive_and_relative_paths_are_not_network_paths() {
        for p in [r"C:\x\y.rs", "C:/x/y.rs", r"\\?\C:\x\y.rs", "//?/C:/x/y.rs"] {
            assert!(is_plain_local_absolute(p), "{p} must be local");
            assert!(!is_network_or_device_path(p), "{p} is not a network path");
        }
        for p in ["src/lib.rs", ".", "/home/u/p", r"\x"] {
            assert!(!is_network_or_device_path(p), "{p} is not a network path");
        }
        assert_eq!(is_plain_local_absolute("/home/u/p"), !cfg!(windows));
        assert!(!is_plain_local_absolute("src/lib.rs"));
    }
}
