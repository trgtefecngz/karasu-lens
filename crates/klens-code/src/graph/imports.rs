use std::collections::{BTreeMap, BTreeSet};
use std::fs;

use klens_core::RelPath;

use crate::index::CodeIndex;
use crate::store::IndexedFileRecord;

/// Workspace metadata used to resolve language-specific AST imports to internal files.
pub(crate) struct ImportResolverContext {
    /// Rust workspace crate name (with `_`) -> normalized `src` directory path.
    cargo_crates: BTreeMap<String, String>,
    /// Go module path prefix from root `go.mod` (e.g. `example.com/demo`).
    go_module_prefix: Option<String>,
}

impl ImportResolverContext {
    pub(crate) fn load(index: &CodeIndex, files: &[IndexedFileRecord]) -> Self {
        let mut cargo_crates = BTreeMap::new();
        let mut go_module_prefix = None;

        for rec in files {
            let file_name = rec.path.file_name().unwrap_or("");
            if file_name == "Cargo.toml" {
                if let Ok((abs, _)) = index.project_root().resolve_existing_with_extra(
                    rec.path.as_str(),
                    &index.project_config().extra_sensitive_patterns,
                ) && let Ok(content) = fs::read_to_string(&abs)
                    && let Ok(doc) = toml::from_str::<toml::Value>(&content)
                    && let Some(pkg_name) = doc
                        .get("package")
                        .and_then(|p| p.get("name"))
                        .and_then(toml::Value::as_str)
                {
                    let crate_ident = pkg_name.replace('-', "_");
                    let parent_dir = parent_dir_str(rec.path.as_str());
                    let src_dir = if parent_dir.is_empty() {
                        "src".to_string()
                    } else {
                        format!("{parent_dir}/src")
                    };
                    cargo_crates.entry(crate_ident).or_insert(src_dir);
                }
            } else if rec.path.as_str() == "go.mod"
                && let Ok((abs, _)) = index.project_root().resolve_existing_with_extra(
                    "go.mod",
                    &index.project_config().extra_sensitive_patterns,
                )
                && let Ok(content) = fs::read_to_string(&abs)
            {
                for line in content.lines() {
                    let trimmed = line.trim();
                    if let Some(rest) = trimmed.strip_prefix("module ") {
                        let module_path = rest.split_whitespace().next().unwrap_or("").trim();
                        if !module_path.is_empty() {
                            go_module_prefix = Some(module_path.to_string());
                            break;
                        }
                    }
                }
            }
        }

        Self {
            cargo_crates,
            go_module_prefix,
        }
    }

    pub(crate) fn resolve_import(
        &self,
        from_path: &str,
        language_id: &str,
        raw_to: &str,
        file_set: &BTreeSet<String>,
    ) -> Vec<String> {
        let mut targets = BTreeSet::new();

        match language_id {
            "rust" => self.resolve_rust_import(from_path, raw_to, file_set, &mut targets),
            "typescript" => resolve_ts_js_import(from_path, raw_to, file_set, &mut targets),
            "python" => resolve_python_import(from_path, raw_to, file_set, &mut targets),
            "go" => self.resolve_go_import(raw_to, file_set, &mut targets),
            _ => resolve_external_import(from_path, raw_to, file_set, &mut targets),
        }

        targets.into_iter().collect()
    }

    fn resolve_rust_import(
        &self,
        from_path: &str,
        raw_to: &str,
        file_set: &BTreeSet<String>,
        out: &mut BTreeSet<String>,
    ) {
        let from_dir = parent_dir_str(from_path);
        let from_stem = file_stem_str(from_path);

        if let Some(mod_name) = raw_to.strip_prefix("mod:") {
            let candidates = if matches!(from_stem, "lib" | "main" | "mod") {
                vec![
                    join_rel(from_dir, &format!("{mod_name}.rs")),
                    join_rel(from_dir, &format!("{mod_name}/mod.rs")),
                ]
            } else {
                vec![
                    join_rel(from_dir, &format!("{from_stem}/{mod_name}.rs")),
                    join_rel(from_dir, &format!("{from_stem}/{mod_name}/mod.rs")),
                    join_rel(from_dir, &format!("{mod_name}.rs")),
                    join_rel(from_dir, &format!("{mod_name}/mod.rs")),
                ]
            };
            for cand in candidates {
                if file_set.contains(&cand) {
                    out.insert(cand);
                    return;
                }
            }
            return;
        }

        let Some(import_expr) = raw_to.strip_prefix("import:") else {
            return;
        };
        let crate_src = rust_crate_src_root(from_path);

        for expanded in expand_rust_use_paths(import_expr) {
            let clean = expanded
                .split(" as ")
                .next()
                .unwrap_or(&expanded)
                .trim()
                .trim_start_matches("::");
            if clean.is_empty() {
                continue;
            }
            let segs: Vec<&str> = clean
                .split("::")
                .map(str::trim)
                .filter(|s| !s.is_empty() && *s != "*")
                .collect();
            if segs.is_empty() {
                continue;
            }

            if segs[0] == "crate" {
                if let Some(found) = resolve_rust_segments(crate_src, &segs[1..], file_set) {
                    out.insert(found);
                } else if segs.len() >= 2 {
                    let lib_rs = join_rel(crate_src, "lib.rs");
                    if file_set.contains(&lib_rs) && lib_rs != from_path {
                        out.insert(lib_rs);
                    }
                }
            } else if segs[0] == "super" {
                let super_count = segs.iter().take_while(|&&s| s == "super").count();
                let rest = &segs[super_count..];
                let up_dirs = if matches!(from_stem, "mod" | "lib" | "main") {
                    super_count
                } else {
                    super_count.saturating_sub(1)
                };
                let base = ascend_dirs(from_dir, up_dirs);
                if let Some(found) = resolve_rust_segments(&base, rest, file_set) {
                    out.insert(found);
                } else if let Some(found) = resolve_rust_segments(from_dir, rest, file_set) {
                    out.insert(found);
                }
            } else if segs[0] == "self" {
                let rest = &segs[1..];
                let sub_base = join_rel(from_dir, from_stem);
                if let Some(found) = resolve_rust_segments(&sub_base, rest, file_set)
                    .or_else(|| resolve_rust_segments(from_dir, rest, file_set))
                {
                    out.insert(found);
                }
            } else if let Some(target_src) = self.cargo_crates.get(segs[0]) {
                if let Some(found) = resolve_rust_segments(target_src, &segs[1..], file_set) {
                    out.insert(found);
                } else {
                    let lib_rs = join_rel(target_src, "lib.rs");
                    if file_set.contains(&lib_rs) {
                        out.insert(lib_rs);
                    }
                }
            } else if let Some(found) = resolve_rust_segments(from_dir, &segs, file_set)
                .or_else(|| resolve_rust_segments(crate_src, &segs, file_set))
            {
                out.insert(found);
            }
        }
    }

    fn resolve_go_import(
        &self,
        raw_to: &str,
        file_set: &BTreeSet<String>,
        out: &mut BTreeSet<String>,
    ) {
        let Some(import_path) = raw_to.strip_prefix("import:") else {
            return;
        };
        let Some(prefix) = &self.go_module_prefix else {
            return;
        };
        let Some(rel_dir) = import_path.strip_prefix(&format!("{prefix}/")) else {
            return;
        };
        let rel_dir = rel_dir.trim_matches('/');
        if rel_dir.is_empty() {
            return;
        }
        let dir_prefix = format!("{rel_dir}/");
        for path in file_set {
            if let Some(rest) = path.strip_prefix(&dir_prefix)
                && !rest.contains('/')
                && rest.ends_with(".go")
                && !rest.ends_with("_test.go")
            {
                out.insert(path.clone());
            }
        }
    }
}

fn resolve_rust_segments(
    base_dir: &str,
    segs: &[&str],
    file_set: &BTreeSet<String>,
) -> Option<String> {
    if segs.is_empty() {
        return None;
    }
    for len in (1..=segs.len()).rev() {
        let joined = segs[..len].join("/");
        let direct = join_rel(base_dir, &format!("{joined}.rs"));
        if file_set.contains(&direct) {
            return Some(direct);
        }
        let mod_file = join_rel(base_dir, &format!("{joined}/mod.rs"));
        if file_set.contains(&mod_file) {
            return Some(mod_file);
        }
    }
    None
}

fn expand_rust_use_paths(expr: &str) -> Vec<String> {
    let trimmed = expr.trim();
    let Some(open) = trimmed.find('{') else {
        return vec![trimmed.to_string()];
    };
    let Some(close) = trimmed.rfind('}') else {
        return vec![trimmed.to_string()];
    };
    if close <= open {
        return vec![trimmed.to_string()];
    }
    let prefix = trimmed[..open].trim();
    let inside = &trimmed[open + 1..close];
    let mut results = Vec::new();
    let mut depth = 0usize;
    let mut start = 0usize;

    for (idx, ch) in inside.char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => {
                let part = inside[start..idx].trim();
                if !part.is_empty() {
                    let combined = if part == "self" {
                        prefix.trim_end_matches("::").to_string()
                    } else {
                        format!("{prefix}{part}")
                    };
                    results.extend(expand_rust_use_paths(&combined));
                }
                start = idx + 1;
            }
            _ => {}
        }
    }
    let tail = inside[start..].trim();
    if !tail.is_empty() {
        let combined = if tail == "self" {
            prefix.trim_end_matches("::").to_string()
        } else {
            format!("{prefix}{tail}")
        };
        results.extend(expand_rust_use_paths(&combined));
    }

    if results.is_empty() {
        results.push(trimmed.to_string());
    }
    results
}

fn rust_crate_src_root(from_path: &str) -> &str {
    if let Some(idx) = from_path.find("/src/") {
        &from_path[..idx + 4]
    } else if from_path.starts_with("src/") {
        "src"
    } else {
        ""
    }
}

fn resolve_ts_js_import(
    from_path: &str,
    raw_to: &str,
    file_set: &BTreeSet<String>,
    out: &mut BTreeSet<String>,
) {
    let Some(spec_raw) = raw_to.strip_prefix("import:") else {
        return;
    };
    let spec = spec_raw.split(['?', '#']).next().unwrap_or(spec_raw).trim();
    if spec.is_empty() {
        return;
    }

    let base_candidate = if spec.starts_with("./") || spec.starts_with("../") {
        normalize_relative_join(parent_dir_str(from_path), spec)
    } else {
        spec.strip_prefix("@/")
            .or_else(|| spec.strip_prefix("~/"))
            .map(|rest| format!("src/{rest}"))
    };

    let Some(base) = base_candidate else {
        return;
    };

    if file_set.contains(&base) {
        out.insert(base);
        return;
    }

    let stem_base = strip_js_esm_ext(&base);

    const EXTS: &[&str] = &[
        ".ts", ".tsx", ".d.ts", ".js", ".jsx", ".mts", ".cts", ".mjs", ".cjs",
    ];
    for ext in EXTS {
        let cand = format!("{stem_base}{ext}");
        if file_set.contains(&cand) {
            out.insert(cand);
            return;
        }
    }

    const INDEXES: &[&str] = &[
        "/index.ts",
        "/index.tsx",
        "/index.d.ts",
        "/index.js",
        "/index.jsx",
    ];
    for idx_suffix in INDEXES {
        let cand = format!("{base}{idx_suffix}");
        if file_set.contains(&cand) {
            out.insert(cand);
            return;
        }
    }
}

fn strip_js_esm_ext(path: &str) -> &str {
    for ext in [".js", ".mjs", ".cjs", ".jsx"] {
        if let Some(stripped) = path.strip_suffix(ext) {
            return stripped;
        }
    }
    path
}

fn resolve_python_import(
    from_path: &str,
    raw_to: &str,
    file_set: &BTreeSet<String>,
    out: &mut BTreeSet<String>,
) {
    let Some(spec) = raw_to.strip_prefix("import:") else {
        return;
    };
    let spec = spec.trim();
    if spec.is_empty() {
        return;
    }

    let from_dir = parent_dir_str(from_path);
    if spec.starts_with('.') {
        let dots = spec.chars().take_while(|&c| c == '.').count();
        let rest = &spec[dots..];
        let base = ascend_dirs(from_dir, dots.saturating_sub(1));
        if rest.is_empty() {
            let init = join_rel(&base, "__init__.py");
            if file_set.contains(&init) {
                out.insert(init);
            }
            return;
        }
        let segs: Vec<&str> = rest.split('.').filter(|s| !s.is_empty()).collect();
        if let Some(found) = resolve_py_segments(&base, &segs, file_set) {
            out.insert(found);
        }
        return;
    }

    let segs: Vec<&str> = spec.split('.').filter(|s| !s.is_empty()).collect();
    if let Some(found) = resolve_py_segments("", &segs, file_set)
        .or_else(|| resolve_py_segments("src", &segs, file_set))
        .or_else(|| resolve_py_segments(from_dir, &segs, file_set))
    {
        out.insert(found);
    }
}

fn resolve_py_segments(
    base_dir: &str,
    segs: &[&str],
    file_set: &BTreeSet<String>,
) -> Option<String> {
    if segs.is_empty() {
        return None;
    }
    for len in (1..=segs.len()).rev() {
        let joined = segs[..len].join("/");
        let py = join_rel(base_dir, &format!("{joined}.py"));
        if file_set.contains(&py) {
            return Some(py);
        }
        let init = join_rel(base_dir, &format!("{joined}/__init__.py"));
        if file_set.contains(&init) {
            return Some(init);
        }
    }
    None
}

fn resolve_external_import(
    from_path: &str,
    raw_to: &str,
    file_set: &BTreeSet<String>,
    out: &mut BTreeSet<String>,
) {
    let Some(spec_raw) = raw_to.strip_prefix("import:") else {
        return;
    };
    let spec = spec_raw
        .trim()
        .trim_matches(|c| matches!(c, '"' | '\'' | '<' | '>'));
    if spec.is_empty() {
        return;
    }

    // 1. Direct relative path (e.g. `./helper.h`, `../common/types.hpp`, `helper.h`, Ruby `require_relative "foo"`).
    if let Some(joined) = normalize_relative_join(parent_dir_str(from_path), spec) {
        if file_set.contains(&joined) {
            out.insert(joined);
            return;
        }
        if let Some((_, from_ext)) = from_path.rsplit_once('.')
            && !joined.ends_with(&format!(".{from_ext}"))
        {
            let with_ext = format!("{joined}.{from_ext}");
            if file_set.contains(&with_ext) {
                out.insert(with_ext);
                return;
            }
        }
    }

    // 2. Exact workspace-relative path or suffix path match (e.g. `util/math.h` -> `include/util/math.h`,
    // PHP `App\Models\User` -> `src/App/Models/User.php`, Ruby `lib/invoice` -> `lib/invoice.rb`).
    let slash_spec = spec.replace('\\', "/");
    if file_set.contains(&slash_spec) {
        out.insert(slash_spec);
        return;
    }
    if let Some((_, from_ext)) = from_path.rsplit_once('.')
        && !slash_spec.ends_with(&format!(".{from_ext}"))
    {
        let with_ext = format!("{slash_spec}.{from_ext}");
        if file_set.contains(&with_ext) {
            out.insert(with_ext);
            return;
        }
    }
    if slash_spec.contains('/') {
        let suffix = format!("/{slash_spec}");
        let suffix_stem = format!("/{slash_spec}");
        for candidate in file_set {
            if candidate.ends_with(&suffix) {
                out.insert(candidate.clone());
                continue;
            }
            let without_ext = match candidate.rsplit_once('.') {
                Some((prefix, _)) => prefix,
                None => candidate.as_str(),
            };
            if without_ext == slash_spec || without_ext.ends_with(&suffix_stem) {
                out.insert(candidate.clone());
            }
        }
        if !out.is_empty() {
            return;
        }
    }

    // 3. Dotted package/class specifier (e.g. Java `com.acme.Item` -> `src/main/java/com/acme/Item.java`).
    if spec.contains('.') && !spec.ends_with(".*") && !spec.contains('/') {
        let stem_path = spec.replace('.', "/");
        let suffix_stem = format!("/{stem_path}");
        for candidate in file_set {
            let without_ext = match candidate.rsplit_once('.') {
                Some((prefix, _)) => prefix,
                None => candidate.as_str(),
            };
            if without_ext == stem_path || without_ext.ends_with(&suffix_stem) {
                out.insert(candidate.clone());
            }
        }
    }
}

fn parent_dir_str(rel: &str) -> &str {
    match rel.rsplit_once('/') {
        Some((dir, _)) => dir,
        None => "",
    }
}

fn file_stem_str(rel: &str) -> &str {
    let fname = rel.rsplit('/').next().unwrap_or(rel);
    match fname.rsplit_once('.') {
        Some((stem, _)) => stem,
        None => fname,
    }
}

fn join_rel(base: &str, child: &str) -> String {
    if base.is_empty() {
        child.to_string()
    } else if child.is_empty() {
        base.to_string()
    } else {
        format!("{base}/{child}")
    }
}

fn ascend_dirs(dir: &str, levels: usize) -> String {
    if dir.is_empty() || levels == 0 {
        return dir.to_string();
    }
    let parts: Vec<&str> = dir.split('/').filter(|s| !s.is_empty()).collect();
    if levels >= parts.len() {
        String::new()
    } else {
        parts[..parts.len() - levels].join("/")
    }
}

fn normalize_relative_join(base_dir: &str, rel_spec: &str) -> Option<String> {
    let mut parts: Vec<&str> = if base_dir.is_empty() {
        Vec::new()
    } else {
        base_dir.split('/').filter(|s| !s.is_empty()).collect()
    };
    for seg in rel_spec.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                parts.pop()?;
            }
            other => parts.push(other),
        }
    }
    let joined = parts.join("/");
    RelPath::normalize(&joined)
        .ok()
        .map(|r| r.as_str().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expand_rust_use_paths_handles_nested_braces() {
        let expanded = expand_rust_use_paths("crate::{a, b::{c, self}}");
        assert_eq!(expanded, vec!["crate::a", "crate::b::c", "crate::b"]);
    }
}
