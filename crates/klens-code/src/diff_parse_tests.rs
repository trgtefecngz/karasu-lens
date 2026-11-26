//! Unified-diff parsing: every line inside a hunk is data, whatever it starts with.

use std::collections::BTreeMap;

use super::{ParsedFileDiff, parse_unified_diff};

fn parse(diff: &str) -> BTreeMap<String, ParsedFileDiff> {
    let mut out = BTreeMap::new();
    parse_unified_diff(diff, &mut out);
    out
}

fn added(diff: &str, path: &str) -> Vec<(usize, String)> {
    parse(diff)
        .get(path)
        .map(|f| f.added_lines.clone())
        .unwrap_or_default()
}

#[test]
fn added_lines_starting_with_plus_plus_are_still_data() {
    let diff = concat!(
        "diff --git a/src/a.rs b/src/a.rs\n",
        "--- a/src/a.rs\n",
        "+++ b/src/a.rs\n",
        "@@ -0,0 +1,3 @@\n",
        "+++x;\n",
        "+++ a:b\n",
        "+let k = \"secret\";\n",
    );
    assert_eq!(
        added(diff, "src/a.rs"),
        vec![
            (1, "++x;".to_string()),
            (2, "++ a:b".to_string()),
            (3, "let k = \"secret\";".to_string()),
        ]
    );
}

#[test]
fn fake_file_header_inside_a_hunk_does_not_switch_files() {
    let diff = concat!(
        "diff --git a/src/a.rs b/src/a.rs\n",
        "--- a/src/a.rs\n",
        "+++ b/src/a.rs\n",
        "@@ -1,0 +2,2 @@\n",
        "+++ b/other.rs\n",
        "+token();\n",
    );
    let parsed = parse(diff);
    assert!(!parsed.contains_key("other.rs"), "{:?}", parsed.keys());
    assert_eq!(
        added(diff, "src/a.rs"),
        vec![
            (2, "++ b/other.rs".to_string()),
            (3, "token();".to_string())
        ]
    );
}

#[test]
fn next_file_after_a_complete_hunk_is_still_recognised() {
    let diff = concat!(
        "diff --git a/a.rs b/a.rs\n",
        "--- a/a.rs\n",
        "+++ b/a.rs\n",
        "@@ -1 +1 @@\n",
        "-old\n",
        "+new\n",
        "\\ No newline at end of file\n",
        "diff --git a/b.rs b/b.rs\n",
        "--- a/b.rs\n",
        "+++ b/b.rs\n",
        "@@ -2,0 +3 @@\n",
        "+more\n",
    );
    assert_eq!(added(diff, "a.rs"), vec![(1, "new".to_string())]);
    assert_eq!(added(diff, "b.rs"), vec![(3, "more".to_string())]);
}
