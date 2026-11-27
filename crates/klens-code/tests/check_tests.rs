use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use klens_code::{
    CheckFileStatus, CheckPayload, CheckTarget, CodeIndex, MAX_PROBLEMS_PER_FILE,
    SyntaxProblemKind, check_files, format_check_text,
};
use klens_core::{ProjectRoot, ProvenanceEnvelope, TrustLevel};

static CHECK_TEST_SEQ: AtomicU64 = AtomicU64::new(0);

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(label: &str) -> Self {
        let id = CHECK_TEST_SEQ.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("klens-check-{label}-{}-{id}", std::process::id()));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).unwrap();
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn write(&self, rel: &str, content: &str) {
        let full = self.path.join(rel);
        if let Some(p) = full.parent() {
            fs::create_dir_all(p).unwrap();
        }
        fs::write(full, content).unwrap();
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn run_git_checked(dir: &Path, args: &[&str]) {
    let mut cmd = Command::new("git");
    cmd.args(args).current_dir(dir);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x0800_0000);
    }
    let out = cmd.output().expect("git command failed to spawn");
    assert!(
        out.status.success(),
        "git {:?} failed: {}",
        args,
        String::from_utf8_lossy(&out.stderr)
    );
}

fn init_git_repo(dir: &Path) {
    run_git_checked(dir, &["init"]);
    run_git_checked(dir, &["config", "user.email", "test@klens.local"]);
    run_git_checked(dir, &["config", "user.name", "Klens Test"]);
    run_git_checked(dir, &["config", "core.autocrlf", "false"]);
}

fn run_check(
    proj: &TempDir,
    cache: &TempDir,
    target: CheckTarget,
) -> ProvenanceEnvelope<CheckPayload> {
    let root = ProjectRoot::new(proj.path()).unwrap();
    let mut index = CodeIndex::open_with_readonly_cache_dir(root, true, cache.path()).unwrap();
    check_files(&mut index, &target).unwrap()
}

fn paths(list: &[&str]) -> CheckTarget {
    CheckTarget::Paths(list.iter().map(|s| (*s).to_string()).collect())
}

fn file<'a>(env: &'a ProvenanceEnvelope<CheckPayload>, path: &str) -> &'a klens_code::CheckedFile {
    env.data
        .files
        .iter()
        .find(|f| f.path == path)
        .unwrap_or_else(|| panic!("no result for {path}: {:?}", env.data.files))
}

#[test]
fn clean_files_in_three_languages_report_ok_on_one_line() {
    let proj = TempDir::new("clean");
    let cache = TempDir::new("clean-cache");
    proj.write(
        "src/lib.rs",
        "pub fn add(a: i32, b: i32) -> i32 {\n    a + b\n}\n",
    );
    proj.write(
        "web/app.ts",
        "export function greet(n: string): string {\n  return `hi ${n}`;\n}\n",
    );
    proj.write("tool/main.py", "def run(x):\n    return x * 2\n");
    proj.write("conf/settings.json", "{\"a\": [1, 2]}\n");

    let env = run_check(
        &proj,
        &cache,
        paths(&[
            "src/lib.rs",
            "web/app.ts",
            "tool/main.py",
            "conf/settings.json",
        ]),
    );
    assert_eq!(env.trust, TrustLevel::VerifiedAst);
    assert_eq!(env.data.ok_files, 4);
    assert_eq!(env.data.error_files, 0);
    assert!(!env.data.has_syntax_errors());
    assert_eq!(format_check_text(&env), "OK 4 files [VERIFIED_AST]");
}

#[test]
fn broken_rust_typescript_and_python_are_located() {
    let proj = TempDir::new("broken");
    let cache = TempDir::new("broken-cache");
    proj.write(
        "src/lib.rs",
        "pub struct S;\n\nimpl S {\n    pub fn run(&self) -> i32 {\n        let x = (1 + ;\n        x\n    }\n}\n",
    );
    proj.write(
        "web/widget.ts",
        "export class Widget {\n  render(): number {\n    return [1, 2;\n  }\n}\n",
    );
    proj.write("tool/main.py", "def run(x:\n    return x\n");

    let env = run_check(
        &proj,
        &cache,
        paths(&["src/lib.rs", "web/widget.ts", "tool/main.py"]),
    );
    assert_eq!(env.trust, TrustLevel::VerifiedAst);
    assert_eq!(env.data.error_files, 3);
    assert_eq!(env.data.ok_files, 0);
    assert!(env.data.has_syntax_errors());

    let rs = file(&env, "src/lib.rs");
    assert_eq!(rs.status, CheckFileStatus::SyntaxErrors);
    assert_eq!(rs.language.as_deref(), Some("rust"));
    assert!(rs.problems.iter().any(|p| p.line == 5), "{:?}", rs.problems);
    let p = rs.problems.iter().find(|p| p.line == 5).unwrap();
    assert!(p.snippet.contains("let x = (1 + ;"), "{p:?}");
    assert!(
        p.symbol.as_deref().is_some_and(|s| s.contains("run")),
        "enclosing symbol should name `run`: {p:?}"
    );

    let ts = file(&env, "web/widget.ts");
    assert_eq!(ts.status, CheckFileStatus::SyntaxErrors);
    assert!(
        ts.problems.iter().all(|p| p.line >= 3 && p.line <= 5),
        "{:?}",
        ts.problems
    );

    let py = file(&env, "tool/main.py");
    assert_eq!(py.status, CheckFileStatus::SyntaxErrors);
    assert!(py.problems.iter().any(|p| p.line == 1), "{:?}", py.problems);

    let text = format_check_text(&env);
    assert!(text.contains("src/lib.rs:5:"), "{text}");
    assert!(text.lines().last().unwrap().starts_with("FAIL "), "{text}");
    assert!(text.ends_with("[VERIFIED_AST]"), "{text}");
}

#[test]
fn missing_token_is_reported_as_missing() {
    let proj = TempDir::new("missing");
    let cache = TempDir::new("missing-cache");
    proj.write("tool/main.py", "def run(:\n    return 1\n");
    let env = run_check(&proj, &cache, paths(&["tool/main.py"]));
    let py = file(&env, "tool/main.py");
    assert!(
        py.problems
            .iter()
            .any(|p| p.kind == SyntaxProblemKind::Missing && p.message.starts_with("missing `")),
        "{:?}",
        py.problems
    );
}

#[test]
fn unsupported_and_sensitive_files_are_never_reported_ok() {
    let proj = TempDir::new("unsupported");
    let cache = TempDir::new("unsupported-cache");
    proj.write("notes/data.xyz", "anything at all {{{\n");
    proj.write("README.md", "# Title\n");
    proj.write(".env", "API_KEY=abc\n");
    proj.write("src/ok.rs", "fn ok() {}\n");

    let env = run_check(
        &proj,
        &cache,
        paths(&[
            "notes/data.xyz",
            "README.md",
            ".env",
            "src/ok.rs",
            "src/gone.rs",
        ]),
    );
    assert_eq!(env.data.ok_files, 1);
    assert_eq!(env.data.error_files, 0);
    assert_eq!(env.data.not_checked_files, 4);
    // Weakest file decides the envelope: not everything could be checked.
    assert_eq!(env.trust, TrustLevel::UnparsedFallback);

    let xyz = file(&env, "notes/data.xyz");
    assert_eq!(xyz.status, CheckFileStatus::NotChecked);
    assert_eq!(xyz.trust, TrustLevel::UnparsedFallback);
    assert_eq!(file(&env, "README.md").status, CheckFileStatus::NotChecked);
    let secret = file(&env, ".env");
    assert_eq!(secret.status, CheckFileStatus::Skipped);
    assert!(secret.reason.as_deref().unwrap().contains("sensitive"));
    assert_eq!(file(&env, "src/gone.rs").status, CheckFileStatus::Skipped);

    let text = format_check_text(&env);
    assert!(
        text.contains("not checked (UNPARSED_FALLBACK, no built-in parser): notes/data.xyz"),
        "{text}"
    );
    assert!(
        text.ends_with("OK 1 file; 4 not checked [UNPARSED_FALLBACK]"),
        "{text}"
    );
}

#[test]
fn json_and_toml_errors_carry_line_and_column() {
    let proj = TempDir::new("docs");
    let cache = TempDir::new("docs-cache");
    proj.write("a.json", "{\n  \"a\": 1,,\n}\n");
    proj.write("b.toml", "[package]\nname = \n");

    let env = run_check(&proj, &cache, paths(&["a.json", "b.toml"]));
    let json = file(&env, "a.json");
    assert_eq!(json.status, CheckFileStatus::SyntaxErrors);
    assert_eq!(json.problems[0].line, 2);
    let toml = file(&env, "b.toml");
    assert_eq!(toml.status, CheckFileStatus::SyntaxErrors);
    assert_eq!(toml.problems[0].line, 2);
}

#[test]
fn many_errors_are_capped_and_counted() {
    let proj = TempDir::new("cap");
    let cache = TempDir::new("cap-cache");
    let mut src = String::new();
    for i in 0..40 {
        src.push_str(&format!("fn f{i}() {{ let x = (1 + ; }}\n"));
    }
    proj.write("src/many.rs", &src);

    let env = run_check(&proj, &cache, paths(&["src/many.rs"]));
    let f = file(&env, "src/many.rs");
    assert_eq!(f.problems.len(), MAX_PROBLEMS_PER_FILE);
    assert!(f.problems_total > MAX_PROBLEMS_PER_FILE);
    let text = format_check_text(&env);
    assert!(text.contains("more problems not listed"), "{text}");
}

#[test]
fn secrets_in_snippets_are_redacted() {
    let proj = TempDir::new("redact");
    let cache = TempDir::new("redact-cache");
    let token = format!("ghp_{}", "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8");
    proj.write(
        "src/lib.rs",
        &format!("fn f() {{ let t = \"{token}\" + ; }}\n"),
    );

    let env = run_check(&proj, &cache, paths(&["src/lib.rs"]));
    let text = format_check_text(&env);
    assert!(env.data.has_syntax_errors());
    assert!(!text.contains(&token), "{text}");
}

#[test]
fn diff_mode_checks_changed_files_and_staged_content() {
    let proj = TempDir::new("diff");
    let cache = TempDir::new("diff-cache");
    init_git_repo(proj.path());
    proj.write("src/a.rs", "fn a() {}\n");
    proj.write("src/untouched.rs", "fn untouched() {}\n");
    proj.write("src/removed.rs", "fn removed() {}\n");
    run_git_checked(proj.path(), &["add", "."]);
    run_git_checked(proj.path(), &["commit", "-m", "init"]);

    // Stage a clean edit, then break the working tree copy afterwards.
    proj.write("src/a.rs", "fn a() { let y = 2; }\n");
    run_git_checked(proj.path(), &["add", "src/a.rs"]);
    proj.write("src/a.rs", "fn a() { let y = (2 + ; }\n");
    // Untracked broken Python file and a deleted file.
    proj.write("tool/new.py", "def n(:\n    pass\n");
    run_git_checked(proj.path(), &["rm", "-q", "src/removed.rs"]);

    let env = run_check(&proj, &cache, CheckTarget::Diff { staged: false });
    assert_eq!(env.data.mode, "diff");
    let checked: Vec<&str> = env.data.files.iter().map(|f| f.path.as_str()).collect();
    assert_eq!(
        checked,
        vec!["src/a.rs", "tool/new.py"],
        "deleted and untouched files skipped"
    );
    assert_eq!(env.data.error_files, 2);

    let staged = run_check(&proj, &cache, CheckTarget::Diff { staged: true });
    assert_eq!(staged.data.mode, "diff:staged");
    let checked: Vec<&str> = staged.data.files.iter().map(|f| f.path.as_str()).collect();
    assert_eq!(checked, vec!["src/a.rs"], "only staged, non-deleted files");
    assert_eq!(
        staged.data.error_files, 0,
        "staged content is the clean edit"
    );
    assert_eq!(format_check_text(&staged), "OK 1 file [VERIFIED_AST]");
}

#[test]
fn diff_mode_outside_git_checks_nothing_honestly() {
    let proj = TempDir::new("nogit");
    let cache = TempDir::new("nogit-cache");
    proj.write("src/a.rs", "fn a() {}\n");
    let env = run_check(&proj, &cache, CheckTarget::Diff { staged: false });
    assert!(!env.data.is_git_repo);
    assert!(env.data.files.is_empty());
    assert_eq!(env.trust, TrustLevel::UnparsedFallback);
    let text = format_check_text(&env);
    assert!(text.contains("not a git repository"), "{text}");
    assert!(
        text.ends_with("NOTHING CHECKED [UNPARSED_FALLBACK]"),
        "{text}"
    );
}

#[test]
fn jsonc_config_files_are_not_false_alarms() {
    let proj = TempDir::new("jsonc");
    let cache = TempDir::new("jsonc-cache");
    proj.write(
        "tsconfig.json",
        "{\n  // generated by tsc --init\n  \"compilerOptions\": { \"strict\": true, },\n}\n",
    );
    proj.write(".vscode/settings.json", "{ /* editor */ \"a\": 1 }\n");
    proj.write("package.json", "{ // note\n  \"name\": \"x\"\n}\n");
    proj.write("web/tsconfig.app.json", "{\n  // c\n  \"a\": 1 2\n}\n");

    let env = run_check(
        &proj,
        &cache,
        paths(&[
            "tsconfig.json",
            ".vscode/settings.json",
            "package.json",
            "web/tsconfig.app.json",
        ]),
    );
    assert_eq!(file(&env, "tsconfig.json").status, CheckFileStatus::Ok);
    assert_eq!(
        file(&env, ".vscode/settings.json").status,
        CheckFileStatus::Ok
    );
    // Comments in a strict JSON file: honest "not checked", never OK and never a fake error.
    let pkg = file(&env, "package.json");
    assert_eq!(pkg.status, CheckFileStatus::NotChecked);
    assert_eq!(pkg.trust, TrustLevel::UnparsedFallback);
    // A real error in a JSONC file is still reported on its line.
    let broken = file(&env, "web/tsconfig.app.json");
    assert_eq!(broken.status, CheckFileStatus::SyntaxErrors);
    assert_eq!(broken.problems[0].line, 3);
}

#[test]
fn c_and_cpp_preprocessor_blocks_are_not_false_alarms() {
    let proj = TempDir::new("cpre");
    let cache = TempDir::new("cpre-cache");
    proj.write(
        "include/widget.h",
        "#pragma once\nnamespace app {\nclass Widget {\npublic:\n  template <typename T> T get() const;\n};\n}\n",
    );
    proj.write(
        "include/guard.h",
        "#ifndef X_H\n#define X_H\n#ifdef __cplusplus\nextern \"C\" {\n#endif\nint add(int a, int b);\n#ifdef __cplusplus\n}\n#endif\n#endif\n",
    );
    proj.write(
        "src/split.c",
        "int f(int x) {\n#if A\n  if (x) {\n#else\n  if (!x) {\n#endif\n    return 1;\n  }\n  return 0;\n}\n",
    );
    proj.write(
        "include/bug.h",
        "#ifndef B_H\n#define B_H\nint add(int a, int b)\nint sub(int a, int b);\n#endif\n",
    );
    proj.write("src/bug.c", "int f(void) {\n  return (1 + ;\n}\n");

    let env = run_check(
        &proj,
        &cache,
        paths(&[
            "include/widget.h",
            "include/guard.h",
            "src/split.c",
            "include/bug.h",
            "src/bug.c",
        ]),
    );
    let widget = file(&env, "include/widget.h");
    assert_eq!(
        widget.status,
        CheckFileStatus::Ok,
        "C++ header retried with C++"
    );
    assert_eq!(widget.language.as_deref(), Some("cpp"));
    assert_eq!(
        file(&env, "include/guard.h").status,
        CheckFileStatus::NotChecked
    );
    assert_eq!(
        file(&env, "src/split.c").status,
        CheckFileStatus::NotChecked
    );
    // Real errors, even inside a header guard, are still reported.
    assert_eq!(
        file(&env, "include/bug.h").status,
        CheckFileStatus::SyntaxErrors
    );
    let bug_c = file(&env, "src/bug.c");
    assert_eq!(bug_c.status, CheckFileStatus::SyntaxErrors);
    assert_eq!(bug_c.problems[0].line, 2);
}
