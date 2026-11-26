//! Comprehensive unit & integration tests for the 5 build/tool filters:
//! `eslint`, `docker`, `make`, `gradle`, and `dotnet`.
//!
//! Verifies:
//! 1. `FilterRegistry::select` and `FilterRegistry::by_id` matching matrix (including
//!    critical `EslintFilter` before `NodePkgFilter` precedence).
//! 2. Clean-run noise compression with explicit `Omission` records and real token reduction.
//! 3. Constitution Article 4 (zero error loss): `exit_code != 0` multi-line ANSI-colored
//!    error outputs preserve 100% of diagnostics, stack traces, code frames, and summaries
//!    with `truncated_errors == false`, zero ANSI remnants, and deterministic output.

use klens_core::CommandFilter;
use klens_exec::{
    DockerFilter, DotnetFilter, EslintFilter, FilterRegistry, GradleFilter, MakeFilter,
    contains_ansi, strip_ansi,
};

fn args(items: &[&str]) -> Vec<String> {
    items.iter().map(|s| (*s).to_string()).collect()
}

// ---------------------------------------------------------------------------
// 1. FilterRegistry::select & by_id Matching Matrix
// ---------------------------------------------------------------------------

#[test]
fn registry_select_matches_eslint_before_node_and_preserves_node_commands() {
    let registry = FilterRegistry::with_defaults();

    // Must select "eslint"
    let eslint_cases: &[(&str, &[&str])] = &[
        ("eslint", &["src/"]),
        ("eslint.cmd", &["."]),
        (
            "C:\\repo\\node_modules\\.bin\\eslint.cmd",
            &["src/index.ts"],
        ),
        ("npx", &["eslint", "src/"]),
        ("npx.cmd", &["--no-install", "eslint", "src/"]),
        ("pnpm", &["eslint", "."]),
        ("pnpm", &["exec", "eslint", "."]),
        ("pnpm", &["dlx", "eslint", "."]),
        ("pnpm", &["--filter", "web", "exec", "eslint", "src/"]),
        ("yarn", &["eslint"]),
        ("yarn", &["dlx", "eslint", "."]),
        ("bunx", &["eslint", "src/"]),
        ("npm", &["exec", "--", "eslint", "."]),
        ("npm.cmd", &["exec", "--", "eslint", "src/"]),
    ];
    for (program, argv) in eslint_cases {
        let selected = registry.select(program, &args(argv));
        assert_eq!(
            selected.id(),
            "eslint",
            "expected `eslint` for `{program} {argv:?}`, got `{}`",
            selected.id()
        );
    }

    // Must STILL fall through to "node" (NEVER swallowed by EslintFilter)
    let node_cases: &[(&str, &[&str])] = &[
        ("npx", &["vitest"]),
        ("npx", &["vitest", "run", "tests/eslint.test.ts"]),
        ("pnpm", &["test"]),
        ("pnpm", &["build"]),
        ("npm", &["test"]),
        ("npm", &["run", "build"]),
        ("npm", &["run", "lint"]),
        ("yarn", &["test"]),
        ("tsc", &["--noEmit"]),
        ("vitest", &["run"]),
    ];
    for (program, argv) in node_cases {
        let selected = registry.select(program, &args(argv));
        assert_eq!(
            selected.id(),
            "node",
            "expected `node` for `{program} {argv:?}`, got `{}`",
            selected.id()
        );
    }
}

#[test]
fn registry_select_and_by_id_match_docker_make_gradle_dotnet() {
    let registry = FilterRegistry::with_defaults();

    let cases: &[(&str, &[&str], &str)] = &[
        ("docker", &["build", "."], "docker"),
        (
            "C:\\Program Files\\Docker\\docker.exe",
            &["compose", "up"],
            "docker",
        ),
        ("docker-compose", &["up", "-d"], "docker"),
        ("make", &["-j8"], "make"),
        ("mingw32-make", &["all"], "make"),
        ("mingw32-make.exe", &["clean"], "make"),
        ("gmake", &["check"], "make"),
        ("nmake.exe", &["/f", "Makefile.win"], "make"),
        ("./gradlew.bat", &["test"], "gradle"),
        (".\\gradlew.cmd", &["build"], "gradle"),
        ("gradlew", &["assembleDebug"], "gradle"),
        ("gradle", &["check"], "gradle"),
        ("dotnet.exe", &["test"], "dotnet"),
        ("dotnet", &["build", "--configuration", "Release"], "dotnet"),
    ];

    for (program, argv, expected_id) in cases {
        let selected = registry.select(program, &args(argv));
        assert_eq!(
            selected.id(),
            *expected_id,
            "expected `{expected_id}` for `{program} {argv:?}`, got `{}`",
            selected.id()
        );
    }

    for id in ["eslint", "docker", "make", "gradle", "dotnet"] {
        assert_eq!(
            registry.by_id(id).id(),
            id,
            "by_id({id:?}) must resolve directly to `{id}`"
        );
    }
}

// ---------------------------------------------------------------------------
// 2. EslintFilter Tests
// ---------------------------------------------------------------------------

#[test]
fn eslint_clean_run_compresses_noise_and_records_omission() {
    let mut stdout = String::from("> app@1.0.0 lint\n> eslint src/\nLinting 42 files...\n");
    for idx in 0..30 {
        stdout.push_str(&format!("✓ src/module_{idx}.ts (0 problems)\n"));
    }
    stdout.push_str("✔ No ESLint warnings or errors\nDone in 1.42s.\n");

    let res = EslintFilter.filter(&stdout, "", 0);
    assert_eq!(res.filter_id, "eslint");
    assert_eq!(res.exit_code, 0);
    assert!(!res.truncated_errors);
    assert!(
        res.omissions
            .iter()
            .any(|o| o.reason == "eslint_noise_omitted" && o.count >= 34),
        "expected eslint_noise_omitted omission, got: {:?}",
        res.omissions
    );
    assert!(
        res.est_filtered_tokens < res.est_raw_tokens,
        "expected token savings: raw={} filtered={}",
        res.est_raw_tokens,
        res.est_filtered_tokens
    );

    let res2 = EslintFilter.filter(&stdout, "", 0);
    assert_eq!(res, res2, "filter output must be deterministic");
}

#[test]
fn eslint_error_run_preserves_ansi_cleaned_diagnostics_and_fatal_blocks() {
    let raw_ansi_stdout = concat!(
        "Linting 12 files...\n",
        "✓ src/clean.ts (0 problems)\n",
        "\n",
        "\x1b[4m/workspace/src/auth/token.ts\x1b[24m\n",
        "  \x1b[2m14:7\x1b[22m   \x1b[31merror\x1b[39m    'secret' is assigned a value but never used  \x1b[2m@typescript-eslint/no-unused-vars\x1b[22m\n",
        "  \x1b[2m28:3\x1b[22m   \x1b[33mwarning\x1b[39m  Unexpected console statement                 \x1b[2mno-console\x1b[22m\n",
        "\n",
        "\x1b[4m/workspace/src/broken.ts\x1b[24m\n",
        "  \x1b[2m9:12\x1b[22m   \x1b[31merror\x1b[39m    Parsing error: Unexpected token }\n",
        "\n",
        "\x1b[31m\x1b[1m✖ 3 problems (2 errors, 1 warning)\x1b[22m\x1b[39m\n",
        "  1 error and 0 warnings potentially fixable with the `--fix` option.\n",
    );
    let raw_ansi_stderr = concat!(
        "\x1b[31mOops! Something went wrong! :(\x1b[39m\n",
        "ESLint: 9.15.0\n",
        "Error: Cannot find module '@eslint/js'\n",
        "    at Module._resolveFilename (node:internal/modules/cjs/loader:1145:15)\n",
    );

    let clean_out = strip_ansi(raw_ansi_stdout);
    let clean_err = strip_ansi(raw_ansi_stderr);
    let res = EslintFilter.filter(&clean_out, &clean_err, 2);

    assert!(!res.truncated_errors);
    assert!(!contains_ansi(&res.summary));
    assert_eq!(res.exit_code, 2);

    for must_keep in [
        "/workspace/src/auth/token.ts",
        "14:7   error    'secret' is assigned a value but never used  @typescript-eslint/no-unused-vars",
        "28:3   warning  Unexpected console statement                 no-console",
        "/workspace/src/broken.ts",
        "9:12   error    Parsing error: Unexpected token }",
        "✖ 3 problems (2 errors, 1 warning)",
        "1 error and 0 warnings potentially fixable with the `--fix` option.",
        "Oops! Something went wrong! :(",
        "ESLint: 9.15.0",
        "Error: Cannot find module '@eslint/js'",
        "at Module._resolveFilename (node:internal/modules/cjs/loader:1145:15)",
    ] {
        assert!(
            res.summary.contains(must_keep),
            "missing critical eslint line `{must_keep}` in:\n{}",
            res.summary
        );
    }

    assert!(
        res.omissions
            .iter()
            .any(|o| o.reason == "eslint_noise_omitted" && o.count == 2)
    );
    assert_eq!(res, EslintFilter.filter(&clean_out, &clean_err, 2));
}

// ---------------------------------------------------------------------------
// 3. DockerFilter Tests
// ---------------------------------------------------------------------------

#[test]
fn docker_clean_build_and_pull_compresses_layer_noise_keeps_image_summary() {
    let stderr = concat!(
        "#0 building with \"default\" instance using docker driver\n",
        "#1 [internal] load build definition from Dockerfile\n",
        "#1 transferring dockerfile: 412B done\n",
        "#1 DONE 0.0s\n",
        "#2 [internal] load metadata for docker.io/library/rust:1.88-slim\n",
        "#2 DONE 0.4s\n",
        "#3 [builder 1/5] FROM docker.io/library/rust:1.88-slim\n",
        "#3 sha256:9b5f1234567890abcdef 4.19MB / 12.50MB\n",
        "#3 CACHED\n",
        "#4 [builder 2/5] WORKDIR /app\n",
        "#4 CACHED\n",
        "#5 [builder 3/5] COPY . .\n",
        "#5 DONE 0.2s\n",
        "#6 exporting to image\n",
        "#6 exporting layers 0.3s done\n",
        "#6 writing image sha256:abcdef1234567890 done\n",
        "#6 naming to docker.io/library/klens-demo:latest done\n",
        "a1b2c3d4e5f6: Pulling fs layer\n",
        "a1b2c3d4e5f6: Waiting\n",
        "a1b2c3d4e5f6: Downloading [===>   ] 1.2MB/4.5MB\n",
        "a1b2c3d4e5f6: Verifying Checksum\n",
        "a1b2c3d4e5f6: Extracting [=====> ] 3.1MB/4.5MB\n",
        "a1b2c3d4e5f6: Pull complete\n",
        "f6e5d4c3b2a1: Already exists\n",
    );

    let res = DockerFilter.filter("", stderr, 0);
    assert_eq!(res.filter_id, "docker");
    assert!(!res.truncated_errors);
    assert!(
        res.summary
            .contains("naming to docker.io/library/klens-demo:latest done")
    );
    assert!(
        res.summary
            .contains("writing image sha256:abcdef1234567890 done")
    );
    assert!(!res.summary.contains("#3 CACHED"));
    assert!(!res.summary.contains("Verifying Checksum"));
    assert!(
        res.omissions
            .iter()
            .any(|o| o.reason == "docker_build_progress_omitted" && o.count >= 12)
    );
    assert!(
        res.omissions
            .iter()
            .any(|o| o.reason == "docker_layer_progress_omitted" && o.count == 7)
    );
    assert!(res.est_filtered_tokens < res.est_raw_tokens);
    assert_eq!(res, DockerFilter.filter("", stderr, 0));
}

#[test]
fn docker_failed_buildkit_run_preserves_entire_failed_step_and_solve_error() {
    let raw_ansi_stderr = concat!(
        "#1 [internal] load build definition from Dockerfile\n",
        "#1 DONE 0.0s\n",
        "#2 [builder 1/4] FROM docker.io/library/rust:1.88\n",
        "#2 CACHED\n",
        "#3 [builder 2/4] COPY Cargo.toml Cargo.lock ./\n",
        "#3 CACHED\n",
        "#4 [builder 3/4] RUN cargo build --release\n",
        "#4 0.412 \x1b[1;31merror[E0425]\x1b[0m: cannot find value `missing_var` in this scope\n",
        "#4 0.412  --> src/main.rs:19:9\n",
        "#4 0.412   |\n",
        "#4 0.412 19 |     let v = missing_var;\n",
        "#4 0.412   |             ^^^^^^^^^^^ not found in this scope\n",
        "#4 \x1b[31mERROR: process \"/bin/sh -c cargo build --release\" did not complete successfully: exit code: 101\x1b[0m\n",
        "------\n",
        " > [builder 3/4] RUN cargo build --release:\n",
        "0.412 error[E0425]: cannot find value `missing_var` in this scope\n",
        "------\n",
        "Dockerfile:14\n",
        "--------------------\n",
        "  12 |     WORKDIR /app\n",
        "  13 |     COPY . .\n",
        "  14 | >>> RUN cargo build --release\n",
        "--------------------\n",
        "\x1b[31mERROR: failed to solve: process \"/bin/sh -c cargo build --release\" did not complete successfully: exit code: 101\x1b[0m\n",
    );

    let clean = strip_ansi(raw_ansi_stderr);
    let res = DockerFilter.filter("", &clean, 1);

    assert!(!res.truncated_errors);
    assert!(!contains_ansi(&res.summary));
    assert_eq!(res.exit_code, 1);

    for must_keep in [
        "#4 [builder 3/4] RUN cargo build --release",
        "#4 0.412 error[E0425]: cannot find value `missing_var` in this scope",
        "#4 0.412 19 |     let v = missing_var;",
        "#4 ERROR: process \"/bin/sh -c cargo build --release\" did not complete successfully: exit code: 101",
        "Dockerfile:14",
        "  14 | >>> RUN cargo build --release",
        "ERROR: failed to solve: process \"/bin/sh -c cargo build --release\" did not complete successfully: exit code: 101",
    ] {
        assert!(
            res.summary.contains(must_keep),
            "missing critical docker error line `{must_keep}` in:\n{}",
            res.summary
        );
    }

    assert!(!res.summary.contains("#2 CACHED"));
    assert!(
        res.omissions
            .iter()
            .any(|o| o.reason == "docker_build_progress_omitted" && o.count >= 5)
    );
    assert_eq!(res, DockerFilter.filter("", &clean, 1));
}

// ---------------------------------------------------------------------------
// 4. MakeFilter Tests
// ---------------------------------------------------------------------------

#[test]
fn make_clean_build_compresses_dir_banners_and_compile_echoes() {
    let mut stdout = String::from(
        "make[1]: Entering directory '/workspace/src'\n\
         mkdir -p build/obj\n",
    );
    for idx in 0..20 {
        stdout.push_str(&format!(
            "gcc -O2 -Wall -c src/unit_{idx}.c -o build/obj/unit_{idx}.o\n"
        ));
    }
    stdout.push_str(
        "clang -O2 -o build/app build/obj/*.o\n\
         make[1]: Leaving directory '/workspace/src'\n\
         Build complete: build/app\n",
    );

    let res = MakeFilter.filter(&stdout, "", 0);
    assert_eq!(res.filter_id, "make");
    assert!(!res.truncated_errors);
    assert!(res.summary.contains("Build complete: build/app"));
    assert!(!res.summary.contains("Entering directory"));
    assert!(!res.summary.contains("gcc -O2 -Wall -c src/unit_0.c"));
    assert!(
        res.omissions
            .iter()
            .any(|o| o.reason == "make_directory_noise_omitted" && o.count == 2)
    );
    assert!(
        res.omissions
            .iter()
            .any(|o| o.reason == "make_compile_commands_omitted" && o.count == 22)
    );
    assert!(res.est_filtered_tokens < res.est_raw_tokens);
    assert_eq!(res, MakeFilter.filter(&stdout, "", 0));
}

#[test]
fn make_failed_build_preserves_compiler_caret_linker_and_stop_lines() {
    let raw_stdout = concat!(
        "make[1]: Entering directory '/workspace/core'\n",
        "mkdir -p build\n",
        "cc -c src/ok.c -o build/ok.o\n",
        "gcc -Wall -c src/parser.c -o build/parser.o\n",
    );
    let raw_ansi_stderr = concat!(
        "\x1b[1msrc/parser.c:42:15:\x1b[0m \x1b[1;31merror:\x1b[0m expected ';' before 'return'\n",
        "   42 |     int x = 1\n",
        "      |              \x1b[1;31m^\x1b[0m\n",
        "      |              ;\n",
        "   43 |     return x;\n",
        "\x1b[1msrc/parser.c:10:1:\x1b[0m \x1b[1;36mnote:\x1b[0m declared in function 'parse_expr'\n",
        "/usr/bin/ld: build/main.o: in function `main':\n",
        "main.c:(.text+0x15): undefined reference to `parse_expr'\n",
        "collect2: error: ld returned 1 exit status\n",
        "make[1]: *** [Makefile:28: build/parser.o] Error 1\n",
        "make[1]: Leaving directory '/workspace/core'\n",
        "make: *** [Makefile:12: all] Error 2\n",
        "Stop.\n",
    );

    let clean_out = strip_ansi(raw_stdout);
    let clean_err = strip_ansi(raw_ansi_stderr);
    let res = MakeFilter.filter(&clean_out, &clean_err, 2);

    assert!(!res.truncated_errors);
    assert!(!contains_ansi(&res.summary));
    assert_eq!(res.exit_code, 2);

    for must_keep in [
        "src/parser.c:42:15: error: expected ';' before 'return'",
        "   42 |     int x = 1",
        "      |              ^",
        "src/parser.c:10:1: note: declared in function 'parse_expr'",
        "main.c:(.text+0x15): undefined reference to `parse_expr'",
        "collect2: error: ld returned 1 exit status",
        "make[1]: *** [Makefile:28: build/parser.o] Error 1",
        "make: *** [Makefile:12: all] Error 2",
        "Stop.",
    ] {
        assert!(
            res.summary.contains(must_keep),
            "missing critical make/compiler error line `{must_keep}` in:\n{}",
            res.summary
        );
    }

    assert!(!res.summary.contains("cc -c src/ok.c"));
    assert!(
        res.omissions
            .iter()
            .any(|o| o.reason == "make_directory_noise_omitted" && o.count == 2)
    );
    assert_eq!(res, MakeFilter.filter(&clean_out, &clean_err, 2));
}

// ---------------------------------------------------------------------------
// 5. GradleFilter Tests
// ---------------------------------------------------------------------------

#[test]
fn gradle_clean_build_compresses_cached_tasks_and_downloads() {
    let stdout = concat!(
        "Downloading https://repo.maven.apache.org/maven2/org/jetbrains/kotlin/1.9.25/kotlin.jar\n",
        "Downloading https://repo.maven.apache.org/maven2/junit/junit/5.10.2/junit.jar\n",
        "> Task :core:compileKotlin UP-TO-DATE\n",
        "> Task :core:compileJava NO-SOURCE\n",
        "> Task :core:processResources UP-TO-DATE\n",
        "> Task :core:classes UP-TO-DATE\n",
        "> Task :core:jar FROM-CACHE\n",
        "> Task :app:compileKotlin FROM-CACHE\n",
        "> Task :app:compileJava NO-SOURCE\n",
        "> Task :app:test UP-TO-DATE\n",
        "\n",
        "BUILD SUCCESSFUL in 2s\n",
        "8 actionable tasks: 2 from cache, 6 up-to-date\n",
    );

    let res = GradleFilter.filter(stdout, "", 0);
    assert_eq!(res.filter_id, "gradle");
    assert!(!res.truncated_errors);
    assert!(res.summary.contains("BUILD SUCCESSFUL in 2s"));
    assert!(!res.summary.contains("UP-TO-DATE"));
    assert!(!res.summary.contains("FROM-CACHE"));
    assert!(!res.summary.contains("NO-SOURCE"));
    assert!(!res.summary.contains("Downloading https://"));
    assert!(
        res.omissions
            .iter()
            .any(|o| o.reason == "gradle_cached_tasks_omitted" && o.count == 8)
    );
    assert!(
        res.omissions
            .iter()
            .any(|o| o.reason == "gradle_download_progress_omitted" && o.count == 2)
    );
    assert!(res.est_filtered_tokens < res.est_raw_tokens);
    assert_eq!(res, GradleFilter.filter(stdout, "", 0));
}

#[test]
fn gradle_failed_build_preserves_kotlin_errors_stack_trace_and_failure_sections() {
    let raw_ansi_stdout = concat!(
        "> Task :core:compileKotlin UP-TO-DATE\n",
        "> Task :app:compileKotlin FAILED\n",
        "\x1b[31me: file:///workspace/app/src/main/kotlin/Auth.kt:27:13 Unresolved reference: verifyJwt\x1b[0m\n",
        "> Task :app:test FAILED\n",
        "com.example.AuthTest > rejectsExpiredToken() FAILED\n",
        "    org.opentest4j.AssertionFailedError: expected: <401> but was: <200>\n",
        "        at com.example.AuthTest.rejectsExpiredToken(AuthTest.kt:44)\n",
    );
    let raw_ansi_stderr = concat!(
        "\x1b[1;31mFAILURE: Build failed with an exception.\x1b[0m\n",
        "\n",
        "* Where:\n",
        "Build file '/workspace/app/build.gradle.kts' line: 42\n",
        "\n",
        "* What went wrong:\n",
        "Execution failed for task ':app:compileKotlin'.\n",
        "> A failure occurred while executing org.jetbrains.kotlin.compilerRunner.GradleCompilerRunnerWithWorkers\n",
        "\n",
        "* Try:\n",
        "> Run with --stacktrace option to get the stack trace.\n",
        "\n",
        "BUILD FAILED in 4s\n",
    );

    let clean_out = strip_ansi(raw_ansi_stdout);
    let clean_err = strip_ansi(raw_ansi_stderr);
    let res = GradleFilter.filter(&clean_out, &clean_err, 1);

    assert!(!res.truncated_errors);
    assert!(!contains_ansi(&res.summary));
    assert_eq!(res.exit_code, 1);

    for must_keep in [
        "> Task :app:compileKotlin FAILED",
        "e: file:///workspace/app/src/main/kotlin/Auth.kt:27:13 Unresolved reference: verifyJwt",
        "com.example.AuthTest > rejectsExpiredToken() FAILED",
        "org.opentest4j.AssertionFailedError: expected: <401> but was: <200>",
        "at com.example.AuthTest.rejectsExpiredToken(AuthTest.kt:44)",
        "FAILURE: Build failed with an exception.",
        "* Where:",
        "Build file '/workspace/app/build.gradle.kts' line: 42",
        "* What went wrong:",
        "Execution failed for task ':app:compileKotlin'.",
        "* Try:",
        "BUILD FAILED in 4s",
    ] {
        assert!(
            res.summary.contains(must_keep),
            "missing critical gradle error line `{must_keep}` in:\n{}",
            res.summary
        );
    }

    assert!(!res.summary.contains("UP-TO-DATE"));
    assert!(
        res.omissions
            .iter()
            .any(|o| o.reason == "gradle_cached_tasks_omitted" && o.count == 1)
    );
    assert_eq!(res, GradleFilter.filter(&clean_out, &clean_err, 1));
}

// ---------------------------------------------------------------------------
// 6. DotnetFilter Tests
// ---------------------------------------------------------------------------

#[test]
fn dotnet_clean_test_run_compresses_restore_and_passed_tests() {
    let mut stdout = String::from(
        "  Determining projects to restore...\n\
         All projects are up-to-date for restore.\n\
         Restored C:\\repo\\App.Tests\\App.Tests.csproj (in 142 ms).\n\
         Build succeeded.\n\
         Test run for C:\\repo\\App.Tests\\bin\\Debug\\net9.0\\App.Tests.dll\n",
    );
    for idx in 0..40 {
        stdout.push_str(&format!(
            "  Passed App.Tests.OrderServiceTests.Case_{idx} [12 ms]\n"
        ));
    }
    stdout.push_str(
        "\nPassed!  - Failed:     0, Passed:    40, Skipped:     0, Total:    40, Duration: 410 ms\n",
    );

    let res = DotnetFilter.filter(&stdout, "", 0);
    assert_eq!(res.filter_id, "dotnet");
    assert!(!res.truncated_errors);
    assert!(res.summary.contains("40 passed (omitted)"));
    assert!(res.summary.contains("Build succeeded."));
    assert!(
        res.summary
            .contains("Passed!  - Failed:     0, Passed:    40")
    );
    assert!(!res.summary.contains("Determining projects to restore"));
    assert!(!res.summary.contains("Case_0"));
    assert!(
        res.omissions
            .iter()
            .any(|o| o.reason == "dotnet_restore_noise_omitted" && o.count == 3)
    );
    assert!(
        res.omissions
            .iter()
            .any(|o| o.reason == "dotnet_passed_tests_omitted" && o.count == 40)
    );
    assert!(res.est_filtered_tokens < res.est_raw_tokens);
    assert_eq!(res, DotnetFilter.filter(&stdout, "", 0));
}

#[test]
fn dotnet_failed_build_and_test_preserves_cs_msb_diagnostics_and_stack_traces() {
    let raw_ansi_stdout = concat!(
        "  Determining projects to restore...\n",
        "  All projects are up-to-date for restore.\n",
        "\x1b[33msrc\\Auth.cs(12,9): warning CS0168: The variable 'unused' is declared but never used [C:\\repo\\App.csproj]\x1b[0m\n",
        "\x1b[31msrc\\Auth.cs(42,17): error CS0029: Cannot implicitly convert type 'string' to 'int' [C:\\repo\\App.csproj]\x1b[0m\n",
        "\x1b[31mC:\\Program Files\\dotnet\\sdk\\9.0\\Microsoft.Common.CurrentVersion.targets(4912,5): error MSB3021: Unable to copy file [C:\\repo\\App.csproj]\x1b[0m\n",
        "  Passed App.Tests.SmokeTests.StartsUp [5 ms]\n",
        "  \x1b[31mFailed App.Tests.AuthTests.ValidatesSignature [21 ms]\x1b[0m\n",
        "  Error Message:\n",
        "   Assert.Equal() Failure: Values differ\n",
        "   Expected: 200\n",
        "   Actual:   401\n",
        "  Stack Trace:\n",
        "     at App.Tests.AuthTests.ValidatesSignature() in C:\\repo\\App.Tests\\AuthTests.cs:line 38\n",
        "     at System.RuntimeMethodHandle.InvokeMethod(Object target, Void** arguments)\n",
        "\n",
        "Build FAILED.\n",
        "Failed!  - Failed:     1, Passed:     1, Skipped:     0, Total:     2, Duration: 26 ms\n",
    );

    let clean = strip_ansi(raw_ansi_stdout);
    let res = DotnetFilter.filter(&clean, "", 1);

    assert!(!res.truncated_errors);
    assert!(!contains_ansi(&res.summary));
    assert_eq!(res.exit_code, 1);

    for must_keep in [
        "src\\Auth.cs(12,9): warning CS0168: The variable 'unused' is declared but never used [C:\\repo\\App.csproj]",
        "src\\Auth.cs(42,17): error CS0029: Cannot implicitly convert type 'string' to 'int' [C:\\repo\\App.csproj]",
        "error MSB3021: Unable to copy file [C:\\repo\\App.csproj]",
        "Failed App.Tests.AuthTests.ValidatesSignature [21 ms]",
        "Error Message:",
        "Assert.Equal() Failure: Values differ",
        "Expected: 200",
        "Actual:   401",
        "Stack Trace:",
        "at App.Tests.AuthTests.ValidatesSignature() in C:\\repo\\App.Tests\\AuthTests.cs:line 38",
        "Build FAILED.",
        "Failed!  - Failed:     1, Passed:     1, Skipped:     0, Total:     2, Duration: 26 ms",
    ] {
        assert!(
            res.summary.contains(must_keep),
            "missing critical dotnet diagnostic/test line `{must_keep}` in:\n{}",
            res.summary
        );
    }

    assert!(!res.summary.contains("Determining projects to restore"));
    assert!(!res.summary.contains("SmokeTests.StartsUp"));
    assert!(
        res.omissions
            .iter()
            .any(|o| o.reason == "dotnet_restore_noise_omitted" && o.count == 2)
    );
    assert!(
        res.omissions
            .iter()
            .any(|o| o.reason == "dotnet_passed_tests_omitted" && o.count == 1)
    );
    assert_eq!(res, DotnetFilter.filter(&clean, "", 1));
}
