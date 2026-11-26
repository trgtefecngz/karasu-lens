//! Deterministic human-readable text formatters for all Phase 3B adapter & lifecycle commands.

use std::fmt::Write as _;

use klens_core::{CheckSeverity, HostDetectStatus, InstallReport};

use crate::adapters::clean_binary_path_string;
use crate::doctor::{DetectReport, DoctorReport};
use crate::lifecycle::{
    AttachReport, DetachReport, DisconnectReport, InitReport, ScanReport, UninstallReport,
};

fn fmt_path(path: &std::path::Path) -> String {
    clean_binary_path_string(path)
}

pub fn format_detect_text(report: &DetectReport) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "Karasu Lens — Environment Detection (read-only)");
    let _ = writeln!(
        out,
        "Project: {} (id: {})",
        fmt_path(&report.project_root),
        report.project_id
    );
    let reg_label = if report.project_registered {
        "registered in ~/.klens/config.toml"
    } else {
        "not attached"
    };
    let mode_label = report
        .project_mode
        .map_or_else(|| "default(active)".to_string(), |m| format!("{m:?}"));
    let _ = writeln!(out, "Status : {reg_label} | mode={mode_label}");

    let _ = writeln!(out, "\nHosts:");
    for row in &report.hosts {
        let status_str = match &row.status {
            HostDetectStatus::NotDetected => "not detected".to_string(),
            HostDetectStatus::Detected { config_path } => {
                format!("detected ({})", fmt_path(config_path))
            }
            HostDetectStatus::Installed { config_path } => {
                format!("installed ({})", fmt_path(config_path))
            }
        };
        let _ = writeln!(out, "  - {:<12} : {status_str}", row.display_name);
    }

    if !report.universal_hints.is_empty() {
        let _ = writeln!(
            out,
            "  - Universal hints: {}",
            report.universal_hints.join(", ")
        );
    }

    let _ = writeln!(out, "\nConfigured Access (Layer 1):");
    if report.configured_access.is_empty() {
        let _ = writeln!(out, "  (none — run `klens init` to connect an AI host)");
    } else {
        for entry in &report.configured_access {
            let bin_note = match entry.binary_matches_current {
                Some(true) => " [binary: OK]",
                Some(false) => " [binary: STALE]",
                None => "",
            };
            let _ = writeln!(
                out,
                "  - {} -> {}{bin_note}",
                entry.scope_label,
                fmt_path(&entry.config_path)
            );
        }
    }

    let _ = writeln!(out, "\nObserved Access (Layer 2 — ~/.klens/metrics.jsonl):");
    if report.observed_access.is_empty() {
        let _ = writeln!(out, "  (no MCP tool calls observed for this project yet)");
    } else {
        for obs in &report.observed_access {
            let ver = if obs.client_version.is_empty() {
                String::new()
            } else {
                format!(" v{}", obs.client_version)
            };
            let _ = writeln!(
                out,
                "  - {}{} : {} call(s), last seen {}",
                obs.client_name, ver, obs.tool_calls, obs.last_seen_utc
            );
        }
    }

    out.trim_end().to_string()
}

pub fn format_scan_text(report: &ScanReport) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "Karasu Lens — Workspace Scan (read-only, depth={})",
        report.max_depth
    );
    let _ = writeln!(out, "Root: {}", fmt_path(&report.root_dir));
    if report.projects.is_empty() {
        let _ = writeln!(out, "No projects discovered (zero files modified).");
    } else {
        let _ = writeln!(out, "\nDiscovered {} project(s):", report.projects.len());
        for p in &report.projects {
            let attach_tag = if p.registered_globally {
                "attached"
            } else if p.has_klens_dir {
                "local-.klens"
            } else {
                "unattached"
            };
            let _ = writeln!(
                out,
                "  - {} [{}] ({}) -> {}",
                p.name,
                attach_tag,
                p.markers.join(", "),
                fmt_path(&p.path)
            );
        }
    }
    out.trim_end().to_string()
}

pub fn format_init_text(report: &InitReport) -> String {
    let mut out = String::new();
    let dry = if report.dry_run { " [DRY-RUN]" } else { "" };
    let _ = writeln!(out, "Karasu Lens — Init{dry}");
    let _ = writeln!(out, "Binary: {}", fmt_path(&report.binary_path));
    for rep in &report.reports {
        format_install_report(&mut out, rep);
    }
    out.trim_end().to_string()
}

pub fn format_attach_text(report: &AttachReport) -> String {
    let mut out = String::new();
    let dry = if report.dry_run { " [DRY-RUN]" } else { "" };
    let _ = writeln!(out, "Karasu Lens — Attach{dry}");
    let _ = writeln!(
        out,
        "Project: {} ({}, mode={:?})",
        report.project_name,
        fmt_path(&report.project_root),
        report.mode
    );
    if report.notes.is_empty() {
        let _ = writeln!(out, "Already attached and up-to-date.");
    } else {
        for note in &report.notes {
            let _ = writeln!(out, "  - {note}");
        }
    }
    out.trim_end().to_string()
}

pub fn format_detach_text(report: &DetachReport) -> String {
    let mut out = String::new();
    let dry = if report.dry_run { " [DRY-RUN]" } else { "" };
    let purge = if report.purge { " [PURGE]" } else { "" };
    let _ = writeln!(out, "Karasu Lens — Detach{purge}{dry}");
    let _ = writeln!(out, "Project: {}", fmt_path(&report.project_root));
    if report.notes.is_empty() {
        let _ = writeln!(out, "Nothing to detach (project already clean).");
    } else {
        for note in &report.notes {
            let _ = writeln!(out, "  - {note}");
        }
    }
    if !report.preserved.is_empty() {
        let _ = writeln!(out, "Preserved:");
        for path in &report.preserved {
            let _ = writeln!(out, "  - {}", fmt_path(path));
        }
    }
    out.trim_end().to_string()
}

pub fn format_disconnect_text(report: &DisconnectReport) -> String {
    let mut out = String::new();
    let dry = if report.dry_run { " [DRY-RUN]" } else { "" };
    let _ = writeln!(out, "Karasu Lens — Disconnect{dry}");
    for rep in &report.reports {
        format_install_report(&mut out, rep);
    }
    out.trim_end().to_string()
}

pub fn format_uninstall_text(report: &UninstallReport) -> String {
    let mut out = String::new();
    let dry = if report.dry_run { " [DRY-RUN]" } else { "" };
    let _ = writeln!(out, "Karasu Lens — Uninstall All{dry}");
    for rep in &report.host_reports {
        format_install_report(&mut out, rep);
    }
    for note in &report.notes {
        let _ = writeln!(out, "  - {note}");
    }
    out.trim_end().to_string()
}

pub fn format_doctor_text(report: &DoctorReport) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "Karasu Lens — Doctor [{}]",
        severity_tag(report.overall)
    );
    let _ = writeln!(
        out,
        "Project: {} (id: {})",
        fmt_path(&report.project_root),
        report.project_id
    );
    let _ = writeln!(out, "Binary : {}", fmt_path(&report.binary_path));

    let _ = writeln!(out, "\nChecks:");
    for check in &report.checks {
        let _ = writeln!(
            out,
            "  [{}] {}: {}",
            severity_tag(check.severity),
            check.name,
            check.message
        );
    }

    let _ = writeln!(out, "\nConfigured Access:");
    if report.configured_access.is_empty() {
        let _ = writeln!(out, "  (none)");
    } else {
        for entry in &report.configured_access {
            let _ = writeln!(
                out,
                "  - {} ({})",
                entry.scope_label,
                fmt_path(&entry.config_path)
            );
        }
    }

    let _ = writeln!(out, "\nObserved Access:");
    if report.observed_access.is_empty() {
        let _ = writeln!(out, "  (none)");
    } else {
        for obs in &report.observed_access {
            let _ = writeln!(
                out,
                "  - {} ({} calls, last seen {})",
                obs.client_name, obs.tool_calls, obs.last_seen_utc
            );
        }
    }

    out.trim_end().to_string()
}

fn format_install_report(out: &mut String, rep: &InstallReport) {
    let status = if rep.dry_run {
        if rep.files_touched.is_empty() {
            "no changes"
        } else {
            "planned"
        }
    } else if rep.changed {
        "updated"
    } else {
        "unchanged"
    };
    let _ = writeln!(out, "\n[{}] ({status})", rep.host_id);
    if rep.notes.is_empty() {
        let _ = writeln!(out, "  - no klens entries found");
    } else {
        for note in &rep.notes {
            let _ = writeln!(out, "  - {note}");
        }
    }
}

const fn severity_tag(sev: CheckSeverity) -> &'static str {
    match sev {
        CheckSeverity::Ok => "OK",
        CheckSeverity::Warning => "WARN",
        CheckSeverity::Error => "ERR",
    }
}
