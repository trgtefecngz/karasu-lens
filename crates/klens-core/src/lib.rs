#![deny(clippy::print_stdout)]
#![forbid(unsafe_code)]

//! Core foundation for Karasu Lens (`klens`).
//!
//! Provides provenance envelopes, project-root path confinement,
//! secret redaction, CRLF-normalized BLAKE3 hashing, deterministic
//! token budgeting, configuration models, and pluggable trait contracts.

pub mod budget;
pub mod config;
pub mod envelope;
pub mod error;
pub mod ext_manifest;
pub mod extensions;
pub mod git;
pub mod hash;
mod input_path;
mod links;
pub mod paths;
pub mod redact;
pub mod root_guard;
pub mod sensitive;
pub mod telemetry;
pub mod time;
pub mod traits;

pub use budget::{CHARS_PER_TOKEN, TokenBudget, estimate_tokens, estimate_tokens_from_bytes};
pub use config::{
    GlobalConfig, ProjectConfig, ProjectMode, RegisteredProject, SUPPORTED_UI_LANGS,
    describe_toml_error, is_supported_ui_lang,
};
pub use envelope::{
    Omission, OmissionKind, ProvenanceEnvelope, RawFallback, SCHEMA_VERSION, TrustLevel,
};
pub use error::{KlensError, PathError};
pub use ext_manifest::{
    CTAGS_EXTENSION_ID, DEFAULT_CTAGS_EXTENSIONS, DEFAULT_MAX_FILE_BYTES, DEFAULT_TIMEOUT_MS,
    DiscoveredLanguageManifest, EXTENSION_MANIFEST_FILE, ExtensionHealthStatus, ExtensionKind,
    InvalidLanguageManifest, LANGUAGE_PARSER_KIND, LanguageExtensionManifest,
    LanguageManifestDiscovery, MAX_ALLOWED_FILE_BYTES, MAX_FRAME_BYTES, MAX_MANIFEST_ARGS,
    MAX_TIMEOUT_MS, MIN_FRAME_BYTES, MIN_TIMEOUT_MS, ManifestOrigin,
    SUPPORTED_SIDECAR_PROTOCOL_VERSION, discover_language_manifests,
    global_extensions_dir_from_config, is_valid_extension_token, is_valid_language_extension_id,
    is_valid_semver, parse_and_validate_language_manifest,
};
pub use extensions::{
    ExtensionListReport, ExtensionScope, ExtensionSpec, ExtensionStatusEntry,
    ExtensionToggleReport, ExtensionTransport, find_known_extension, format_extension_list_text,
    format_extension_toggle_text, known_extensions, list_extensions, set_extension_enabled,
    validate_extension_id,
};
pub use git::git_command;
pub use hash::{
    blake3_file, blake3_normalized_bytes, blake3_parse_cache_key, blake3_raw_bytes, blake3_text,
    normalize_line_endings,
};
pub use links::first_linked_component;
pub use paths::{
    ProjectRoot, RelPath, is_network_or_device_path, is_plain_local_absolute, is_sensitive_path,
    write_atomic, write_atomic_private, write_atomic_with_mode_of,
};
pub use redact::{
    RedactionResult, SecretKind, private_key_line_spans, redact_secrets, redact_secrets_by_line,
};
pub use root_guard::{is_unsafe_project_root, unsafe_project_root_reason};
pub use traits::{
    AdapterContext, CheckSeverity, CodeEdge, CommandFilter, DoctorCheck, EdgeConfidence,
    EdgeRelation, ExtensionSlot, FileSymbols, FilteredRun, HostAdapter, HostDetectStatus,
    InstallReport, LanguageAnalyzer, ParseOutcome, SymbolInfo, SymbolKind,
};
