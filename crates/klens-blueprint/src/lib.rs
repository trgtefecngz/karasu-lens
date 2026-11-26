#![deny(clippy::print_stdout)]
#![forbid(unsafe_code)]

//! Karasu Lens (`klens-blueprint`) — pure, isolated Blueprint board engine,
//! deterministic conflict checker, `USER_LOCKED` contract/task compiler,
//! non-destructive scaffold creator, and pure session handoff composer.
//!
//! Architectural isolation:
//! - Depends ONLY on `klens-core`, `serde`, `serde_json`, and `thiserror`.
//! - Zero coupling to `klens-code`, `klens-exec`, `klens-memory`, or `klens-adapters`.
//! - Zero LLM calls, zero network, zero `unsafe`, `#![deny(clippy::print_stdout)]`.

pub mod compile;
pub mod conflicts;
pub mod error;
pub mod format;
pub mod handoff;
pub mod model;
pub mod tasks;

pub use compile::{
    BlueprintStatusPayload, LockOptions, LockResult, ScaffoldReport, blueprint_status,
    check_blueprint, lock_and_execute, propose_blueprint, select_bubble_option,
};
pub use conflicts::{ConflictReport, check_conflicts};
pub use error::BlueprintError;
pub use format::{
    format_complete_task_text, format_conflicts_text, format_handoff_text, format_lock_text,
    format_next_task_text, format_status_text,
};
pub use handoff::{
    ContractSummary, DEFAULT_HANDOFF_BUDGET_TOKENS, FailedRunSummary, GitCommitSummary,
    GitStatusSummary, HandoffInput, HandoffPayload, MemoryEntrySummary, MemorySummary,
    compose_handoff, truncate_utf8_with_marker,
};
pub use model::{
    BLUEPRINT_DIR_REL, BLUEPRINT_JSON_REL, Blueprint, BlueprintBubble, BlueprintConflict,
    BlueprintOption, BlueprintTask, BubbleStatus, ConflictKind, ConflictSeverity,
    PROJECT_CONTRACT_REL, ScaffoldEntry, TASKS_JSONL_REL, TaskStatus, load_blueprint,
    load_blueprint_optional, load_contract_optional, load_tasks, load_tasks_optional,
    parse_tasks_jsonl, save_blueprint, save_tasks, serialize_tasks_jsonl, validate_identifier,
};
pub use tasks::{
    CompleteTaskResult, NextTaskPayload, complete_task, get_next_ready_task, next_ready_task,
    validate_task_graph,
};
