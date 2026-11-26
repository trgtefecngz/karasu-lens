use serde::de::{self, Deserializer};
use serde::{Deserialize, Serialize};

use crate::error::KlensError;

/// Current persistent JSON / MCP schema version.
pub const SCHEMA_VERSION: u32 = 1;

/// Provenance trust classification required on every structured output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TrustLevel {
    /// Read directly from a built-in, ABI-locked Tree-sitter grammar (or structured doc parser).
    VerifiedAst,
    /// Verified output from a user-enabled out-of-core `ext-lang-*` sidecar parser.
    ExternalParser,
    /// Provided verbatim from source file or raw terminal output.
    VerifiedRaw,
    /// Explicitly confirmed and locked by the user in the Blueprint board.
    UserLocked,
    /// Heuristic or identifier-based inference without full type verification.
    Inferred,
    /// Underlying source file BLAKE3 fingerprint changed since capture.
    Stale,
    /// Unsupported language or broken syntax; honest safe fallback used.
    UnparsedFallback,
}

/// Category of omitted content when budgeting or outlining shortens output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OmissionKind {
    Lines,
    Items,
    Symbols,
    Bytes,
}

/// Explicit record of omitted content (Constitution Article 2: No Silent Truncation).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Omission {
    pub kind: OmissionKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_line: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_line: Option<usize>,
    pub count: usize,
    pub reason: String,
}

impl Omission {
    /// Create a line-range omission marker.
    pub fn lines(
        path: impl Into<String>,
        start_line: usize,
        end_line: usize,
        reason: impl Into<String>,
    ) -> Self {
        let count = end_line.saturating_sub(start_line).saturating_add(1);
        Self {
            kind: OmissionKind::Lines,
            path: Some(path.into()),
            start_line: Some(start_line),
            end_line: Some(end_line),
            count,
            reason: reason.into(),
        }
    }

    /// Create an item-count omission marker.
    pub fn items(count: usize, reason: impl Into<String>) -> Self {
        Self {
            kind: OmissionKind::Items,
            path: None,
            start_line: None,
            end_line: None,
            count,
            reason: reason.into(),
        }
    }
}

/// Metadata describing an honest fallback to raw content or raw logs.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct RawFallback {
    pub reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,
}

fn deserialize_schema_version<'de, D>(deserializer: D) -> Result<u32, D::Error>
where
    D: Deserializer<'de>,
{
    let version = u32::deserialize(deserializer)?;
    if version != SCHEMA_VERSION {
        return Err(de::Error::custom(format!(
            "unsupported schema_version {version}; expected {SCHEMA_VERSION}"
        )));
    }
    Ok(version)
}

/// Standard provenance envelope wrapping all structured `klens` outputs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvenanceEnvelope<T> {
    #[serde(deserialize_with = "deserialize_schema_version")]
    pub schema_version: u32,
    pub trust: TrustLevel,
    pub project_id: String,
    pub warnings: Vec<String>,
    pub omissions: Vec<Omission>,
    pub redactions_count: usize,
    pub raw_fallback: Option<RawFallback>,
    pub data: T,
}

impl<T> ProvenanceEnvelope<T> {
    /// Construct a new envelope pinned to `SCHEMA_VERSION` (`1`).
    pub fn new(trust: TrustLevel, project_id: impl Into<String>, data: T) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            trust,
            project_id: project_id.into(),
            warnings: Vec::new(),
            omissions: Vec::new(),
            redactions_count: 0,
            raw_fallback: None,
            data,
        }
    }

    /// Attach a warning message.
    pub fn with_warning(mut self, warning: impl Into<String>) -> Self {
        self.warnings.push(warning.into());
        self
    }

    /// Attach an explicit omission record.
    pub fn with_omission(mut self, omission: Omission) -> Self {
        self.omissions.push(omission);
        self
    }

    /// Record the number of secret redactions applied to the payload.
    pub fn with_redactions_count(mut self, count: usize) -> Self {
        self.redactions_count = count;
        self
    }

    /// Attach raw fallback metadata.
    pub fn with_raw_fallback(mut self, fallback: RawFallback) -> Self {
        self.raw_fallback = Some(fallback);
        self
    }

    /// Validate envelope invariants (`schema_version == 1`).
    pub fn validate(&self) -> Result<(), KlensError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(KlensError::InvalidSchemaVersion {
                expected: SCHEMA_VERSION,
                found: self.schema_version,
            });
        }
        Ok(())
    }

    /// Serialize to compact, byte-for-byte deterministic JSON.
    ///
    /// Converts through `serde_json::Value` and sorts every object's keys
    /// lexicographically, so the output is deterministic even if `T` contains
    /// unordered maps. (`serde_json`'s `preserve_order` feature is enabled in this
    /// workspace, so `Value` alone would keep insertion order.)
    pub fn to_deterministic_json(&self) -> Result<String, KlensError>
    where
        T: Serialize,
    {
        Ok(serde_json::to_string(&self.sorted_value()?)?)
    }

    /// Serialize to pretty-printed, byte-for-byte deterministic JSON.
    pub fn to_deterministic_json_pretty(&self) -> Result<String, KlensError>
    where
        T: Serialize,
    {
        Ok(serde_json::to_string_pretty(&self.sorted_value()?)?)
    }

    fn sorted_value(&self) -> Result<serde_json::Value, KlensError>
    where
        T: Serialize,
    {
        self.validate()?;
        let mut value = serde_json::to_value(self)?;
        value.sort_all_objects();
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    #[test]
    fn trust_level_serializes_to_constitutional_names() {
        let cases = [
            (TrustLevel::VerifiedAst, "\"VERIFIED_AST\""),
            (TrustLevel::ExternalParser, "\"EXTERNAL_PARSER\""),
            (TrustLevel::VerifiedRaw, "\"VERIFIED_RAW\""),
            (TrustLevel::UserLocked, "\"USER_LOCKED\""),
            (TrustLevel::Inferred, "\"INFERRED\""),
            (TrustLevel::Stale, "\"STALE\""),
            (TrustLevel::UnparsedFallback, "\"UNPARSED_FALLBACK\""),
        ];
        for (variant, expected) in cases {
            assert_eq!(serde_json::to_string(&variant).unwrap(), expected);
        }
    }

    #[test]
    fn envelope_serialization_is_byte_for_byte_deterministic() {
        let mut map = HashMap::new();
        map.insert("zeta".to_string(), 1);
        map.insert("alpha".to_string(), 2);
        map.insert("middle".to_string(), 3);

        let env = ProvenanceEnvelope::new(TrustLevel::VerifiedAst, "proj-1234", map)
            .with_warning("example warning")
            .with_omission(Omission::lines(
                "src/main.rs",
                54,
                95,
                "outline_body_omitted",
            ))
            .with_redactions_count(1);

        let first = env.to_deterministic_json().unwrap();
        let second = env.to_deterministic_json().unwrap();
        assert_eq!(first, second);
        assert_eq!(first.as_bytes(), second.as_bytes());

        let parsed: serde_json::Value = serde_json::from_str(&first).unwrap();
        assert_eq!(parsed["schema_version"], 1);
        assert_eq!(parsed["trust"], "VERIFIED_AST");
        assert_eq!(parsed["redactions_count"], 1);
        assert_eq!(parsed["omissions"][0]["count"], 42);
    }

    #[test]
    fn envelope_json_keys_are_sorted_regardless_of_payload_insertion_order() {
        let mut payload = serde_json::Map::new();
        payload.insert("zeta".to_string(), serde_json::json!({"z": 1, "a": 2}));
        payload.insert("alpha".to_string(), serde_json::json!(2));
        let env = ProvenanceEnvelope::new(TrustLevel::VerifiedAst, "proj-1", payload);

        let compact = env.to_deterministic_json().unwrap();
        let pretty = env.to_deterministic_json_pretty().unwrap();
        for json in [&compact, &pretty] {
            let pos = |needle: &str| json.find(needle).unwrap();
            assert!(pos("\"alpha\"") < pos("\"zeta\""), "{json}");
            assert!(pos("\"a\"") < pos("\"z\""), "{json}");
            assert!(pos("\"data\"") < pos("\"trust\""), "{json}");
        }
    }

    #[test]
    fn envelope_rejects_wrong_schema_version_on_serialize_and_deserialize() {
        let mut env = ProvenanceEnvelope::new(TrustLevel::VerifiedRaw, "proj-1", "ok");
        env.schema_version = 2;
        assert!(matches!(
            env.to_deterministic_json(),
            Err(KlensError::InvalidSchemaVersion {
                expected: 1,
                found: 2
            })
        ));

        let bad_json = r#"{
            "schema_version": 99,
            "trust": "VERIFIED_RAW",
            "project_id": "proj-1",
            "warnings": [],
            "omissions": [],
            "redactions_count": 0,
            "raw_fallback": null,
            "data": "hello"
        }"#;
        let parsed: Result<ProvenanceEnvelope<String>, _> = serde_json::from_str(bad_json);
        assert!(parsed.is_err());
    }

    #[test]
    fn envelope_roundtrip_preserves_schema_version_one() {
        let env =
            ProvenanceEnvelope::new(TrustLevel::UnparsedFallback, "abc123", "raw".to_string())
                .with_raw_fallback(RawFallback {
                    reason: "unsupported extension".into(),
                    path: Some("notes.xyz".into()),
                    hint: Some("read raw range".into()),
                });
        let json = env.to_deterministic_json().unwrap();
        let roundtrip: ProvenanceEnvelope<String> = serde_json::from_str(&json).unwrap();
        assert_eq!(roundtrip.schema_version, 1);
        assert_eq!(roundtrip, env);
    }
}
