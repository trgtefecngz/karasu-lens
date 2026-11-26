//! Leaf HTTP response and fail-closed request/query parsing helpers for `klens-ui`.

use std::collections::BTreeMap;
use std::io::Read;

use klens_memory::AnchorSpec;
use serde::Serialize;
use serde_json::{Value, json};
use tiny_http::Request;

use crate::error::UiError;

/// Maximum accepted HTTP JSON request body size (2 MiB).
pub const MAX_REQUEST_BODY_BYTES: usize = 2 * 1024 * 1024;

/// HTTP response returned by route handlers and written by the server loop.
#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status: u16,
    pub content_type: &'static str,
    pub body: Vec<u8>,
    pub extra_headers: Vec<(String, String)>,
}

impl HttpResponse {
    /// Build a `200 OK` JSON response.
    pub fn json_ok<T: Serialize>(payload: &T) -> Result<Self, UiError> {
        Self::json_status(200, payload)
    }

    /// Build a JSON response with an explicit HTTP status code.
    pub fn json_status<T: Serialize>(status: u16, payload: &T) -> Result<Self, UiError> {
        let body = serde_json::to_vec(payload)?;
        Ok(Self {
            status,
            content_type: "application/json; charset=utf-8",
            body,
            extra_headers: vec![("Cache-Control".to_string(), "no-store".to_string())],
        })
    }

    /// Build a structured JSON error response from [`UiError`].
    pub fn from_error(err: &UiError) -> Self {
        let (status, code) = err.http_status();
        let body = serde_json::to_vec(&json!({
            "error": code,
            "message": err.to_string(),
        }))
        .unwrap_or_else(|_| {
            b"{\"error\":\"internal_error\",\"message\":\"serialization error\"}".to_vec()
        });
        Self {
            status,
            content_type: "application/json; charset=utf-8",
            body,
            extra_headers: vec![("Cache-Control".to_string(), "no-store".to_string())],
        }
    }

    /// Build a static asset response (`index.html`, `style.css`, `app.js`, `i18n/*.json`).
    pub fn static_asset(content_type: &'static str, body: &str) -> Self {
        Self {
            status: 200,
            content_type,
            body: body.as_bytes().to_vec(),
            extra_headers: vec![("Cache-Control".to_string(), "no-cache".to_string())],
        }
    }

    /// Build a `302 Found` redirect that sets the `HttpOnly; SameSite=Strict; Path=/` session cookie.
    pub fn redirect_with_cookie(location: &str, cookie_header: String) -> Self {
        Self {
            status: 302,
            content_type: "text/plain; charset=utf-8",
            body: Vec::new(),
            extra_headers: vec![
                ("Location".to_string(), location.to_string()),
                ("Set-Cookie".to_string(), cookie_header),
                ("Cache-Control".to_string(), "no-store".to_string()),
            ],
        }
    }
}

/// Fail-closed JSON request body reader (bounded to [`MAX_REQUEST_BODY_BYTES`]).
///
/// If `allow_empty_object` is `true`, an empty request body returns `{}`.
pub fn read_json_body(request: &mut Request, allow_empty_object: bool) -> Result<Value, UiError> {
    let mut raw = Vec::new();
    let reader = request.as_reader();
    let mut limited = reader.take((MAX_REQUEST_BODY_BYTES + 1) as u64);
    limited.read_to_end(&mut raw)?;
    if raw.len() > MAX_REQUEST_BODY_BYTES {
        return Err(UiError::BadRequest(format!(
            "request body exceeds limit of {MAX_REQUEST_BODY_BYTES} bytes"
        )));
    }
    if raw.is_empty() {
        return if allow_empty_object {
            Ok(Value::Object(serde_json::Map::new()))
        } else {
            Err(UiError::BadRequest("JSON request body is required".into()))
        };
    }
    let val: Value = serde_json::from_slice(&raw)
        .map_err(|e| UiError::BadRequest(format!("invalid JSON body: {e}")))?;
    if !val.is_object() {
        return Err(UiError::BadRequest(
            "JSON request body must be a JSON object".into(),
        ));
    }
    Ok(val)
}

/// Require a non-empty string field from a JSON object (fail-closed).
pub fn json_req_str<'a>(obj: &'a Value, field: &str) -> Result<&'a str, UiError> {
    match obj.get(field) {
        Some(Value::String(s)) => {
            let trimmed = s.trim();
            if trimmed.is_empty() {
                Err(UiError::BadRequest(format!(
                    "`{field}` must be a non-empty string"
                )))
            } else {
                Ok(trimmed)
            }
        }
        Some(_) => Err(UiError::BadRequest(format!("`{field}` must be a string"))),
        None => Err(UiError::BadRequest(format!("`{field}` is required"))),
    }
}

/// Read an optional string field (allows empty string if `allow_empty == true`; rejects non-strings).
pub fn json_opt_str(
    obj: &Value,
    field: &str,
    allow_empty: bool,
) -> Result<Option<String>, UiError> {
    match obj.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => {
            if allow_empty {
                Ok(Some(s.clone()))
            } else {
                let trimmed = s.trim();
                if trimmed.is_empty() {
                    Ok(None)
                } else {
                    Ok(Some(trimmed.to_string()))
                }
            }
        }
        Some(_) => Err(UiError::BadRequest(format!("`{field}` must be a string"))),
    }
}

/// Require a boolean field from a JSON object (fail-closed: rejects missing, null, strings, numbers).
pub fn json_req_bool(obj: &Value, field: &str) -> Result<bool, UiError> {
    match obj.get(field) {
        Some(Value::Bool(b)) => Ok(*b),
        Some(_) => Err(UiError::BadRequest(format!("`{field}` must be a boolean"))),
        None => Err(UiError::BadRequest(format!("`{field}` is required"))),
    }
}

/// Read an optional boolean field (rejects non-booleans).
pub fn json_opt_bool(obj: &Value, field: &str) -> Result<Option<bool>, UiError> {
    match obj.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Bool(b)) => Ok(Some(*b)),
        Some(_) => Err(UiError::BadRequest(format!("`{field}` must be a boolean"))),
    }
}

/// Read an optional unsigned integer field (rejects negative numbers, floats, strings).
pub fn json_opt_usize(obj: &Value, field: &str) -> Result<Option<usize>, UiError> {
    match obj.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Number(n)) => {
            let v = n.as_u64().ok_or_else(|| {
                UiError::BadRequest(format!("`{field}` must be a non-negative integer"))
            })?;
            let u = usize::try_from(v)
                .map_err(|_| UiError::BadRequest(format!("`{field}` is out of range")))?;
            Ok(Some(u))
        }
        Some(_) => Err(UiError::BadRequest(format!(
            "`{field}` must be a non-negative integer"
        ))),
    }
}

/// Read an optional array of strings (rejects non-arrays or non-string elements).
pub fn json_opt_string_array(obj: &Value, field: &str) -> Result<Option<Vec<String>>, UiError> {
    match obj.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Array(arr)) => {
            let mut out = Vec::with_capacity(arr.len());
            for item in arr {
                let s = item.as_str().ok_or_else(|| {
                    UiError::BadRequest(format!("`{field}` elements must all be strings"))
                })?;
                out.push(s.to_string());
            }
            Ok(Some(out))
        }
        Some(_) => Err(UiError::BadRequest(format!(
            "`{field}` must be an array of strings"
        ))),
    }
}

/// Parse optional `anchors` array (accepts either `"path"`/`"path#symbol"` strings or
/// `{ "path": "...", "symbol": "..." }` objects; rejects any malformed shape).
pub fn json_opt_anchors(obj: &Value, field: &str) -> Result<Option<Vec<AnchorSpec>>, UiError> {
    match obj.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Array(arr)) => {
            let mut out = Vec::with_capacity(arr.len());
            for item in arr {
                match item {
                    Value::String(spec) => {
                        out.push(AnchorSpec::parse(spec)?);
                    }
                    Value::Object(_) => {
                        let path = json_req_str(item, "path")?;
                        let symbol = json_opt_str(item, "symbol", false)?;
                        out.push(AnchorSpec {
                            path: path.to_string(),
                            symbol,
                        });
                    }
                    _ => {
                        return Err(UiError::BadRequest(format!(
                            "`{field}` items must be strings or {{path, symbol?}} objects"
                        )));
                    }
                }
            }
            Ok(Some(out))
        }
        Some(_) => Err(UiError::BadRequest(format!("`{field}` must be an array"))),
    }
}

/// Fail-closed boolean query param parser (`"true"`/`"false"` only).
pub fn query_opt_bool(
    params: &BTreeMap<String, String>,
    key: &str,
) -> Result<Option<bool>, UiError> {
    match params.get(key) {
        None => Ok(None),
        Some(raw) => match raw.trim() {
            "true" | "1" => Ok(Some(true)),
            "false" | "0" => Ok(Some(false)),
            other => Err(UiError::BadRequest(format!(
                "query parameter `{key}` must be `true` or `false`, got `{other}`"
            ))),
        },
    }
}

/// Fail-closed positive integer query param parser.
pub fn query_opt_usize(
    params: &BTreeMap<String, String>,
    key: &str,
    min: usize,
    max: usize,
) -> Result<Option<usize>, UiError> {
    match params.get(key) {
        None => Ok(None),
        Some(raw) => {
            let parsed = raw.trim().parse::<usize>().map_err(|_| {
                UiError::BadRequest(format!(
                    "query parameter `{key}` must be an integer, got `{raw}`"
                ))
            })?;
            if parsed < min || parsed > max {
                return Err(UiError::BadRequest(format!(
                    "query parameter `{key}` must be between {min} and {max}, got {parsed}"
                )));
            }
            Ok(Some(parsed))
        }
    }
}

/// Require a non-empty query parameter.
pub fn query_req_str<'a>(
    params: &'a BTreeMap<String, String>,
    key: &str,
) -> Result<&'a str, UiError> {
    match params.get(key) {
        Some(raw) if !raw.trim().is_empty() => Ok(raw.trim()),
        _ => Err(UiError::BadRequest(format!(
            "query parameter `{key}` is required"
        ))),
    }
}

/// Guard helper blocking writes whenever read-only mode is active.
pub fn ensure_writable(read_only: bool, op: &str) -> Result<(), UiError> {
    if read_only {
        return Err(UiError::ReadOnlyForbidden(op.to_string()));
    }
    Ok(())
}
