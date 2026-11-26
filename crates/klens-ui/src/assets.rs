//! Offline embedded UI assets (`include_str!`) and lightweight JSON i18n dictionaries.
//!
//! Zero external CDN requests: every HTML, CSS, JS, and i18n JSON resource is compiled
//! directly into the `klens` binary.

/// Embedded main HTML shell (`/`).
pub const INDEX_HTML: &str = include_str!("../assets/index.html");

/// Embedded styles (`/style.css`).
pub const STYLE_CSS: &str = include_str!("../assets/style.css");

/// Embedded client-side core shell script (`/app.js`).
pub const APP_JS: &str = include_str!("../assets/app.js");

/// Embedded Blueprint & Code Graph view module (`/views_board.js`).
pub const VIEWS_BOARD_JS: &str = include_str!("../assets/views_board.js");

/// Embedded Memory, Runs & Real Stats view module (`/views_vault.js`).
pub const VIEWS_VAULT_JS: &str = include_str!("../assets/views_vault.js");

/// Embedded English fallback dictionary (`/i18n/en.json`).
pub const I18N_EN: &str = include_str!("../assets/i18n/en.json");
/// Embedded Turkish dictionary (`/i18n/tr.json`).
pub const I18N_TR: &str = include_str!("../assets/i18n/tr.json");
/// Embedded German dictionary (`/i18n/de.json`).
pub const I18N_DE: &str = include_str!("../assets/i18n/de.json");
/// Embedded Spanish dictionary (`/i18n/es.json`).
pub const I18N_ES: &str = include_str!("../assets/i18n/es.json");
/// Embedded French dictionary (`/i18n/fr.json`).
pub const I18N_FR: &str = include_str!("../assets/i18n/fr.json");
/// Embedded Portuguese dictionary (`/i18n/pt.json`).
pub const I18N_PT: &str = include_str!("../assets/i18n/pt.json");

/// Look up an embedded static asset by normalized URL path, returning `(content_type, body)`.
pub fn lookup_static_asset(path: &str) -> Option<(&'static str, &'static str)> {
    match path {
        "/" | "/index.html" => Some(("text/html; charset=utf-8", INDEX_HTML)),
        "/style.css" => Some(("text/css; charset=utf-8", STYLE_CSS)),
        "/app.js" => Some(("application/javascript; charset=utf-8", APP_JS)),
        "/views_board.js" => Some(("application/javascript; charset=utf-8", VIEWS_BOARD_JS)),
        "/views_vault.js" => Some(("application/javascript; charset=utf-8", VIEWS_VAULT_JS)),
        "/i18n/en.json" => Some(("application/json; charset=utf-8", I18N_EN)),
        "/i18n/tr.json" => Some(("application/json; charset=utf-8", I18N_TR)),
        "/i18n/de.json" => Some(("application/json; charset=utf-8", I18N_DE)),
        "/i18n/es.json" => Some(("application/json; charset=utf-8", I18N_ES)),
        "/i18n/fr.json" => Some(("application/json; charset=utf-8", I18N_FR)),
        "/i18n/pt.json" => Some(("application/json; charset=utf-8", I18N_PT)),
        _ => None,
    }
}

/// All embedded i18n dictionaries `(code, raw_json)` for integrity tests.
pub const ALL_I18N_BUNDLES: &[(&str, &str)] = &[
    ("en", I18N_EN),
    ("tr", I18N_TR),
    ("de", I18N_DE),
    ("es", I18N_ES),
    ("fr", I18N_FR),
    ("pt", I18N_PT),
];
