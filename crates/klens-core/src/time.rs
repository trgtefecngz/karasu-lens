//! Pure-Rust UTC calendar formatting and RFC3339 / ISO-8601 timestamp parsing
//! (zero external date/time crates).

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::hash::blake3_text;

static ID_SEQ: AtomicU64 = AtomicU64::new(0);

/// Seconds in one UTC calendar day.
pub const SECS_PER_DAY: i64 = 86_400;

/// UTC timestamp components decomposed from `SystemTime` or Unix seconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UtcParts {
    pub year: i64,
    pub month: u32,
    pub day: u32,
    pub hour: u32,
    pub minute: u32,
    pub second: u32,
    pub subsec_nanos: u32,
}

impl UtcParts {
    /// Current UTC wall-clock timestamp.
    pub fn now() -> Self {
        let dur = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        Self::from_unix_secs(dur.as_secs() as i64, dur.subsec_nanos())
    }

    /// Convert Unix epoch seconds and subsecond nanoseconds into UTC calendar components.
    pub fn from_unix_secs(unix_secs: i64, subsec_nanos: u32) -> Self {
        let days = unix_secs.div_euclid(SECS_PER_DAY);
        let secs_of_day = unix_secs.rem_euclid(SECS_PER_DAY) as u32;
        let (year, month, day) = civil_from_days(days);
        let hour = secs_of_day / 3600;
        let minute = (secs_of_day % 3600) / 60;
        let second = secs_of_day % 60;
        Self {
            year,
            month,
            day,
            hour,
            minute,
            second,
            subsec_nanos,
        }
    }

    /// Convert UTC calendar components back into Unix epoch seconds.
    pub fn to_unix_secs(self) -> i64 {
        let days = days_from_civil(self.year, self.month, self.day);
        days * SECS_PER_DAY
            + i64::from(self.hour) * 3600
            + i64::from(self.minute) * 60
            + i64::from(self.second)
    }

    /// ISO-8601 UTC string (`YYYY-MM-DDTHH:MM:SSZ`).
    pub fn to_iso8601(self) -> String {
        format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
            self.year, self.month, self.day, self.hour, self.minute, self.second
        )
    }

    /// Compact sortable UTC prefix (`YYYYMMDD-HHMMSS`).
    pub fn to_compact_stamp(self) -> String {
        format!(
            "{:04}{:02}{:02}-{:02}{:02}{:02}",
            self.year, self.month, self.day, self.hour, self.minute, self.second
        )
    }
}

/// Current Unix timestamp in whole seconds.
pub fn now_unix_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

/// Current UTC timestamp formatted as ISO-8601 (`YYYY-MM-DDTHH:MM:SSZ`).
pub fn now_iso8601_utc() -> String {
    UtcParts::now().to_iso8601()
}

/// Start of the UTC calendar day (`00:00:00Z`) containing `unix_secs`.
pub const fn start_of_utc_day_secs(unix_secs: i64) -> i64 {
    unix_secs - unix_secs.rem_euclid(SECS_PER_DAY)
}

/// Generate a lexicographically sortable unique ID: `(<YYYYMMDD>-<HHMMSS>-<4hex>, <ISO-8601 UTC>)`.
pub fn generate_sortable_id(salt: &str) -> (String, String) {
    let now = UtcParts::now();
    let seq = ID_SEQ.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    let mut hasher = blake3_hash_seed(now, pid, seq, salt);
    let hex_suffix = hasher.drain(..4).collect::<String>();
    let id = format!("{}-{hex_suffix}", now.to_compact_stamp());
    (id, now.to_iso8601())
}

fn blake3_hash_seed(now: UtcParts, pid: u32, seq: u64, salt: &str) -> String {
    let seed = format!(
        "{}-{}-{}-{}-{}-{}-{}-{pid}-{seq}-{salt}",
        now.year, now.month, now.day, now.hour, now.minute, now.second, now.subsec_nanos
    );
    blake3_text(&seed)
}

/// Parse an ISO-8601 / RFC3339 timestamp string into Unix epoch seconds (UTC).
///
/// Accepts `YYYY-MM-DDTHH:MM:SS`, optional fractional seconds (`.NNN...`), and a timezone
/// suffix (`Z`/`z`, `+HH:MM`, `-HH:MM`, `+HHMM`, or `-HHMM`). Lowercase `t` or a single
/// ASCII space is accepted as the date/time separator.
///
/// Returns `None` for invalid dates, out-of-range fields, or malformed/non-ASCII timestamps
/// without panicking.
pub fn parse_iso8601_utc_secs(input: &str) -> Option<i64> {
    let s = input.trim();
    let bytes = s.as_bytes();
    // Minimum valid form: `YYYY-MM-DDTHH:MM:SSZ` (20 bytes)
    if bytes.len() < 20 || !bytes.is_ascii() {
        return None;
    }

    if bytes[4] != b'-' || bytes[7] != b'-' || bytes[13] != b':' || bytes[16] != b':' {
        return None;
    }
    if !matches!(bytes[10], b'T' | b't' | b' ') {
        return None;
    }

    let year = parse_ascii_digits(&bytes[0..4])? as i64;
    let month = parse_ascii_digits(&bytes[5..7])? as u32;
    let day = parse_ascii_digits(&bytes[8..10])? as u32;
    let hour = parse_ascii_digits(&bytes[11..13])? as u32;
    let minute = parse_ascii_digits(&bytes[14..16])? as u32;
    let raw_second = parse_ascii_digits(&bytes[17..19])? as u32;

    if !(1..=12).contains(&month) {
        return None;
    }
    let max_day = days_in_month(year, month);
    if day == 0 || day > max_day {
        return None;
    }
    if hour > 23 || minute > 59 || raw_second > 60 {
        return None;
    }
    let second = raw_second.min(59);

    let mut idx = 19;
    if idx < bytes.len() && bytes[idx] == b'.' {
        idx += 1;
        let frac_start = idx;
        while idx < bytes.len() && bytes[idx].is_ascii_digit() {
            idx += 1;
        }
        if idx == frac_start {
            return None;
        }
    }

    let tz = &bytes[idx..];
    let offset_secs: i64 = match tz {
        [b'Z'] | [b'z'] => 0,
        [sign @ (b'+' | b'-'), h1, h2, b':', m1, m2] => {
            parse_tz_offset(*sign, &[*h1, *h2], &[*m1, *m2])?
        }
        [sign @ (b'+' | b'-'), h1, h2, m1, m2] => parse_tz_offset(*sign, &[*h1, *h2], &[*m1, *m2])?,
        _ => return None,
    };

    let days = days_from_civil(year, month, day);
    let local_secs = days
        .checked_mul(SECS_PER_DAY)?
        .checked_add(i64::from(hour) * 3600 + i64::from(minute) * 60 + i64::from(second))?;
    local_secs.checked_sub(offset_secs)
}

fn parse_tz_offset(sign: u8, hh: &[u8], mm: &[u8]) -> Option<i64> {
    let off_h = parse_ascii_digits(hh)? as i64;
    let off_m = parse_ascii_digits(mm)? as i64;
    if off_h > 23 || off_m > 59 {
        return None;
    }
    let mag = off_h * 3600 + off_m * 60;
    Some(if sign == b'+' { mag } else { -mag })
}

fn parse_ascii_digits(bytes: &[u8]) -> Option<u64> {
    if bytes.is_empty() {
        return None;
    }
    let mut val: u64 = 0;
    for &b in bytes {
        if !b.is_ascii_digit() {
            return None;
        }
        val = val.checked_mul(10)?.checked_add(u64::from(b - b'0'))?;
    }
    Some(val)
}

const fn is_leap_year(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}

const fn days_in_month(year: i64, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if is_leap_year(year) {
                29
            } else {
                28
            }
        }
        _ => 0,
    }
}

/// Howard Hinnant's civil-from-days algorithm (exact proleptic Gregorian calendar).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let year = y + i64::from(m <= 2);
    (year, m as u32, d as u32)
}

/// Howard Hinnant's days-from-civil algorithm (exact inverse of [`civil_from_days`]).
fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let y = year - i64::from(month <= 2);
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u64; // [0, 399]
    let m = u64::from(month);
    let d = u64::from(day);
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    era * 146_097 + (doe as i64) - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn converts_known_unix_timestamps_to_exact_utc() {
        let epoch = UtcParts::from_unix_secs(0, 0);
        assert_eq!(epoch.to_iso8601(), "1970-01-01T00:00:00Z");
        assert_eq!(epoch.to_unix_secs(), 0);

        // 2026-11-22T18:30:00Z = 1795372200
        let sample = UtcParts::from_unix_secs(1_795_372_200, 0);
        assert_eq!(sample.to_iso8601(), "2026-11-22T18:30:00Z");
        assert_eq!(sample.to_compact_stamp(), "20261122-183000");
        assert_eq!(sample.to_unix_secs(), 1_795_372_200);

        // Leap day: 2024-02-29T12:00:00Z = 1709208000
        let leap = UtcParts::from_unix_secs(1_709_208_000, 0);
        assert_eq!(leap.to_iso8601(), "2024-02-29T12:00:00Z");
        assert_eq!(leap.to_unix_secs(), 1_709_208_000);
    }

    #[test]
    fn parses_rfc3339_utc_fractional_and_offsets() {
        assert_eq!(parse_iso8601_utc_secs("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(
            parse_iso8601_utc_secs("2026-11-22T18:30:00Z"),
            Some(1_795_372_200)
        );
        assert_eq!(
            parse_iso8601_utc_secs("2026-11-22T18:30:00.987654Z"),
            Some(1_795_372_200)
        );
        assert_eq!(
            parse_iso8601_utc_secs("2026-11-22T21:30:00+03:00"),
            Some(1_795_372_200)
        );
        assert_eq!(
            parse_iso8601_utc_secs("2026-11-22T13:30:00.123-05:00"),
            Some(1_795_372_200)
        );
        assert_eq!(
            parse_iso8601_utc_secs("2024-02-29T12:00:00z"),
            Some(1_709_208_000)
        );
    }

    #[test]
    fn rejects_invalid_and_multibyte_timestamps_safely() {
        assert_eq!(parse_iso8601_utc_secs(""), None);
        assert_eq!(parse_iso8601_utc_secs("2025-02-29T00:00:00Z"), None);
        assert_eq!(parse_iso8601_utc_secs("2026-13-01T00:00:00Z"), None);
        assert_eq!(parse_iso8601_utc_secs("2026-11-22T25:00:00Z"), None);
        assert_eq!(parse_iso8601_utc_secs("2026-11-22T18:30:00"), None);
        assert_eq!(parse_iso8601_utc_secs("2026-11-22T18:30:00.Z"), None);
        assert_eq!(
            parse_iso8601_utc_secs("ğüşiöç-🚀-2026-11-22T18:30:00Z"),
            None
        );
    }

    #[test]
    fn start_of_utc_day_rounds_down_to_midnight() {
        // 2026-11-22T18:30:00Z -> 2026-11-22T00:00:00Z
        let midnight = start_of_utc_day_secs(1_795_372_200);
        assert_eq!(
            UtcParts::from_unix_secs(midnight, 0).to_iso8601(),
            "2026-11-22T00:00:00Z"
        );
    }
}
