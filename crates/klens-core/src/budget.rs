use serde::{Deserialize, Serialize};

/// Single-source-of-truth character-to-token ratio across the entire workspace.
///
/// Formula: `ceil(unicode_scalar_count / 4)` (0 for empty text).
pub const CHARS_PER_TOKEN: usize = 4;

/// Deterministically estimate token count from UTF-8 text.
///
/// Uses ceiling division of Unicode scalar (`char`) count by [`CHARS_PER_TOKEN`],
/// returning `0` for empty input and at least `1` for any non-empty input.
pub fn estimate_tokens(text: &str) -> usize {
    if text.is_empty() {
        return 0;
    }
    text.chars().count().div_ceil(CHARS_PER_TOKEN)
}

/// Deterministically estimate token count from a raw byte length.
pub fn estimate_tokens_from_bytes(byte_len: usize) -> usize {
    if byte_len == 0 {
        return 0;
    }
    byte_len.div_ceil(CHARS_PER_TOKEN)
}

/// Deterministic token budget tracker.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenBudget {
    limit: usize,
    used: usize,
}

impl TokenBudget {
    /// Create a fresh budget with the given token limit.
    pub const fn new(limit: usize) -> Self {
        Self { limit, used: 0 }
    }

    /// Maximum allowed token budget.
    pub const fn limit(&self) -> usize {
        self.limit
    }

    /// Tokens consumed so far.
    pub const fn used(&self) -> usize {
        self.used
    }

    /// Remaining tokens before reaching the limit.
    pub const fn remaining(&self) -> usize {
        self.limit.saturating_sub(self.used)
    }

    /// Whether the budget has no remaining tokens.
    pub const fn is_exhausted(&self) -> bool {
        self.used >= self.limit
    }

    /// Check whether `tokens` can fit without exceeding `limit`.
    pub const fn can_fit(&self, tokens: usize) -> bool {
        match self.used.checked_add(tokens) {
            Some(total) => total <= self.limit,
            None => false,
        }
    }

    /// Consume `tokens` if they fit within `limit`. Returns `true` on success.
    pub fn try_consume(&mut self, tokens: usize) -> bool {
        if self.can_fit(tokens) {
            self.used += tokens;
            true
        } else {
            false
        }
    }

    /// Estimate and consume tokens for `text` if it fits within `limit`.
    pub fn try_consume_text(&mut self, text: &str) -> bool {
        self.try_consume(estimate_tokens(text))
    }

    /// Record consumed tokens even if they exceed `limit` (e.g., mandatory error blocks).
    pub fn consume_unbounded(&mut self, tokens: usize) {
        self.used = self.used.saturating_add(tokens);
    }

    /// Number of tokens consumed above `limit` (0 if within budget).
    pub const fn over_budget_by(&self) -> usize {
        self.used.saturating_sub(self.limit)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn estimate_tokens_is_deterministic_and_monotonic() {
        assert_eq!(estimate_tokens(""), 0);
        assert_eq!(estimate_tokens("a"), 1);
        assert_eq!(estimate_tokens("abcd"), 1);
        assert_eq!(estimate_tokens("abcde"), 2);
        assert_eq!(estimate_tokens("ğüşiöç12"), 2); // 8 Unicode scalars -> 2 tokens
    }

    #[test]
    fn token_budget_tracks_usage_and_rejects_overflow() {
        let mut budget = TokenBudget::new(10);
        assert_eq!(budget.remaining(), 10);
        assert!(budget.try_consume(4));
        assert_eq!(budget.used(), 4);
        assert_eq!(budget.remaining(), 6);
        assert!(!budget.try_consume(7));
        assert_eq!(budget.used(), 4);
        assert!(budget.try_consume_text("12345678")); // 2 tokens
        assert_eq!(budget.used(), 6);
        assert!(!budget.is_exhausted());

        budget.consume_unbounded(10);
        assert!(budget.is_exhausted());
        assert_eq!(budget.over_budget_by(), 6);
    }
}
