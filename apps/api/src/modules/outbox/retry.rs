use crate::core::EventId;

/// Outcome persisted after one failed dispatch or consumer-handling attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FailureDisposition {
    Retry { delay_seconds: u32 },
    DeadLetter,
}

/// Bounded deterministic exponential backoff with event/attempt-derived jitter.
/// Deterministic jitter gives retries a stable spread without requiring a
/// platform RNG in domain code. It is not used for security decisions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RetryPolicy {
    max_attempts: u32,
    base_delay_seconds: u32,
    max_delay_seconds: u32,
    jitter_percent: u8,
}

impl RetryPolicy {
    pub const MAX_RETRY_DELAY_SECONDS: u32 = 86_400;

    /// P01 defaults: five total failed attempts, starting at 30 seconds, capped
    /// at 30 minutes, with deterministic ±20% jitter. Worker-level fallback
    /// retries use explicit Queue configuration separately.
    pub const fn p01_default() -> Self {
        Self {
            max_attempts: 5,
            base_delay_seconds: 30,
            max_delay_seconds: 1_800,
            jitter_percent: 20,
        }
    }

    pub const fn new(
        max_attempts: u32,
        base_delay_seconds: u32,
        max_delay_seconds: u32,
        jitter_percent: u8,
    ) -> Option<Self> {
        if max_attempts == 0
            || base_delay_seconds == 0
            || max_delay_seconds < base_delay_seconds
            || max_delay_seconds > Self::MAX_RETRY_DELAY_SECONDS
            || jitter_percent > 100
        {
            return None;
        }
        Some(Self {
            max_attempts,
            base_delay_seconds,
            max_delay_seconds,
            jitter_percent,
        })
    }

    pub const fn max_attempts(self) -> u32 {
        self.max_attempts
    }

    /// `attempt` is one-based and describes the attempt that just failed.
    pub fn after_failure(self, attempt: u32, event_id: &EventId) -> FailureDisposition {
        if attempt == 0 || attempt >= self.max_attempts {
            return FailureDisposition::DeadLetter;
        }

        let shift = attempt.saturating_sub(1).min(31);
        let exponential = self
            .base_delay_seconds
            .checked_mul(1_u32 << shift)
            .unwrap_or(self.max_delay_seconds)
            .min(self.max_delay_seconds);
        let jitter_span = exponential
            .saturating_mul(u32::from(self.jitter_percent))
            .saturating_add(99)
            / 100;
        let low = exponential.saturating_sub(jitter_span).max(1);
        let high = exponential
            .saturating_add(jitter_span)
            .min(self.max_delay_seconds);
        let spread = high.saturating_sub(low).saturating_add(1);
        let jitter = if spread <= 1 {
            0
        } else {
            stable_jitter(event_id.as_str().as_bytes(), attempt) % spread
        };

        FailureDisposition::Retry {
            delay_seconds: low.saturating_add(jitter),
        }
    }
}

fn stable_jitter(event_id: &[u8], attempt: u32) -> u32 {
    let mut hash = 2_166_136_261_u32;
    for byte in event_id.iter().copied().chain(attempt.to_le_bytes()) {
        hash ^= u32::from(byte);
        hash = hash.wrapping_mul(16_777_619);
    }
    hash
}
