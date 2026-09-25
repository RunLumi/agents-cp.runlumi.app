//! Canonical schedule semantics for P06 automations.
//!
//! The control plane owns schedule authority, so the answer to "which canonical
//! UTC instants are due" must be a *pure* function of an immutable schedule
//! revision, a caller-supplied authoritative cursor, and a caller-supplied
//! `now`. If it were not, a queue redelivery or a device reconnect could mint a
//! different answer and therefore a second logical occurrence. Nothing in this
//! module reads a clock, D1, or the network.
//!
//! Two implementation boundaries are load bearing and are stated here rather
//! than left implicit:
//!
//! 1. **Time is integer seconds since the Unix epoch.** Civil-date arithmetic
//!    ([`days_from_civil`]/[`civil_from_days`]) is Howard Hinnant's
//!    public-domain algorithm, reimplemented here. The workspace has no
//!    `chrono`-class dependency and none may be added, because it must compile
//!    for `wasm32-unknown-unknown` with a bounded bundle size.
//! 2. **A zone is caller-supplied transitions, not a linked tz database.** The
//!    frozen wire stores an IANA timezone string, and the contract forbids
//!    depending on a tz crate here. [`TimezoneId`] therefore validates the
//!    string's *shape and length* and never interprets it; the adapter resolves
//!    the zone and supplies the ordered UTC-offset transitions as
//!    [`ZoneOffsets`]. DST behavior is then still decided here, purely, from
//!    those transitions and the frozen [`DstPolicy`].
//!
//! Identity note: the canonical UTC instant — never the display expression, the
//! local civil time, or the zone — is what a caller must use for occurrence
//! identity. See [`super::occurrence`] for the key construction.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::core::Timestamp;

use super::DomainError;

/// Default overlap policy from `p06-cg-v1`: `skip`.
pub const DEFAULT_OVERLAP_POLICY: OverlapPolicy = OverlapPolicy::Skip;
/// Default missed-run policy from `p06-cg-v1`: `run_once`.
pub const DEFAULT_MISSED_POLICY: MissedPolicy = MissedPolicy::RunOnce;

/// The server inspects at most seven days of missed history, regardless of how
/// long a device or the control plane was offline. This is what prevents a
/// reconnect burst.
pub const MAX_MISSED_HISTORY_DAYS: i64 = 7;

/// Bounds on `catch_up_limit`. The field is only meaningful for
/// [`MissedPolicy::CatchUp`].
pub const MIN_CATCH_UP_LIMIT: u8 = 1;
pub const MAX_CATCH_UP_LIMIT: u8 = 20;

/// Bounds on an interval's `every` value.
pub const MIN_INTERVAL_EVERY: u16 = 1;
pub const MAX_INTERVAL_EVERY: u16 = 200;

/// One generation call never returns more than this many instants, and a single
/// occurrence enumeration is bounded so a Worker request cannot spin.
pub const MAX_NEXT_INSTANTS: usize = 20;

/// A single generation pass examines at most this many candidate schedule
/// slots. 100_800 is 70 days at one-minute density, so a full seven-day missed
/// window is always completed for any legal interval, with headroom for the
/// cron day scan. A filter combination that exhausts the budget returns the
/// instants found so far; the caller re-invokes with an advanced cursor.
pub const MAX_SCHEDULE_CANDIDATES: u32 = 100_800;

/// Day-scan ceiling for cron. Four Gregorian years always contain a matching
/// date for any legal five-field expression, including `29 2`.
pub const MAX_CRON_SEARCH_DAYS: i64 = 366 * 4;

/// Maximum serialized size of a stored cron expression and of a timezone.
pub const MAX_CRON_EXPRESSION_BYTES: usize = 128;
pub const MAX_TIMEZONE_BYTES: usize = 64;
/// IANA names are at most four `/`-separated segments in practice.
pub const MAX_TIMEZONE_SEGMENTS: usize = 4;
/// Largest absolute UTC offset used when bracketing a local-time resolution and
/// when validating supplied transitions. 18h is wider than any real zone.
pub const MAX_UTC_OFFSET_SECONDS: i32 = 18 * 60 * 60;
/// Bounded transition list so a zone cannot become an unbounded payload.
pub const MAX_ZONE_TRANSITIONS: usize = 512;

const SECONDS_PER_DAY: i64 = 86_400;
const SECONDS_PER_HOUR: i64 = 3_600;
const SECONDS_PER_MINUTE: i64 = 60;

/// Civil years this module can represent in the canonical four-digit RFC 3339
/// form. Anything outside is rejected rather than silently truncated.
pub const MIN_CIVIL_YEAR: i64 = 1;
pub const MAX_CIVIL_YEAR: i64 = 9999;

// ---------------------------------------------------------------------------
// Civil date arithmetic
// ---------------------------------------------------------------------------

/// Proleptic Gregorian leap year test.
pub const fn is_leap_year(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

/// Days in a Gregorian month. `month` must be 1–12; callers validate first.
pub const fn days_in_month(year: i64, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => 0,
    }
}

/// Days since 1970-01-01 for a proleptic Gregorian date.
///
/// Hinnant's `days_from_civil`: the era-relative decomposition avoids any
/// month-length table beyond leap years, so February and the century leap rules
/// are handled once, in one place.
pub fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let shifted = if month <= 2 { year - 1 } else { year };
    let era = if shifted >= 0 { shifted } else { shifted - 399 } / 400;
    let year_of_era = shifted - era * 400;
    let month_position = i64::from((month + 9) % 12);
    let day_of_year = (153 * month_position + 2) / 5 + i64::from(day) - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

/// Inverse of [`days_from_civil`]. Returns `(year, month, day)`.
pub fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let shifted = days + 719_468;
    let era = if shifted >= 0 {
        shifted
    } else {
        shifted - 146_096
    } / 146_097;
    let day_of_era = shifted - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_position = (5 * day_of_year + 2) / 153;
    let day = (day_of_year - (153 * month_position + 2) / 5 + 1) as u32;
    let month = if month_position < 10 {
        month_position + 3
    } else {
        month_position - 9
    } as u32;
    (if month <= 2 { year + 1 } else { year }, month, day)
}

/// Day of week with `0 = Sunday` and `6 = Saturday`, matching the frozen cron
/// day-of-week numbering. 1970-01-01 was a Thursday.
pub fn weekday_from_civil(year: i64, month: u32, day: u32) -> u32 {
    (days_from_civil(year, month, day) + 4).rem_euclid(7) as u32
}

/// Parse the frozen RFC 3339 UTC wire form into epoch seconds.
///
/// Validation is delegated to [`Timestamp`] so there is exactly one definition
/// of the accepted form. A leap second (`:60`) is floored to `:59`: a leap
/// second cannot be scheduled as its own occurrence identity, and flooring
/// keeps `scheduled_for` representable in the canonical four-digit form.
pub fn parse_instant_utc(value: &str) -> Result<i64, DomainError> {
    let timestamp = Timestamp::new(value).map_err(|_| DomainError::ScheduleInvalid)?;
    let bytes = timestamp.as_str().as_bytes();
    let year = read_number(bytes, 0, 4);
    let month = read_number(bytes, 5, 2);
    let day = read_number(bytes, 8, 2);
    let hour = read_number(bytes, 11, 2);
    let minute = read_number(bytes, 14, 2);
    let second = read_number(bytes, 17, 2).min(59);

    if !(MIN_CIVIL_YEAR..=MAX_CIVIL_YEAR).contains(&year) {
        return Err(DomainError::ScheduleInvalid);
    }
    let month = u32::try_from(month).map_err(|_| DomainError::ScheduleInvalid)?;
    let day = u32::try_from(day).map_err(|_| DomainError::ScheduleInvalid)?;
    let hour = u32::try_from(hour).map_err(|_| DomainError::ScheduleInvalid)?;
    let minute = u32::try_from(minute).map_err(|_| DomainError::ScheduleInvalid)?;
    let second = u32::try_from(second).map_err(|_| DomainError::ScheduleInvalid)?;
    let days = days_from_civil(year, month, day);
    let seconds = days
        .checked_mul(SECONDS_PER_DAY)
        .and_then(|value| value.checked_add(i64::from(hour) * SECONDS_PER_HOUR))
        .and_then(|value| value.checked_add(i64::from(minute) * SECONDS_PER_MINUTE))
        .and_then(|value| value.checked_add(i64::from(second)))
        .ok_or(DomainError::ScheduleInvalid)?;
    // Reject anything that does not round-trip; this catches a value that was
    // only shape-valid.
    if format_instant_utc(seconds)? != canonical_second_form(timestamp.as_str()) {
        return Err(DomainError::ScheduleInvalid);
    }
    Ok(seconds)
}

/// Render epoch seconds in the canonical frozen form `YYYY-MM-DDTHH:MM:SS.000Z`.
///
/// Canonicalization matters: occurrence identity must be stable across
/// `2026-09-25T16:00:00Z` and `2026-09-25T16:00:00.000Z`.
pub fn format_instant_utc(epoch_seconds: i64) -> Result<String, DomainError> {
    let days = epoch_seconds.div_euclid(SECONDS_PER_DAY);
    let time_of_day = epoch_seconds.rem_euclid(SECONDS_PER_DAY);
    let (year, month, day) = civil_from_days(days);
    if !(MIN_CIVIL_YEAR..=MAX_CIVIL_YEAR).contains(&year) {
        return Err(DomainError::ScheduleInvalid);
    }
    let hour = time_of_day / SECONDS_PER_HOUR;
    let minute = (time_of_day % SECONDS_PER_HOUR) / SECONDS_PER_MINUTE;
    let second = time_of_day % SECONDS_PER_MINUTE;
    Ok(format!(
        "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.000Z"
    ))
}

fn canonical_second_form(value: &str) -> String {
    format!("{}.000Z", &value[..19])
}

fn read_number(bytes: &[u8], start: usize, width: usize) -> i64 {
    bytes[start..start + width]
        .iter()
        .fold(0_i64, |value, digit| value * 10 + i64::from(digit - b'0'))
}

// ---------------------------------------------------------------------------
// Zone resolution
// ---------------------------------------------------------------------------

/// One UTC-offset change. `at_utc` is the instant the new offset takes effect.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UtcOffsetTransition {
    pub at_utc: i64,
    pub offset_seconds: i32,
}

/// A bounded, ordered offset table for one resolved timezone.
///
/// The Worker does not link a tz database, so this is how a zone enters the
/// domain. The adapter resolves the validated opaque [`TimezoneId`] once and
/// supplies the transitions; the domain then decides DST behavior purely.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZoneOffsets {
    default_offset_seconds: i32,
    transitions: Vec<UtcOffsetTransition>,
}

impl ZoneOffsets {
    /// A zone that never changes offset. `UTC` and fixed-offset test fixtures.
    pub fn fixed(offset_seconds: i32) -> Result<Self, DomainError> {
        Self::new(offset_seconds, &[])
    }

    /// The identity zone. No DST behavior is possible, which is exactly what a
    /// `UTC` schedule should mean.
    pub fn utc() -> Self {
        Self {
            default_offset_seconds: 0,
            transitions: Vec::new(),
        }
    }

    /// Build a zone from a strictly ascending transition list.
    pub fn new(
        default_offset_seconds: i32,
        transitions: &[UtcOffsetTransition],
    ) -> Result<Self, DomainError> {
        if default_offset_seconds.abs() > MAX_UTC_OFFSET_SECONDS
            || transitions.len() > MAX_ZONE_TRANSITIONS
        {
            return Err(DomainError::ScheduleTimezoneInvalid);
        }
        let mut ordered: Vec<UtcOffsetTransition> = Vec::with_capacity(transitions.len());
        for transition in transitions {
            if transition.offset_seconds.abs() > MAX_UTC_OFFSET_SECONDS {
                return Err(DomainError::ScheduleTimezoneInvalid);
            }
            if let Some(previous) = ordered.last()
                && previous.at_utc >= transition.at_utc
            {
                return Err(DomainError::ScheduleTimezoneInvalid);
            }
            ordered.push(*transition);
        }
        Ok(Self {
            default_offset_seconds,
            transitions: ordered,
        })
    }

    /// Offset in effect at a UTC instant.
    pub fn offset_at(&self, utc: i64) -> i32 {
        let mut low = 0_usize;
        let mut high = self.transitions.len();
        while low < high {
            let middle = low + (high - low) / 2;
            if self.transitions[middle].at_utc <= utc {
                low = middle + 1;
            } else {
                high = middle;
            }
        }
        if low == 0 {
            self.default_offset_seconds
        } else {
            self.transitions[low - 1].offset_seconds
        }
    }

    /// The local civil instant corresponding to a UTC instant, expressed as
    /// epoch seconds with the local offset applied.
    pub fn to_local(&self, utc: i64) -> i64 {
        utc + i64::from(self.offset_at(utc))
    }

    /// Resolve one local civil instant to its UTC instant(s).
    ///
    /// Two probes bracket every real transition: the offset well before and
    /// well after the slot. Each probe is a candidate UTC instant and is kept
    /// only when it round-trips back to the requested local civil instant. No
    /// candidate means the local time does not exist (spring-forward gap);
    /// two candidates mean it is repeated (fall-back overlap).
    pub fn resolve_local(&self, local_epoch: i64) -> LocalResolution {
        let before = self.offset_at(local_epoch - i64::from(MAX_UTC_OFFSET_SECONDS));
        let after = self.offset_at(local_epoch + i64::from(MAX_UTC_OFFSET_SECONDS));
        if before == after {
            let candidate = local_epoch - i64::from(before);
            return if candidate + i64::from(self.offset_at(candidate)) == local_epoch {
                LocalResolution::Unique { utc: candidate }
            } else {
                LocalResolution::Missing
            };
        }

        let mut hits = [0_i64; 2];
        let mut count = 0_usize;
        for offset in [before, after] {
            let candidate = local_epoch - i64::from(offset);
            if candidate + i64::from(self.offset_at(candidate)) == local_epoch
                && !hits[..count].contains(&candidate)
            {
                hits[count] = candidate;
                count += 1;
            }
        }
        match count {
            0 => LocalResolution::Missing,
            1 => LocalResolution::Unique { utc: hits[0] },
            _ => {
                if hits[0] < hits[1] {
                    LocalResolution::Repeated {
                        first_utc: hits[0],
                        second_utc: hits[1],
                    }
                } else {
                    LocalResolution::Repeated {
                        first_utc: hits[1],
                        second_utc: hits[0],
                    }
                }
            }
        }
    }

    /// The number of transitions, exposed for diagnostics and bounds checks.
    pub fn transition_count(&self) -> usize {
        self.transitions.len()
    }
}

/// The result of resolving one local civil instant against a zone.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalResolution {
    /// The local time exists exactly once.
    Unique { utc: i64 },
    /// The local time does not exist. The frozen contract skips this slot with
    /// `dst_missing_time`; it is never rolled into a neighbouring instant.
    Missing,
    /// The local time exists twice, at two distinct UTC instants.
    Repeated { first_utc: i64, second_utc: i64 },
}

// ---------------------------------------------------------------------------
// Frozen enums
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScheduleKind {
    OneTime,
    Cron,
    Interval,
    #[default]
    Manual,
}

impl ScheduleKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OneTime => "one_time",
            Self::Cron => "cron",
            Self::Interval => "interval",
            Self::Manual => "manual",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "one_time" => Some(Self::OneTime),
            "cron" => Some(Self::Cron),
            "interval" => Some(Self::Interval),
            "manual" => Some(Self::Manual),
            _ => None,
        }
    }
}

impl fmt::Display for ScheduleKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Concurrency policy when the previous occurrence is still live.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OverlapPolicy {
    /// Run concurrently with the live predecessor.
    Allow,
    /// Drop the new occurrence and record it as skipped.
    #[default]
    Skip,
    /// Retain at most one pending successor.
    QueueOne,
    /// Record a cancellation for the predecessor before creating the successor.
    CancelPrevious,
}

impl OverlapPolicy {
    pub const ALL: [Self; 4] = [
        Self::Allow,
        Self::Skip,
        Self::QueueOne,
        Self::CancelPrevious,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Skip => "skip",
            Self::QueueOne => "queue_one",
            Self::CancelPrevious => "cancel_previous",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "allow" => Some(Self::Allow),
            "skip" => Some(Self::Skip),
            "queue_one" => Some(Self::QueueOne),
            "cancel_previous" => Some(Self::CancelPrevious),
            _ => None,
        }
    }
}

impl fmt::Display for OverlapPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Behavior for schedule slots missed while the control plane or a device was
/// unable to dispatch.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MissedPolicy {
    /// Missed slots produce no occurrence at all.
    Skip,
    /// Exactly one occurrence for the most recent missed slot.
    #[default]
    RunOnce,
    /// Up to [`MAX_CATCH_UP_LIMIT`] occurrences, newest first.
    CatchUp,
}

impl MissedPolicy {
    pub const ALL: [Self; 3] = [Self::Skip, Self::RunOnce, Self::CatchUp];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Skip => "skip",
            Self::RunOnce => "run_once",
            Self::CatchUp => "catch_up",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "skip" => Some(Self::Skip),
            "run_once" => Some(Self::RunOnce),
            "catch_up" => Some(Self::CatchUp),
            _ => None,
        }
    }
}

impl fmt::Display for MissedPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// How a cron rule combines day-of-month with day-of-week.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DomDowMode {
    /// Standard cron: an unrestricted field defers to the other; two restricted
    /// fields are OR-ed.
    #[default]
    Or,
    /// Both fields must match.
    And,
}

impl DomDowMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Or => "or",
            Self::And => "and",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "or" => Some(Self::Or),
            "and" => Some(Self::And),
            _ => None,
        }
    }
}

/// Explicit DST behavior for a cron rule.
///
/// The gate is unambiguous that a *missing* local time is always skipped with
/// `dst_missing_time`, and that a *repeated* local time runs once at the first
/// UTC instant or twice at both. It does not spell out how the two single-run
/// policies differ, so this module draws the line as follows and the coordinator
/// must ratify it: `run_first` and `skip_duplicate` both emit the first UTC
/// instant, and `skip_duplicate` additionally records the duplicate as an
/// explicit skip with the frozen `dst_repeated_time` reason while `run_first`
/// records nothing. `run_both` emits both UTC instants as due.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DstPolicy {
    /// Run once at the first UTC instant and record the duplicate as skipped.
    #[default]
    SkipDuplicate,
    /// Run once at the first UTC instant and record nothing for the duplicate.
    RunFirst,
    /// Run at both UTC instants.
    RunBoth,
}

impl DstPolicy {
    pub const ALL: [Self; 3] = [Self::SkipDuplicate, Self::RunFirst, Self::RunBoth];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SkipDuplicate => "skip_duplicate",
            Self::RunFirst => "run_first",
            Self::RunBoth => "run_both",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "skip_duplicate" => Some(Self::SkipDuplicate),
            "run_first" => Some(Self::RunFirst),
            "run_both" => Some(Self::RunBoth),
            _ => None,
        }
    }
}

/// Interval unit. `minutes`/`hours` are elapsed arithmetic; the rest are local
/// calendar arithmetic.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntervalUnit {
    #[default]
    Minutes,
    Hours,
    Days,
    Weeks,
    Months,
    Years,
}

impl IntervalUnit {
    pub const ALL: [Self; 6] = [
        Self::Minutes,
        Self::Hours,
        Self::Days,
        Self::Weeks,
        Self::Months,
        Self::Years,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Minutes => "minutes",
            Self::Hours => "hours",
            Self::Days => "days",
            Self::Weeks => "weeks",
            Self::Months => "months",
            Self::Years => "years",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "minutes" => Some(Self::Minutes),
            "hours" => Some(Self::Hours),
            "days" => Some(Self::Days),
            "weeks" => Some(Self::Weeks),
            "months" => Some(Self::Months),
            "years" => Some(Self::Years),
            _ => None,
        }
    }

    /// Elapsed units step by a fixed number of seconds. Calendar units step in
    /// the zone's local civil calendar and therefore follow the anchor's local
    /// time of day across a DST change.
    pub const fn is_elapsed(self) -> bool {
        matches!(self, Self::Minutes | Self::Hours)
    }
}

impl fmt::Display for IntervalUnit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Timezone
// ---------------------------------------------------------------------------

/// A validated-but-opaque IANA timezone name.
///
/// Validation is deliberately shape-and-length only. No tz database is linked
/// into the Worker bundle, so this type never interprets the name; it exists to
/// reject unbounded, control-bearing, or obviously malformed input at the
/// boundary and to give the adapter a stable, bounded value to resolve.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TimezoneId(String);

impl TimezoneId {
    pub fn new(value: impl Into<String>) -> Result<Self, DomainError> {
        let value = value.into();
        if value.is_empty() || value.len() > MAX_TIMEZONE_BYTES {
            return Err(DomainError::ScheduleTimezoneInvalid);
        }
        let mut segments = 0_usize;
        for byte in value.bytes() {
            match byte {
                b'/' => segments += 1,
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_' | b'-' | b'+' => {}
                _ => return Err(DomainError::ScheduleTimezoneInvalid),
            }
        }
        // A leading, trailing, or doubled separator is not an IANA name.
        if value.starts_with('/')
            || value.ends_with('/')
            || value.contains("//")
            || segments + 1 > MAX_TIMEZONE_SEGMENTS
        {
            return Err(DomainError::ScheduleTimezoneInvalid);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for TimezoneId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::str::FromStr for TimezoneId {
    type Err = DomainError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

// ---------------------------------------------------------------------------
// Cron expression
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FieldSpec {
    min: u32,
    max: u32,
    names: &'static [(&'static str, u32)],
}

const MONTH_NAMES: &[(&str, u32)] = &[
    ("jan", 1),
    ("feb", 2),
    ("mar", 3),
    ("apr", 4),
    ("may", 5),
    ("jun", 6),
    ("jul", 7),
    ("aug", 8),
    ("sep", 9),
    ("oct", 10),
    ("nov", 11),
    ("dec", 12),
];

const DOW_NAMES: &[(&str, u32)] = &[
    ("sun", 0),
    ("mon", 1),
    ("tue", 2),
    ("wed", 3),
    ("thu", 4),
    ("fri", 5),
    ("sat", 6),
];

const MINUTE_SPEC: FieldSpec = FieldSpec {
    min: 0,
    max: 59,
    names: &[],
};
const HOUR_SPEC: FieldSpec = FieldSpec {
    min: 0,
    max: 23,
    names: &[],
};
const DOM_SPEC: FieldSpec = FieldSpec {
    min: 1,
    max: 31,
    names: &[],
};
const MONTH_SPEC: FieldSpec = FieldSpec {
    min: 1,
    max: 12,
    names: MONTH_NAMES,
};
const DOW_SPEC: FieldSpec = FieldSpec {
    min: 0,
    max: 7,
    names: DOW_NAMES,
};

/// A parsed cron field as a bit set. Values fit in 64 bits for every field the
/// frozen five-field grammar allows, so matching is a single bit test.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Field {
    mask: u64,
    max: u32,
}

impl Field {
    fn full(spec: FieldSpec) -> Self {
        let span = u64::from(spec.max - spec.min + 1);
        Self {
            mask: if span >= 64 {
                u64::MAX
            } else {
                (1 << span) - 1
            },
            max: spec.max,
        }
    }

    fn empty(spec: FieldSpec) -> Self {
        Self {
            mask: 0,
            max: spec.max,
        }
    }

    fn insert(&mut self, spec: FieldSpec, value: u32) -> Result<(), DomainError> {
        if !(spec.min..=spec.max).contains(&value) {
            return Err(DomainError::ScheduleInvalid);
        }
        // Day-of-week 7 is an accepted spelling of Sunday and folds into 0.
        let normalized = if spec.max == DOW_SPEC.max && value == 7 {
            0
        } else {
            value
        };
        self.mask |= 1 << (normalized - spec.min);
        Ok(())
    }

    /// True when this field covers its entire spec range, which is how a
    /// canonical `*` is recognized. Used by DOM/DOW `or` semantics: a `*` day
    /// field must not force the other field to be ignored.
    fn is_full(&self, spec: FieldSpec) -> bool {
        self.max == spec.max && self.mask == Self::full(spec).mask
    }

    /// Test membership using the SAME bit index that [`Field::insert`] wrote.
    ///
    /// `insert` stores `value` at bit `value - spec.min`, so `matches` must read
    /// `value - spec.min` too. A hard-coded `value - 1` silently misreads every
    /// field whose `min` is not 1 (minutes and hours are 0-based), which would
    /// shift a canonical `0 9 * * 1-5` into a different firing time.
    fn matches(&self, spec: FieldSpec, value: u32) -> bool {
        if !(spec.min..=spec.max).contains(&value) {
            return false;
        }
        // Day-of-week 7 folds into 0, matching `insert`.
        let normalized = if spec.max == DOW_SPEC.max && value == 7 {
            0
        } else {
            value
        };
        let index = normalized - spec.min;
        index < 64 && (self.mask & (1 << index)) != 0
    }
}

/// A strict, canonical five-field cron expression.
///
/// Supported grammar per field: `*`, `n`, `name`, `a-b`, `a-b/step`, `n/step`,
/// and comma-separated lists of those. Quartz extensions (`?`, `L`, `W`, `#`),
/// seconds and year fields, `@daily` macros, and out-of-range values are
/// rejected with `schedule_invalid` rather than guessed at.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CronExpression {
    minutes: Field,
    hours: Field,
    days_of_month: Field,
    months: Field,
    days_of_week: Field,
    dom_dow_mode: DomDowMode,
    normalized: String,
}

impl CronExpression {
    /// Parse and canonicalize an expression.
    ///
    /// The canonical form lists each field's covered values in ascending order
    /// and uses `*` when a field covers its whole range. Canonicalization is
    /// idempotent, so the same logical expression always stores the same text
    /// and a PATCH carrying an equivalent expression is not a new rule.
    pub fn parse(expression: &str, dom_dow_mode: DomDowMode) -> Result<Self, DomainError> {
        if expression.is_empty() || expression.len() > MAX_CRON_EXPRESSION_BYTES {
            return Err(DomainError::ScheduleInvalid);
        }
        let fields: Vec<&str> = expression.split_whitespace().collect();
        if fields.len() != 5 {
            return Err(DomainError::ScheduleInvalid);
        }
        let minutes = parse_field(fields[0], MINUTE_SPEC)?;
        let hours = parse_field(fields[1], HOUR_SPEC)?;
        let days_of_month = parse_field(fields[2], DOM_SPEC)?;
        let months = parse_field(fields[3], MONTH_SPEC)?;
        let days_of_week = parse_field(fields[4], DOW_SPEC)?;
        let normalized = format!(
            "{} {} {} {} {}",
            render_field(&minutes, MINUTE_SPEC),
            render_field(&hours, HOUR_SPEC),
            render_field(&days_of_month, DOM_SPEC),
            render_field(&months, MONTH_SPEC),
            render_field(&days_of_week, DOW_SPEC),
        );
        Ok(Self {
            minutes,
            hours,
            days_of_month,
            months,
            days_of_week,
            dom_dow_mode,
            normalized,
        })
    }

    /// The stored canonical text.
    pub fn normalized(&self) -> &str {
        &self.normalized
    }

    pub const fn dom_dow_mode(&self) -> DomDowMode {
        self.dom_dow_mode
    }

    /// A date matches when month matches and the day-of-month/day-of-week
    /// combination satisfies the configured mode.
    fn matches_date(&self, year: i64, month: u32, day: u32) -> bool {
        if !self.months.matches(MONTH_SPEC, month) {
            return false;
        }
        let dom_hit = self.days_of_month.matches(DOM_SPEC, day);
        let dow_hit = self
            .days_of_week
            .matches(DOW_SPEC, weekday_from_civil(year, month, day));
        match self.dom_dow_mode {
            DomDowMode::And => dom_hit && dow_hit,
            DomDowMode::Or => {
                let dom_full = self.days_of_month.is_full(DOM_SPEC);
                let dow_full = self.days_of_week.is_full(DOW_SPEC);
                match (dom_full, dow_full) {
                    (true, true) => true,
                    (true, false) => dow_hit,
                    (false, true) => dom_hit,
                    (false, false) => dom_hit || dow_hit,
                }
            }
        }
    }

    /// Ascending minutes-of-day for a date, or an empty list when the date does
    /// not match.
    fn minutes_of_day(&self, year: i64, month: u32, day: u32) -> Vec<i64> {
        if !self.matches_date(year, month, day) {
            return Vec::new();
        }
        let mut minutes = Vec::with_capacity(60);
        for hour in 0..=23_u32 {
            if !self.hours.matches(HOUR_SPEC, hour) {
                continue;
            }
            for minute in 0..=59_u32 {
                if self.minutes.matches(MINUTE_SPEC, minute) {
                    minutes.push(i64::from(hour * 3_600 + minute * 60));
                }
            }
        }
        minutes
    }
}

fn parse_field(text: &str, spec: FieldSpec) -> Result<Field, DomainError> {
    if text.is_empty() {
        return Err(DomainError::ScheduleInvalid);
    }
    let mut field = Field::empty(spec);
    for part in text.split(',') {
        let part = part.trim();
        if part.is_empty() {
            return Err(DomainError::ScheduleInvalid);
        }
        let (base, step) = match part.split_once('/') {
            Some((base, step)) => {
                if step.contains('/') {
                    return Err(DomainError::ScheduleInvalid);
                }
                let step = parse_value(step, spec)?;
                if step == 0 || step > spec.max {
                    return Err(DomainError::ScheduleInvalid);
                }
                (base, step)
            }
            None => (part, 1),
        };

        let (low, high) = if base == "*" {
            (spec.min, spec.max)
        } else if let Some((from, to)) = base.split_once('-') {
            let low = parse_value(from, spec)?;
            let high = parse_value(to, spec)?;
            if low > high {
                return Err(DomainError::ScheduleInvalid);
            }
            (low, high)
        } else {
            let value = parse_value(base, spec)?;
            if step == 1 {
                (value, value)
            } else {
                (value, spec.max)
            }
        };

        let mut value = low;
        while value <= high {
            field.insert(spec, value)?;
            match value.checked_add(step) {
                Some(next) => value = next,
                None => break,
            }
        }
    }
    if field.mask == 0 {
        return Err(DomainError::ScheduleInvalid);
    }
    Ok(field)
}

fn parse_value(text: &str, spec: FieldSpec) -> Result<u32, DomainError> {
    if text.is_empty() {
        return Err(DomainError::ScheduleInvalid);
    }
    if let Ok(value) = text.parse::<u32>() {
        return Ok(value);
    }
    let lowered = text.to_ascii_lowercase();
    spec.names
        .iter()
        .find(|(name, _)| *name == lowered)
        .map(|(_, value)| *value)
        .ok_or(DomainError::ScheduleInvalid)
}

fn render_field(field: &Field, spec: FieldSpec) -> String {
    if field.is_full(spec) {
        return "*".to_owned();
    }
    let mut rendered = Vec::new();
    for value in spec.min..=spec.max {
        if field.matches(spec, value) {
            rendered.push(value.to_string());
        }
    }
    rendered.join(",")
}

impl fmt::Display for CronExpression {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.normalized)
    }
}

// ---------------------------------------------------------------------------
// Schedule rule
// ---------------------------------------------------------------------------

/// The immutable canonical schedule revision.
///
/// `schedule_rule_id` is immutable: editing or rolling back a schedule mints a
/// new revision, and therefore a new logical occurrence slot. This type never
/// carries a revision identifier itself; the adapter supplies it when it
/// computes an occurrence identity key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ScheduleRule {
    OneTime(OneTimeSchedule),
    Cron(CronSchedule),
    Interval(IntervalSchedule),
    Manual(ManualSchedule),
}

#[derive(Deserialize)]
#[serde(untagged, deny_unknown_fields)]
enum ScheduleRuleWire {
    OneTime(OneTimeWire),
    Cron(CronWire),
    Interval(IntervalWire),
    Manual(ManualWire),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OneTimeWire {
    kind: ScheduleKind,
    scheduled_at: Timestamp,
    #[serde(default)]
    overlap_policy: Option<OverlapPolicy>,
    #[serde(default)]
    missed_policy: Option<MissedPolicy>,
    #[serde(default)]
    catch_up_limit: Option<u8>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CronWire {
    kind: ScheduleKind,
    expression: String,
    timezone: TimezoneId,
    #[serde(default)]
    dom_dow_mode: Option<DomDowMode>,
    #[serde(default)]
    dst_policy: Option<DstPolicy>,
    #[serde(default)]
    overlap_policy: Option<OverlapPolicy>,
    #[serde(default)]
    missed_policy: Option<MissedPolicy>,
    #[serde(default)]
    catch_up_limit: Option<u8>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IntervalWire {
    kind: ScheduleKind,
    every: u16,
    unit: IntervalUnit,
    anchor_at: Timestamp,
    timezone: TimezoneId,
    #[serde(default)]
    by_weekday: Option<Vec<u8>>,
    #[serde(default)]
    by_monthday: Option<Vec<u8>>,
    #[serde(default)]
    by_month: Option<Vec<u8>>,
    #[serde(default)]
    overlap_policy: Option<OverlapPolicy>,
    #[serde(default)]
    missed_policy: Option<MissedPolicy>,
    #[serde(default)]
    catch_up_limit: Option<u8>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ManualWire {
    kind: ScheduleKind,
    #[serde(default)]
    overlap_policy: Option<OverlapPolicy>,
    #[serde(default)]
    missed_policy: Option<MissedPolicy>,
    #[serde(default)]
    catch_up_limit: Option<u8>,
}

impl<'de> Deserialize<'de> for ScheduleRule {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = ScheduleRuleWire::deserialize(deserializer)?;
        // A rejected rule is a single stable reason, never a serde message that
        // could echo the offending expression, timezone, or selector back to a
        // client. `DomainError::code()` is the only text that escapes.
        ScheduleRule::from_wire(wire).map_err(|error| serde::de::Error::custom(error.code()))
    }
}

impl ScheduleRule {
    /// Validate a decoded wire schedule into the canonical domain rule.
    ///
    /// Kept separate from `Deserialize` so every validation branch can use `?`
    /// against `DomainError` and the serde boundary maps the single failure
    /// point, instead of each call site converting a domain error into a serde
    /// error type.
    fn from_wire(wire: ScheduleRuleWire) -> Result<Self, DomainError> {
        Ok(match wire {
            ScheduleRuleWire::OneTime(wire) => {
                expect_kind(wire.kind, ScheduleKind::OneTime)?;
                ScheduleRule::OneTime(OneTimeSchedule {
                    scheduled_at: wire.scheduled_at,
                    overlap_policy: wire.overlap_policy.unwrap_or(DEFAULT_OVERLAP_POLICY),
                    missed_policy: wire.missed_policy.unwrap_or(DEFAULT_MISSED_POLICY),
                    catch_up_limit: validate_catch_up_limit(
                        wire.missed_policy.unwrap_or(DEFAULT_MISSED_POLICY),
                        wire.catch_up_limit,
                    )?,
                })
            }
            ScheduleRuleWire::Cron(wire) => {
                expect_kind(wire.kind, ScheduleKind::Cron)?;
                let dom_dow_mode = wire.dom_dow_mode.unwrap_or_default();
                let parsed = CronExpression::parse(&wire.expression, dom_dow_mode)?;
                ScheduleRule::Cron(CronSchedule {
                    expression: parsed.normalized().to_owned(),
                    timezone: wire.timezone,
                    dom_dow_mode,
                    dst_policy: wire.dst_policy.unwrap_or_default(),
                    overlap_policy: wire.overlap_policy.unwrap_or(DEFAULT_OVERLAP_POLICY),
                    missed_policy: wire.missed_policy.unwrap_or(DEFAULT_MISSED_POLICY),
                    catch_up_limit: validate_catch_up_limit(
                        wire.missed_policy.unwrap_or(DEFAULT_MISSED_POLICY),
                        wire.catch_up_limit,
                    )?,
                    parsed,
                })
            }
            ScheduleRuleWire::Interval(wire) => {
                expect_kind(wire.kind, ScheduleKind::Interval)?;
                // `every` is bounded at the wire boundary. A zero or unbounded
                // interval would let a client request a schedule that generates
                // unbounded work, so it is rejected here rather than only when
                // the interval is evaluated.
                if !(MIN_INTERVAL_EVERY..=MAX_INTERVAL_EVERY).contains(&wire.every) {
                    return Err(DomainError::ScheduleIntervalInvalid);
                }
                // Resolve the anchor instant before moving it into the struct so
                // the validated epoch seconds and the stored wire text cannot
                // disagree.
                let anchor_seconds = parse_instant_utc(wire.anchor_at.as_str())?;
                ScheduleRule::Interval(IntervalSchedule {
                    every: wire.every,
                    unit: wire.unit,
                    anchor_at: wire.anchor_at,
                    timezone: wire.timezone,
                    by_weekday: normalize_selectors(wire.by_weekday, SelectorKind::Weekday)?,
                    by_monthday: normalize_selectors(wire.by_monthday, SelectorKind::Monthday)?,
                    by_month: normalize_selectors(wire.by_month, SelectorKind::Month)?,
                    overlap_policy: wire.overlap_policy.unwrap_or(DEFAULT_OVERLAP_POLICY),
                    missed_policy: wire.missed_policy.unwrap_or(DEFAULT_MISSED_POLICY),
                    catch_up_limit: validate_catch_up_limit(
                        wire.missed_policy.unwrap_or(DEFAULT_MISSED_POLICY),
                        wire.catch_up_limit,
                    )?,
                    anchor_seconds,
                })
            }
            ScheduleRuleWire::Manual(wire) => {
                expect_kind(wire.kind, ScheduleKind::Manual)?;
                ScheduleRule::Manual(ManualSchedule {
                    overlap_policy: wire.overlap_policy.unwrap_or(DEFAULT_OVERLAP_POLICY),
                    missed_policy: wire.missed_policy.unwrap_or(DEFAULT_MISSED_POLICY),
                    catch_up_limit: validate_catch_up_limit(
                        wire.missed_policy.unwrap_or(DEFAULT_MISSED_POLICY),
                        wire.catch_up_limit,
                    )?,
                })
            }
        })
    }
}

fn expect_kind(actual: ScheduleKind, expected: ScheduleKind) -> Result<(), DomainError> {
    if actual == expected {
        Ok(())
    } else {
        Err(DomainError::ScheduleInvalid)
    }
}

fn validate_catch_up_limit(
    missed_policy: MissedPolicy,
    catch_up_limit: Option<u8>,
) -> Result<Option<u8>, DomainError> {
    // The gate requires `catch_up` to carry a bounded positive limit. It also
    // shows `catch_up_limit` alongside `run_once` in its own examples, so a
    // present-but-unused limit is tolerated (still range-checked) rather than
    // rejected.
    match catch_up_limit {
        Some(limit) if !(MIN_CATCH_UP_LIMIT..=MAX_CATCH_UP_LIMIT).contains(&limit) => {
            Err(DomainError::ScheduleInvalid)
        }
        Some(_) => Ok(catch_up_limit),
        None if missed_policy == MissedPolicy::CatchUp => Err(DomainError::ScheduleInvalid),
        None => Ok(None),
    }
}

/// A single UTC instant with no recurrence.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OneTimeSchedule {
    pub scheduled_at: Timestamp,
    #[serde(
        default = "default_overlap_policy",
        skip_serializing_if = "is_default_overlap"
    )]
    pub overlap_policy: OverlapPolicy,
    #[serde(
        default = "default_missed_policy",
        skip_serializing_if = "is_default_missed"
    )]
    pub missed_policy: MissedPolicy,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub catch_up_limit: Option<u8>,
}

/// A canonical five-field cron expression in an IANA timezone.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CronSchedule {
    /// The normalized expression. The server stores the canonical text, not the
    /// caller's display spelling.
    pub expression: String,
    /// Validated, opaque. Resolved to transitions by the adapter.
    pub timezone: TimezoneId,
    pub dom_dow_mode: DomDowMode,
    pub dst_policy: DstPolicy,
    #[serde(
        default = "default_overlap_policy",
        skip_serializing_if = "is_default_overlap"
    )]
    pub overlap_policy: OverlapPolicy,
    #[serde(
        default = "default_missed_policy",
        skip_serializing_if = "is_default_missed"
    )]
    pub missed_policy: MissedPolicy,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub catch_up_limit: Option<u8>,
    #[serde(skip)]
    parsed: CronExpression,
}

impl<'de> Deserialize<'de> for CronSchedule {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = CronWire::deserialize(deserializer)?;
        // Single mapped failure point: a rejected cron surfaces only its stable
        // reason code, never the offending expression text.
        CronSchedule::from_wire(wire).map_err(|error| serde::de::Error::custom(error.code()))
    }
}

impl CronSchedule {
    fn from_wire(wire: CronWire) -> Result<Self, DomainError> {
        expect_kind(wire.kind, ScheduleKind::Cron)?;
        let dom_dow_mode = wire.dom_dow_mode.unwrap_or_default();
        let parsed = CronExpression::parse(&wire.expression, dom_dow_mode)?;
        Ok(Self {
            expression: parsed.normalized().to_owned(),
            timezone: wire.timezone,
            dom_dow_mode,
            dst_policy: wire.dst_policy.unwrap_or_default(),
            overlap_policy: wire.overlap_policy.unwrap_or(DEFAULT_OVERLAP_POLICY),
            missed_policy: wire.missed_policy.unwrap_or(DEFAULT_MISSED_POLICY),
            catch_up_limit: validate_catch_up_limit(
                wire.missed_policy.unwrap_or(DEFAULT_MISSED_POLICY),
                wire.catch_up_limit,
            )?,
            parsed,
        })
    }
}

impl CronSchedule {
    /// The parsed expression. Re-parsing a stored revision is deterministic, so
    /// a caller may also build one from [`CronSchedule::new`].
    pub fn cron(&self) -> &CronExpression {
        &self.parsed
    }
}

/// Product-level interval schedule.
///
/// `minutes`/`hours` step by elapsed seconds from the anchor. `days`/`weeks`/
/// `months`/`years` step in the zone's local civil calendar from the anchor's
/// local time of day, and an invalid calendar date is skipped rather than rolled
/// into another period — a 31st-of-the-month anchor does not run in February.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IntervalSchedule {
    pub every: u16,
    pub unit: IntervalUnit,
    pub anchor_at: Timestamp,
    pub timezone: TimezoneId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub by_weekday: Option<Vec<u8>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub by_monthday: Option<Vec<u8>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub by_month: Option<Vec<u8>>,
    #[serde(
        default = "default_overlap_policy",
        skip_serializing_if = "is_default_overlap"
    )]
    pub overlap_policy: OverlapPolicy,
    #[serde(
        default = "default_missed_policy",
        skip_serializing_if = "is_default_missed"
    )]
    pub missed_policy: MissedPolicy,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub catch_up_limit: Option<u8>,
    #[serde(skip)]
    anchor_seconds: i64,
}

impl<'de> Deserialize<'de> for IntervalSchedule {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // `IntervalSchedule` is always built through `ScheduleRule`'s validated
        // wire path, which also resolves `anchor_seconds` from `anchor_at`.
        // Reaching this impl directly means a caller tried to decode a bare
        // interval without its anchor, which is not a representable rule.
        let _ = deserializer;
        Err(serde::de::Error::custom(
            DomainError::ScheduleIntervalInvalid.code(),
        ))
    }
}

/// No clock schedule. Only an authorized `run-now` may create an occurrence.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManualSchedule {
    #[serde(
        default = "default_overlap_policy",
        skip_serializing_if = "is_default_overlap"
    )]
    pub overlap_policy: OverlapPolicy,
    #[serde(
        default = "default_missed_policy",
        skip_serializing_if = "is_default_missed"
    )]
    pub missed_policy: MissedPolicy,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub catch_up_limit: Option<u8>,
}

fn default_overlap_policy() -> OverlapPolicy {
    DEFAULT_OVERLAP_POLICY
}

fn default_missed_policy() -> MissedPolicy {
    DEFAULT_MISSED_POLICY
}

fn is_default_overlap(policy: &OverlapPolicy) -> bool {
    *policy == DEFAULT_OVERLAP_POLICY
}

fn is_default_missed(policy: &MissedPolicy) -> bool {
    *policy == DEFAULT_MISSED_POLICY
}

impl ScheduleRule {
    /// Build a one-time rule, validating the instant.
    pub fn one_time(
        scheduled_at: &str,
        overlap_policy: OverlapPolicy,
        missed_policy: MissedPolicy,
        catch_up_limit: Option<u8>,
    ) -> Result<Self, DomainError> {
        parse_instant_utc(scheduled_at)?;
        Ok(Self::OneTime(OneTimeSchedule {
            scheduled_at: Timestamp::new(scheduled_at).map_err(|_| DomainError::ScheduleInvalid)?,
            overlap_policy,
            missed_policy,
            catch_up_limit: validate_catch_up_limit(missed_policy, catch_up_limit)?,
        }))
    }

    /// Build a cron rule. The stored expression is the canonical text.
    #[allow(clippy::too_many_arguments)]
    pub fn cron(
        expression: &str,
        timezone: &str,
        dom_dow_mode: DomDowMode,
        dst_policy: DstPolicy,
        overlap_policy: OverlapPolicy,
        missed_policy: MissedPolicy,
        catch_up_limit: Option<u8>,
    ) -> Result<Self, DomainError> {
        let parsed = CronExpression::parse(expression, dom_dow_mode)?;
        Ok(Self::Cron(CronSchedule {
            expression: parsed.normalized().to_owned(),
            timezone: TimezoneId::new(timezone)?,
            dom_dow_mode,
            dst_policy,
            overlap_policy,
            missed_policy,
            catch_up_limit: validate_catch_up_limit(missed_policy, catch_up_limit)?,
            parsed,
        }))
    }

    /// Build an interval rule.
    #[allow(clippy::too_many_arguments)]
    pub fn interval(
        every: u16,
        unit: IntervalUnit,
        anchor_at: &str,
        timezone: &str,
        selectors: IntervalSelectors,
        overlap_policy: OverlapPolicy,
        missed_policy: MissedPolicy,
        catch_up_limit: Option<u8>,
    ) -> Result<Self, DomainError> {
        if !(MIN_INTERVAL_EVERY..=MAX_INTERVAL_EVERY).contains(&every) {
            return Err(DomainError::ScheduleIntervalInvalid);
        }
        let anchor_seconds = parse_instant_utc(anchor_at)?;
        Ok(Self::Interval(IntervalSchedule {
            every,
            unit,
            anchor_at: Timestamp::new(anchor_at).map_err(|_| DomainError::ScheduleInvalid)?,
            timezone: TimezoneId::new(timezone)?,
            by_weekday: normalize_selectors(selectors.by_weekday, SelectorKind::Weekday)?,
            by_monthday: normalize_selectors(selectors.by_monthday, SelectorKind::Monthday)?,
            by_month: normalize_selectors(selectors.by_month, SelectorKind::Month)?,
            overlap_policy,
            missed_policy,
            catch_up_limit: validate_catch_up_limit(missed_policy, catch_up_limit)?,
            anchor_seconds,
        }))
    }

    /// A manual rule. Only `run-now` may create an occurrence for it.
    pub fn manual(
        overlap_policy: OverlapPolicy,
        missed_policy: MissedPolicy,
        catch_up_limit: Option<u8>,
    ) -> Result<Self, DomainError> {
        Ok(Self::Manual(ManualSchedule {
            overlap_policy,
            missed_policy,
            catch_up_limit: validate_catch_up_limit(missed_policy, catch_up_limit)?,
        }))
    }

    pub const fn kind(&self) -> ScheduleKind {
        match self {
            Self::OneTime(_) => ScheduleKind::OneTime,
            Self::Cron(_) => ScheduleKind::Cron,
            Self::Interval(_) => ScheduleKind::Interval,
            Self::Manual(_) => ScheduleKind::Manual,
        }
    }

    pub const fn overlap_policy(&self) -> OverlapPolicy {
        match self {
            Self::OneTime(rule) => rule.overlap_policy,
            Self::Cron(rule) => rule.overlap_policy,
            Self::Interval(rule) => rule.overlap_policy,
            Self::Manual(rule) => rule.overlap_policy,
        }
    }

    pub const fn missed_policy(&self) -> MissedPolicy {
        match self {
            Self::OneTime(rule) => rule.missed_policy,
            Self::Cron(rule) => rule.missed_policy,
            Self::Interval(rule) => rule.missed_policy,
            Self::Manual(rule) => rule.missed_policy,
        }
    }

    pub const fn catch_up_limit(&self) -> Option<u8> {
        match self {
            Self::OneTime(rule) => rule.catch_up_limit,
            Self::Cron(rule) => rule.catch_up_limit,
            Self::Interval(rule) => rule.catch_up_limit,
            Self::Manual(rule) => rule.catch_up_limit,
        }
    }

    /// `false` for `manual`, which never produces a scheduled instant.
    pub const fn produces_scheduled_instants(&self) -> bool {
        !matches!(self, Self::Manual(_))
    }
}

/// Optional interval calendar selectors, before normalization.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IntervalSelectors {
    /// `0 = Sunday` .. `6 = Saturday`, matching the frozen cron numbering.
    pub by_weekday: Option<Vec<u8>>,
    /// `1` .. `31`.
    pub by_monthday: Option<Vec<u8>>,
    /// `1` .. `12`.
    pub by_month: Option<Vec<u8>>,
}

const MAX_SELECTOR_VALUES: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SelectorKind {
    Weekday,
    Monthday,
    Month,
}

impl SelectorKind {
    const fn bounds(self) -> (u8, u8) {
        match self {
            Self::Weekday => (0, 6),
            Self::Monthday => (1, 31),
            Self::Month => (1, 12),
        }
    }
}

fn normalize_selectors(
    values: Option<Vec<u8>>,
    kind: SelectorKind,
) -> Result<Option<Vec<u8>>, DomainError> {
    let Some(values) = values else {
        return Ok(None);
    };
    if values.is_empty() || values.len() > MAX_SELECTOR_VALUES {
        return Err(DomainError::ScheduleIntervalInvalid);
    }
    let (min, max) = kind.bounds();
    let mut normalized: Vec<u8> = Vec::with_capacity(values.len());
    for value in values {
        if !(min..=max).contains(&value) {
            return Err(DomainError::ScheduleIntervalInvalid);
        }
        if !normalized.contains(&value) {
            normalized.push(value);
        }
    }
    normalized.sort_unstable();
    Ok(Some(normalized))
}

impl IntervalSchedule {
    pub const fn every(&self) -> u16 {
        self.every
    }

    pub const fn unit(&self) -> IntervalUnit {
        self.unit
    }

    /// The anchor as epoch seconds.
    pub const fn anchor_seconds(&self) -> i64 {
        self.anchor_seconds
    }

    /// Whether a local civil date passes the configured selectors. An absent
    /// selector set matches everything; the selectors are applied uniformly to
    /// elapsed and calendar units so a stored rule has one meaning.
    pub fn selectors_allow(&self, year: i64, month: u32, day: u32) -> bool {
        if let Some(months) = &self.by_month
            && !months.contains(&(month as u8))
        {
            return false;
        }
        if let Some(days) = &self.by_monthday
            && !days.contains(&(day as u8))
        {
            return false;
        }
        if let Some(weekdays) = &self.by_weekday
            && !weekdays.contains(&(weekday_from_civil(year, month, day) as u8))
        {
            return false;
        }
        true
    }
}

// ---------------------------------------------------------------------------
// Instant enumeration
// ---------------------------------------------------------------------------

/// One canonical schedule slot and what the frozen contract says happens to it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScheduleInstant {
    /// The canonical UTC instant. This value — not the local civil time and not
    /// the display expression — is the occurrence identity input.
    pub scheduled_for_utc: i64,
    pub outcome: ScheduleInstantOutcome,
}

impl ScheduleInstant {
    /// The canonical RFC 3339 form of the slot.
    pub fn scheduled_for(&self) -> Result<String, DomainError> {
        format_instant_utc(self.scheduled_for_utc)
    }

    pub const fn is_due(&self) -> bool {
        matches!(self.outcome, ScheduleInstantOutcome::Due)
    }
}

/// Whether a schedule slot creates an occurrence or is deliberately skipped.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScheduleInstantOutcome {
    /// Create one occurrence at this instant.
    Due,
    /// Create none. The reason is one of the frozen stable codes, which the
    /// adapter persists on the occurrence.
    Skipped(DomainError),
}

/// A bounded, deterministic generation pass over one schedule revision.
///
/// The budget is shared by design: a missed-window scan calls this repeatedly
/// with an advancing cursor, and the sum of all calls stays bounded so a Worker
/// request cannot spin.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CandidateBudget {
    remaining: u32,
}

impl CandidateBudget {
    const fn new() -> Self {
        Self {
            remaining: MAX_SCHEDULE_CANDIDATES,
        }
    }

    /// Returns `false` once the pass must stop.
    fn spend(&mut self, count: u32) -> bool {
        if count > self.remaining {
            self.remaining = 0;
            return false;
        }
        self.remaining -= count;
        true
    }

    const fn exhausted(&self) -> bool {
        self.remaining == 0
    }
}

/// Enumerate the next due instants strictly after `after_utc`.
///
/// `limit` is clamped to [`MAX_NEXT_INSTANTS`]. A pathological rule whose
/// selectors reject every slot inside the candidate budget returns the instants
/// found so far; the caller re-invokes with the returned instant as the new
/// cursor. Determinism is the contract: the same rule, zone, and cursor always
/// produce the same instants in the same order.
pub fn next_due_instants(
    rule: &ScheduleRule,
    zone: &ZoneOffsets,
    after_utc: i64,
    limit: usize,
) -> Result<Vec<ScheduleInstant>, DomainError> {
    let limit = limit.clamp(1, MAX_NEXT_INSTANTS);
    let mut budget = CandidateBudget::new();
    generate(rule, zone, after_utc, limit, &mut budget)
}

/// The first due instant strictly after `after_utc`, ignoring explicit skips.
pub fn next_due_instant(
    rule: &ScheduleRule,
    zone: &ZoneOffsets,
    after_utc: i64,
) -> Result<Option<ScheduleInstant>, DomainError> {
    Ok(next_due_instants(rule, zone, after_utc, MAX_NEXT_INSTANTS)?
        .into_iter()
        .find(ScheduleInstant::is_due))
}

/// The bounded plan for every schedule slot missed between a cursor and `now`.
///
/// Determinism and boundedness are the whole point: a device that reconnects
/// after a long offline period must not produce a burst, and re-running the
/// planning step for the same cursor must produce the same plan.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MissedRunPlan {
    /// Occurrences to create plus explicit schedule-slot skips, ascending by
    /// canonical UTC instant.
    pub instants: Vec<ScheduleInstant>,
    /// The authoritative cursor to persist transactionally with the generated
    /// occurrences. Always the supplied `now`: planning has now considered every
    /// slot up to it.
    pub cursor_after: i64,
    /// `true` when the seven-day history window clamped the scan, when the
    /// `catch_up_limit` dropped older due slots, or when the candidate budget
    /// ran out. The adapter should surface this as
    /// `automation_missed_schedule_limit`.
    pub truncated: bool,
    /// How many due slots the missed policy considered. Useful for
    /// observability even when the policy produced no occurrence.
    pub missed_slots: usize,
}

impl MissedRunPlan {
    /// The canonical instants that should become occurrences, ascending.
    pub fn due_instants(&self) -> Vec<i64> {
        self.instants
            .iter()
            .filter(|instant| instant.is_due())
            .map(|instant| instant.scheduled_for_utc)
            .collect()
    }
}

/// Plan the missed-run work between an authoritative cursor and `now`.
///
/// Policy interpretation, stated explicitly because the gate does not spell it
/// out:
///
/// - `skip` produces no occurrence. A missed slot is not evidence that the
///   schedule slot exists and was deliberately declined, so there is no
///   occurrence to record a reason on.
/// - `run_once` coalesces to the **most recent** missed slot, not the oldest.
///   Coalescing forward is what makes the default safe after a long outage: the
///   product runs the current slot once instead of replaying stale work.
/// - `catch_up(limit)` replays the `limit` most recent missed slots in
///   ascending order, bounded by `catch_up_limit` (1–20) and by the seven-day
///   window. Both bounds can truncate; `truncated` reports it.
/// - A slot that DST deliberately skipped (`dst_missing_time`, or the duplicate
///   half of a repeated time under `skip_duplicate`) is *always* reported, even
///   under `skip`. Those are explicit decisions about a slot that exists, not
///   an outage artifact, and the frozen contract requires the stable reason to
///   be recorded.
pub fn missed_run_plan(
    rule: &ScheduleRule,
    zone: &ZoneOffsets,
    cursor_utc: i64,
    now_utc: i64,
) -> Result<MissedRunPlan, DomainError> {
    if now_utc < cursor_utc {
        // A regressed cursor or clock is not a decision the domain may guess at.
        return Err(DomainError::ScheduleInvalid);
    }

    let window_start = now_utc.saturating_sub(MAX_MISSED_HISTORY_DAYS * SECONDS_PER_DAY);
    let mut truncated = false;
    let mut scan_start = cursor_utc;
    if scan_start < window_start {
        scan_start = window_start;
        truncated = true;
    }

    let keep = match rule.missed_policy() {
        MissedPolicy::Skip => 1,
        MissedPolicy::RunOnce => 1,
        MissedPolicy::CatchUp => usize::from(
            rule.catch_up_limit()
                .unwrap_or(MAX_CATCH_UP_LIMIT)
                .clamp(MIN_CATCH_UP_LIMIT, MAX_CATCH_UP_LIMIT),
        ),
    };

    let mut budget = CandidateBudget::new();
    let mut cursor = scan_start;
    let mut due_ring: Vec<ScheduleInstant> = Vec::with_capacity(keep);
    let mut skipped: Vec<ScheduleInstant> = Vec::new();
    let mut due_slots = 0_usize;
    let mut truncated_by_budget = false;

    loop {
        let batch = generate(rule, zone, cursor, keep.max(1), &mut budget)?;
        let Some(last) = batch.last().copied() else {
            break;
        };
        for instant in batch {
            match instant.outcome {
                ScheduleInstantOutcome::Due => {
                    due_slots += 1;
                    if due_ring.len() == keep {
                        due_ring.remove(0);
                    }
                    due_ring.push(instant);
                }
                ScheduleInstantOutcome::Skipped(_) => {
                    if skipped.len() == MAX_NEXT_INSTANTS {
                        truncated = true;
                    } else {
                        skipped.push(instant);
                    }
                }
            }
        }
        if last.scheduled_for_utc <= cursor {
            break;
        }
        cursor = last.scheduled_for_utc;
        if budget.exhausted() {
            truncated_by_budget = true;
            break;
        }
    }

    if due_slots > due_ring.len() {
        truncated = true;
    }
    if truncated_by_budget {
        truncated = true;
    }

    let mut instants = skipped;
    instants.extend(due_ring);
    instants.sort_by_key(|instant| instant.scheduled_for_utc);

    Ok(MissedRunPlan {
        instants,
        cursor_after: now_utc,
        truncated,
        missed_slots: due_slots,
    })
}

/// Generate up to `limit` instants strictly after `after_utc`, consuming from a
/// shared candidate budget.
fn generate(
    rule: &ScheduleRule,
    zone: &ZoneOffsets,
    after_utc: i64,
    limit: usize,
    budget: &mut CandidateBudget,
) -> Result<Vec<ScheduleInstant>, DomainError> {
    let mut instants = Vec::with_capacity(limit);
    match rule {
        ScheduleRule::Manual(_) => {}
        ScheduleRule::OneTime(rule) => {
            let instant = parse_instant_utc(rule.scheduled_at.as_str())?;
            if instant > after_utc {
                if !budget.spend(1) {
                    return Ok(instants);
                }
                instants.push(ScheduleInstant {
                    scheduled_for_utc: instant,
                    outcome: ScheduleInstantOutcome::Due,
                });
            }
        }
        ScheduleRule::Cron(rule) => {
            generate_cron(rule, zone, after_utc, limit, budget, &mut instants)?
        }
        ScheduleRule::Interval(rule) => {
            generate_interval(rule, zone, after_utc, limit, budget, &mut instants)?
        }
    }
    Ok(instants)
}

fn generate_cron(
    rule: &CronSchedule,
    zone: &ZoneOffsets,
    after_utc: i64,
    limit: usize,
    budget: &mut CandidateBudget,
    out: &mut Vec<ScheduleInstant>,
) -> Result<(), DomainError> {
    let cron = rule.cron();
    let after_local = zone.to_local(after_utc);
    let start_day = after_local.div_euclid(SECONDS_PER_DAY);
    let start_time_of_day = after_local.rem_euclid(SECONDS_PER_DAY);

    for offset in 0..MAX_CRON_SEARCH_DAYS {
        if out.len() >= limit || budget.exhausted() {
            break;
        }
        if !budget.spend(1) {
            break;
        }
        let day = start_day + offset;
        let (year, month, day_of_month) = civil_from_days(day);
        let day_base = day * SECONDS_PER_DAY;
        let mut minutes = cron.minutes_of_day(year, month, day_of_month);
        if offset == 0 {
            minutes.retain(|minute| *minute > start_time_of_day);
        }
        for minute in minutes {
            if out.len() >= limit {
                break;
            }
            if !budget.spend(1) {
                return Ok(());
            }
            let local = day_base + minute;
            push_resolved(zone, local, rule.dst_policy, out);
        }
    }
    Ok(())
}

fn generate_interval(
    rule: &IntervalSchedule,
    zone: &ZoneOffsets,
    after_utc: i64,
    limit: usize,
    budget: &mut CandidateBudget,
    out: &mut Vec<ScheduleInstant>,
) -> Result<(), DomainError> {
    let every = i64::from(rule.every);
    let anchor_seconds = rule.anchor_seconds;
    let anchor_local = zone.to_local(anchor_seconds);
    let (anchor_year, anchor_month, anchor_day) =
        civil_from_days(anchor_local.div_euclid(SECONDS_PER_DAY));
    let anchor_time_of_day = anchor_local.rem_euclid(SECONDS_PER_DAY);
    let after_local = zone.to_local(after_utc);

    if rule.unit.is_elapsed() {
        let step = match rule.unit {
            IntervalUnit::Minutes => i64::from(rule.every) * SECONDS_PER_MINUTE,
            IntervalUnit::Hours => i64::from(rule.every) * SECONDS_PER_HOUR,
            _ => unreachable!("elapsed units are minutes and hours only"),
        };
        let mut step_index = (after_utc - anchor_seconds).div_euclid(step) + 1;
        while out.len() < limit {
            if !budget.spend(1) {
                break;
            }
            let Some(utc) = step_index
                .checked_mul(step)
                .and_then(|offset| anchor_seconds.checked_add(offset))
            else {
                break;
            };
            step_index += 1;
            if utc <= after_utc {
                continue;
            }
            let (year, month, day) =
                civil_from_days(zone.to_local(utc).div_euclid(SECONDS_PER_DAY));
            if rule.selectors_allow(year, month, day) {
                out.push(ScheduleInstant {
                    scheduled_for_utc: utc,
                    outcome: ScheduleInstantOutcome::Due,
                });
            }
        }
        return Ok(());
    }

    // Calendar arithmetic works in the zone's local civil calendar so a DST
    // change moves the slot with the local time of day instead of the elapsed
    // seconds.
    let (start_index, step_index_start) = match rule.unit {
        IntervalUnit::Months => {
            let base = anchor_year * 12 + i64::from(anchor_month) - 1;
            let (after_year, after_month, _) =
                civil_from_days(after_local.div_euclid(SECONDS_PER_DAY));
            let after_months = i64::from(after_month) + 12 * after_year - 1;
            (base, (after_months - base).div_euclid(every) + 1)
        }
        IntervalUnit::Years => {
            let after_year = civil_from_days(after_local.div_euclid(SECONDS_PER_DAY)).0;
            (
                anchor_year,
                (after_year - anchor_year).div_euclid(every) + 1,
            )
        }
        IntervalUnit::Days | IntervalUnit::Weeks => {
            let base = days_from_civil(anchor_year, anchor_month, anchor_day);
            let after_day = after_local.div_euclid(SECONDS_PER_DAY);
            let day_step = if rule.unit == IntervalUnit::Weeks {
                every * 7
            } else {
                every
            };
            (base, (after_day - base).div_euclid(day_step) + 1)
        }
        IntervalUnit::Minutes | IntervalUnit::Hours => unreachable!("handled above"),
    };

    let mut index = step_index_start;
    while out.len() < limit {
        if !budget.spend(1) {
            break;
        }
        let Some(local_epoch) = calendar_slot(
            rule.unit,
            start_index,
            index,
            every,
            anchor_month,
            anchor_day,
            anchor_time_of_day,
        ) else {
            // An invalid calendar date is skipped, never rolled forward.
            index += 1;
            continue;
        };
        index += 1;
        push_resolved(zone, local_epoch, DstPolicy::SkipDuplicate, out);
    }
    Ok(())
}

/// The local civil slot for calendar step `index`, or `None` when the date does
/// not exist in the target period.
fn calendar_slot(
    unit: IntervalUnit,
    base: i64,
    index: i64,
    every: i64,
    anchor_month: u32,
    anchor_day: u32,
    anchor_time_of_day: i64,
) -> Option<i64> {
    match unit {
        IntervalUnit::Days | IntervalUnit::Weeks => {
            let day_step = if unit == IntervalUnit::Weeks {
                every * 7
            } else {
                every
            };
            let target_day = base.checked_add(index.checked_mul(day_step)?)?;
            let (year, _, _) = civil_from_days(target_day);
            if !(MIN_CIVIL_YEAR..=MAX_CIVIL_YEAR).contains(&year) {
                return None;
            }
            Some(target_day * SECONDS_PER_DAY + anchor_time_of_day)
        }
        IntervalUnit::Months => {
            let target_month = base.checked_add(index.checked_mul(every)?)?;
            let year = target_month.div_euclid(12);
            let month = (target_month.rem_euclid(12) + 1) as u32;
            if !(MIN_CIVIL_YEAR..=MAX_CIVIL_YEAR).contains(&year)
                || anchor_day > days_in_month(year, month)
            {
                return None;
            }
            Some(days_from_civil(year, month, anchor_day) * SECONDS_PER_DAY + anchor_time_of_day)
        }
        IntervalUnit::Years => {
            let year = base.checked_add(index.checked_mul(every)?)?;
            if !(MIN_CIVIL_YEAR..=MAX_CIVIL_YEAR).contains(&year)
                || anchor_month > 12
                || anchor_day > days_in_month(year, anchor_month)
            {
                return None;
            }
            Some(
                days_from_civil(year, anchor_month, anchor_day) * SECONDS_PER_DAY
                    + anchor_time_of_day,
            )
        }
        IntervalUnit::Minutes | IntervalUnit::Hours => None,
    }
}

/// Apply the frozen DST policy to one local civil slot and push the result.
fn push_resolved(
    zone: &ZoneOffsets,
    local_epoch: i64,
    dst_policy: DstPolicy,
    out: &mut Vec<ScheduleInstant>,
) {
    match zone.resolve_local(local_epoch) {
        LocalResolution::Unique { utc } => out.push(ScheduleInstant {
            scheduled_for_utc: utc,
            outcome: ScheduleInstantOutcome::Due,
        }),
        LocalResolution::Missing => out.push(ScheduleInstant {
            scheduled_for_utc: local_epoch,
            outcome: ScheduleInstantOutcome::Skipped(DomainError::DstMissingTime),
        }),
        LocalResolution::Repeated {
            first_utc,
            second_utc,
        } => {
            out.push(ScheduleInstant {
                scheduled_for_utc: first_utc,
                outcome: ScheduleInstantOutcome::Due,
            });
            match dst_policy {
                DstPolicy::RunBoth => out.push(ScheduleInstant {
                    scheduled_for_utc: second_utc,
                    outcome: ScheduleInstantOutcome::Due,
                }),
                DstPolicy::SkipDuplicate => out.push(ScheduleInstant {
                    scheduled_for_utc: second_utc,
                    outcome: ScheduleInstantOutcome::Skipped(DomainError::DstRepeatedTime),
                }),
                DstPolicy::RunFirst => {}
            }
        }
    }
}
