use crate::core::Timestamp;

/// Non-sensitive marker for a Worker clock value that could not be validated.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TimeError;

/// Obtain a canonical RFC 3339 UTC timestamp from the Worker runtime clock.
/// The conversion is performed by the platform Date implementation and returns
/// millisecond precision, matching the P01 SQLite timestamp convention.
pub fn now_utc() -> Result<Timestamp, TimeError> {
    let date = worker::js_sys::Date::from(worker::Date::now());
    Timestamp::new(date.to_iso_string()).map_err(|_| TimeError)
}
