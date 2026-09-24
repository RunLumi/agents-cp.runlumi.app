use std::{fmt, str::FromStr};

use serde::{Deserialize, Deserializer, Serialize};

use super::CoreError;

/// RFC 3339 timestamp in UTC (`Z`), retained in its supplied precision.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct Timestamp(String);

impl Timestamp {
    pub fn new(value: impl Into<String>) -> Result<Self, CoreError> {
        let value = value.into();
        if !is_rfc3339_utc(&value) {
            return Err(CoreError::InvalidTimestamp);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn is_rfc3339_utc(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() < 20
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
    {
        return false;
    }

    if !digits(bytes, 0, 4)
        || !digits(bytes, 5, 2)
        || !digits(bytes, 8, 2)
        || !digits(bytes, 11, 2)
        || !digits(bytes, 14, 2)
        || !digits(bytes, 17, 2)
    {
        return false;
    }

    let year = number(bytes, 0, 4);
    let month = number(bytes, 5, 2);
    let day = number(bytes, 8, 2);
    let hour = number(bytes, 11, 2);
    let minute = number(bytes, 14, 2);
    let second = number(bytes, 17, 2);
    if !(1..=12).contains(&month)
        || hour > 23
        || minute > 59
        || second > 60
        || day == 0
        || day > days_in_month(year, month)
    {
        return false;
    }

    match bytes.get(19) {
        Some(b'Z') if bytes.len() == 20 => true,
        Some(b'.') => {
            let fraction = &bytes[20..bytes.len().saturating_sub(1)];
            !fraction.is_empty()
                && fraction.iter().all(u8::is_ascii_digit)
                && bytes.last() == Some(&b'Z')
        }
        _ => false,
    }
}

fn digits(bytes: &[u8], start: usize, width: usize) -> bool {
    bytes
        .get(start..start + width)
        .is_some_and(|slice| slice.iter().all(u8::is_ascii_digit))
}

fn number(bytes: &[u8], start: usize, width: usize) -> u32 {
    bytes[start..start + width]
        .iter()
        .fold(0, |value, digit| value * 10 + u32::from(digit - b'0'))
}

fn days_in_month(year: u32, month: u32) -> u32 {
    match month {
        2 if year.is_multiple_of(400) || (year.is_multiple_of(4) && !year.is_multiple_of(100)) => {
            29
        }
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

impl fmt::Debug for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Timestamp").field(&self.0).finish()
    }
}

impl fmt::Display for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for Timestamp {
    type Err = CoreError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

impl<'de> Deserialize<'de> for Timestamp {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamp_keeps_utc_rfc3339_wire_text() {
        let timestamp: Timestamp = "2026-09-24T12:00:00.000Z".parse().unwrap();
        assert_eq!(timestamp.as_str(), "2026-09-24T12:00:00.000Z");
        assert_eq!(
            serde_json::to_string(&timestamp).unwrap(),
            "\"2026-09-24T12:00:00.000Z\""
        );
    }

    #[test]
    fn timestamps_validate_date_and_timezone() {
        for invalid in [
            "2026-02-29T12:00:00Z",
            "2026-09-24T25:00:00Z",
            "2026-09-24T12:00:00+00:00",
            "2026-09-24T12:00:00.abcZ",
            "2026-9-24T12:00:00Z",
            "2026-09-24 12:00:00Z",
        ] {
            assert!(Timestamp::new(invalid).is_err(), "accepted {invalid}");
            assert!(serde_json::from_str::<Timestamp>(&format!("\"{invalid}\"")).is_err());
        }
        assert!(Timestamp::new("2024-02-29T23:59:60Z").is_ok());
        assert!(Timestamp::new("2026-09-24T12:00:00Z").is_ok());
    }
}
