use serde::Deserialize;
use worker::d1::D1PreparedStatement;

use crate::{
    adapters::d1::{BindValue, D1Adapter},
    core::{EventEnvelope, EventId, Timestamp},
    modules::outbox::{
        DeliveryStatus, FailureCode, FailureDisposition, FailureUpdate, OutboxRecord, OutboxStore,
        OutboxStoreError, StoreTransition,
    },
};

const INSERT_EVENT_SQL: &str = r#"
INSERT INTO outbox_events (
    event_id, event_type, occurred_at, request_id, correlation_id,
    organization_id, envelope_json, delivery_status, attempt_count, next_attempt_at
) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'pending', 0, ?3)
"#;

const LIST_DUE_SQL: &str = r#"
SELECT event_id, event_type, occurred_at, request_id, correlation_id,
       organization_id, envelope_json, delivery_status, attempt_count,
       next_attempt_at, queued_at, delivered_at, last_error_code
FROM outbox_events
WHERE delivery_status = 'pending'
  AND next_attempt_at <= ?1
ORDER BY next_attempt_at ASC, event_id ASC
LIMIT ?2
"#;

const MARK_QUEUED_SQL: &str = r#"
UPDATE outbox_events
SET delivery_status = 'queued',
    next_attempt_at = NULL,
    queued_at = ?1
WHERE event_id = ?2
  AND delivery_status = 'pending'
  AND attempt_count = ?3
  AND next_attempt_at <= ?1
"#;

const RECORD_RETRY_SQL: &str = r#"
UPDATE outbox_events
SET delivery_status = 'pending',
    attempt_count = ?1,
    next_attempt_at = strftime('%Y-%m-%dT%H:%M:%fZ', ?2, printf('+%d seconds', ?3)),
    last_error_code = ?4
WHERE event_id = ?5
  AND delivery_status = ?6
  AND attempt_count = ?7
"#;

const RECORD_DEAD_LETTER_SQL: &str = r#"
UPDATE outbox_events
SET delivery_status = 'dead_letter',
    attempt_count = ?1,
    next_attempt_at = NULL,
    last_error_code = ?2
WHERE event_id = ?3
  AND delivery_status = ?4
  AND attempt_count = ?5
"#;

const MARK_DELIVERED_SQL: &str = r#"
UPDATE outbox_events
SET delivery_status = 'delivered',
    next_attempt_at = NULL,
    delivered_at = ?1
WHERE event_id = ?2
  AND delivery_status IN ('pending', 'queued')
"#;

const MARK_DEAD_LETTER_SQL: &str = r#"
UPDATE outbox_events
SET delivery_status = 'dead_letter',
    next_attempt_at = NULL,
    last_error_code = ?1
WHERE event_id = ?2
  AND delivery_status IN ('pending', 'queued')
"#;

const GET_RECORD_SQL: &str = r#"
SELECT event_id, event_type, occurred_at, request_id, correlation_id,
       organization_id, envelope_json, delivery_status, attempt_count,
       next_attempt_at, queued_at, delivered_at, last_error_code
FROM outbox_events
WHERE event_id = ?1
LIMIT 1
"#;

#[derive(Deserialize)]
struct OutboxRow {
    event_id: String,
    event_type: String,
    occurred_at: String,
    request_id: String,
    correlation_id: String,
    organization_id: String,
    envelope_json: String,
    delivery_status: String,
    attempt_count: u32,
    next_attempt_at: Option<String>,
    queued_at: Option<String>,
    delivered_at: Option<String>,
    last_error_code: Option<String>,
}

/// D1 implementation of the outbox store port plus the initial event insert
/// statement used by idempotent business transactions.
pub struct OutboxRepository<'a> {
    database: &'a D1Adapter,
}

impl<'a> OutboxRepository<'a> {
    pub fn new(database: &'a D1Adapter) -> Self {
        Self { database }
    }

    /// Build the initial pending outbox insert. Use this prepared statement in
    /// the same D1 batch as the associated mutation and idempotency completion.
    pub fn insert_statement(
        &self,
        event: &EventEnvelope,
    ) -> Result<D1PreparedStatement, OutboxStoreError> {
        validate_event(event)?;
        let envelope_json =
            serde_json::to_string(event).map_err(|_| OutboxStoreError::InvalidRecord)?;
        self.database
            .prepare(
                INSERT_EVENT_SQL,
                &[
                    BindValue::Text(event.event_id.as_str()),
                    BindValue::Text(event.event_type.as_str()),
                    BindValue::Text(event.occurred_at.as_str()),
                    BindValue::Text(event.request_id.as_str()),
                    BindValue::Text(event.correlation_id.as_str()),
                    BindValue::Text(organization_scope(event)),
                    BindValue::Text(&envelope_json),
                ],
            )
            .map_err(|_| OutboxStoreError::Unavailable)
    }
}

impl<'a> OutboxStore for OutboxRepository<'a> {
    async fn list_due_pending(
        &self,
        now: &Timestamp,
        limit: u16,
    ) -> Result<Vec<OutboxRecord>, OutboxStoreError> {
        validate_timestamp(now)?;
        if !(1..=100).contains(&limit) {
            return Err(OutboxStoreError::InvalidRecord);
        }

        let statement = self
            .database
            .prepare(
                LIST_DUE_SQL,
                &[
                    BindValue::Text(now.as_str()),
                    BindValue::Integer(i32::from(limit)),
                ],
            )
            .map_err(|_| OutboxStoreError::Unavailable)?;
        let results = statement
            .all()
            .await
            .map_err(|_| OutboxStoreError::Unavailable)?;
        let rows = results
            .results::<OutboxRow>()
            .map_err(|_| OutboxStoreError::InvalidRecord)?;
        rows.into_iter().map(try_into_record).collect()
    }

    async fn mark_queued(
        &self,
        event_id: &EventId,
        expected_attempt_count: u32,
        queued_at: &Timestamp,
    ) -> Result<StoreTransition, OutboxStoreError> {
        validate_timestamp(queued_at)?;
        let statement = self
            .database
            .prepare(
                MARK_QUEUED_SQL,
                &[
                    BindValue::Text(queued_at.as_str()),
                    BindValue::Text(event_id.as_str()),
                    BindValue::Integer(sql_integer(expected_attempt_count)?),
                ],
            )
            .map_err(|_| OutboxStoreError::Unavailable)?;
        run_transition(statement).await
    }

    async fn record_failure(
        &self,
        event_id: &EventId,
        update: &FailureUpdate<'_>,
    ) -> Result<StoreTransition, OutboxStoreError> {
        validate_timestamp(update.failed_at)?;
        validate_failure_transition(
            update.expected_status,
            update.expected_attempt_count,
            update.new_attempt_count,
            update.disposition,
        )?;

        let statement = match update.disposition {
            FailureDisposition::Retry { delay_seconds } => self
                .database
                .prepare(
                    RECORD_RETRY_SQL,
                    &[
                        BindValue::Integer(sql_integer(update.new_attempt_count)?),
                        BindValue::Text(update.failed_at.as_str()),
                        BindValue::Integer(sql_integer(delay_seconds)?),
                        BindValue::Text(update.error_code.as_str()),
                        BindValue::Text(event_id.as_str()),
                        BindValue::Text(expected_status_as_str(update.expected_status)),
                        BindValue::Integer(sql_integer(update.expected_attempt_count)?),
                    ],
                )
                .map_err(|_| OutboxStoreError::Unavailable)?,
            FailureDisposition::DeadLetter => self
                .database
                .prepare(
                    RECORD_DEAD_LETTER_SQL,
                    &[
                        BindValue::Integer(sql_integer(update.new_attempt_count)?),
                        BindValue::Text(update.error_code.as_str()),
                        BindValue::Text(event_id.as_str()),
                        BindValue::Text(expected_status_as_str(update.expected_status)),
                        BindValue::Integer(sql_integer(update.expected_attempt_count)?),
                    ],
                )
                .map_err(|_| OutboxStoreError::Unavailable)?,
        };
        run_transition(statement).await
    }

    async fn mark_delivered(
        &self,
        event_id: &EventId,
        delivered_at: &Timestamp,
    ) -> Result<StoreTransition, OutboxStoreError> {
        validate_timestamp(delivered_at)?;
        let statement = self
            .database
            .prepare(
                MARK_DELIVERED_SQL,
                &[
                    BindValue::Text(delivered_at.as_str()),
                    BindValue::Text(event_id.as_str()),
                ],
            )
            .map_err(|_| OutboxStoreError::Unavailable)?;
        run_transition(statement).await
    }

    async fn mark_dead_letter(
        &self,
        event_id: &EventId,
        error_code: &FailureCode,
    ) -> Result<StoreTransition, OutboxStoreError> {
        let statement = self
            .database
            .prepare(
                MARK_DEAD_LETTER_SQL,
                &[
                    BindValue::Text(error_code.as_str()),
                    BindValue::Text(event_id.as_str()),
                ],
            )
            .map_err(|_| OutboxStoreError::Unavailable)?;
        run_transition(statement).await
    }

    async fn get_record(
        &self,
        event_id: &EventId,
    ) -> Result<Option<OutboxRecord>, OutboxStoreError> {
        let statement = self
            .database
            .prepare(GET_RECORD_SQL, &[BindValue::Text(event_id.as_str())])
            .map_err(|_| OutboxStoreError::Unavailable)?;
        let row = statement
            .first::<OutboxRow>(None)
            .await
            .map_err(|_| OutboxStoreError::Unavailable)?;
        row.map(try_into_record).transpose()
    }
}

async fn run_transition(
    statement: D1PreparedStatement,
) -> Result<StoreTransition, OutboxStoreError> {
    let result = statement
        .run()
        .await
        .map_err(|_| OutboxStoreError::Unavailable)?;
    match D1Adapter::changes(&result).map_err(|_| OutboxStoreError::Unavailable)? {
        0 => Ok(StoreTransition::NotApplied),
        1 => Ok(StoreTransition::Applied),
        _ => Err(OutboxStoreError::InvalidRecord),
    }
}

fn try_into_record(row: OutboxRow) -> Result<OutboxRecord, OutboxStoreError> {
    let event: EventEnvelope =
        serde_json::from_str(&row.envelope_json).map_err(|_| OutboxStoreError::InvalidRecord)?;
    if event.event_id.as_str() != row.event_id.as_str()
        || event.event_type.as_str() != row.event_type.as_str()
        || event.occurred_at.as_str() != row.occurred_at.as_str()
        || event.request_id.as_str() != row.request_id.as_str()
        || event.correlation_id.as_str() != row.correlation_id.as_str()
        || organization_scope(&event) != row.organization_id.as_str()
    {
        return Err(OutboxStoreError::InvalidRecord);
    }

    let delivery_status = parse_status(&row.delivery_status)?;
    let next_attempt_at = parse_optional_timestamp(row.next_attempt_at)?;
    let queued_at = parse_optional_timestamp(row.queued_at)?;
    let delivered_at = parse_optional_timestamp(row.delivered_at)?;
    let last_error_code = row
        .last_error_code
        .map(FailureCode::new)
        .transpose()
        .map_err(|_| OutboxStoreError::InvalidRecord)?;

    let valid_state = match delivery_status {
        DeliveryStatus::Pending => next_attempt_at.is_some() && delivered_at.is_none(),
        DeliveryStatus::Queued => next_attempt_at.is_none() && delivered_at.is_none(),
        DeliveryStatus::Delivered => next_attempt_at.is_none() && delivered_at.is_some(),
        DeliveryStatus::DeadLetter => next_attempt_at.is_none() && delivered_at.is_none(),
    };
    if !valid_state {
        return Err(OutboxStoreError::InvalidRecord);
    }

    Ok(OutboxRecord {
        event,
        delivery_status,
        attempt_count: row.attempt_count,
        next_attempt_at,
        queued_at,
        delivered_at,
        last_error_code,
    })
}

fn validate_event(event: &EventEnvelope) -> Result<(), OutboxStoreError> {
    validate_timestamp(&event.occurred_at)?;
    if event.event_type.as_str().chars().count() > 255
        || !within_text_limit(event.request_id.as_str(), 255)
        || !within_text_limit(event.correlation_id.as_str(), 255)
        || event
            .organization_id
            .as_ref()
            .is_some_and(|organization_id| !within_text_limit(organization_id.as_str(), 255))
    {
        return Err(OutboxStoreError::InvalidRecord);
    }
    Ok(())
}

fn validate_timestamp(timestamp: &Timestamp) -> Result<(), OutboxStoreError> {
    let bytes = timestamp.as_str().as_bytes();
    let valid = bytes.len() == 24
        && bytes[4] == b'-'
        && bytes[7] == b'-'
        && bytes[10] == b'T'
        && bytes[13] == b':'
        && bytes[16] == b':'
        && bytes[19] == b'.'
        && bytes[23] == b'Z'
        && [0..4, 5..7, 8..10, 11..13, 14..16, 17..19, 20..23]
            .iter()
            .all(|range| bytes[range.clone()].iter().all(u8::is_ascii_digit));
    if !valid {
        return Err(OutboxStoreError::InvalidRecord);
    }
    Ok(())
}

fn validate_failure_transition(
    expected_status: DeliveryStatus,
    expected_attempt_count: u32,
    new_attempt_count: u32,
    disposition: FailureDisposition,
) -> Result<(), OutboxStoreError> {
    let expected_next = expected_attempt_count
        .checked_add(1)
        .ok_or(OutboxStoreError::InvalidRecord)?;
    if new_attempt_count != expected_next
        || !matches!(
            expected_status,
            DeliveryStatus::Pending | DeliveryStatus::Queued
        )
    {
        return Err(OutboxStoreError::InvalidRecord);
    }
    sql_integer(expected_attempt_count)?;
    sql_integer(new_attempt_count)?;
    if let FailureDisposition::Retry { delay_seconds } = disposition {
        if delay_seconds == 0 {
            return Err(OutboxStoreError::InvalidRecord);
        }
        sql_integer(delay_seconds)?;
    }
    Ok(())
}

fn parse_status(value: &str) -> Result<DeliveryStatus, OutboxStoreError> {
    match value {
        "pending" => Ok(DeliveryStatus::Pending),
        "queued" => Ok(DeliveryStatus::Queued),
        "delivered" => Ok(DeliveryStatus::Delivered),
        "dead_letter" => Ok(DeliveryStatus::DeadLetter),
        _ => Err(OutboxStoreError::InvalidRecord),
    }
}

fn expected_status_as_str(status: DeliveryStatus) -> &'static str {
    match status {
        DeliveryStatus::Pending => "pending",
        DeliveryStatus::Queued => "queued",
        DeliveryStatus::Delivered => "delivered",
        DeliveryStatus::DeadLetter => "dead_letter",
    }
}

fn parse_optional_timestamp(value: Option<String>) -> Result<Option<Timestamp>, OutboxStoreError> {
    value
        .map(|value| {
            let timestamp = Timestamp::new(value).map_err(|_| OutboxStoreError::InvalidRecord)?;
            validate_timestamp(&timestamp)?;
            Ok(timestamp)
        })
        .transpose()
}

fn sql_integer(value: u32) -> Result<i32, OutboxStoreError> {
    i32::try_from(value).map_err(|_| OutboxStoreError::InvalidRecord)
}

fn within_text_limit(value: &str, max_characters: usize) -> bool {
    !value.is_empty()
        && value.chars().count() <= max_characters
        && !value.chars().any(char::is_control)
}

fn organization_scope(event: &EventEnvelope) -> &str {
    event
        .organization_id
        .as_ref()
        .map_or("", |organization_id| organization_id.as_str())
}
