//! Thin Cloudflare D1 adapter. SQL stays in repository code, and all values are
//! bound parameters; callers must never interpolate client-controlled strings.

use wasm_bindgen::JsValue;
use worker::d1::{D1Database, D1PreparedStatement, D1Result};

/// A bound SQL value supported by the P01 repositories.
///
/// Deliberately has no `Debug` implementation so values cannot be included in
/// diagnostics by accident.
pub enum BindValue<'a> {
    Text(&'a str),
    Integer(i32),
    /// 64-bit integer bound as a JS number; exact for values below 2^53
    /// (counters and policy versions stay far below that bound).
    Int64(i64),
    Null,
}

/// A request-scoped handle to the configured D1 database.
pub struct D1Adapter {
    database: D1Database,
}

impl D1Adapter {
    pub fn new(database: D1Database) -> Self {
        Self { database }
    }

    /// Prepare a constant SQL statement and bind every dynamic value.
    pub fn prepare(
        &self,
        sql: &str,
        values: &[BindValue<'_>],
    ) -> worker::Result<D1PreparedStatement> {
        let values = values
            .iter()
            .map(|value| match value {
                BindValue::Text(value) => JsValue::from_str(value),
                BindValue::Integer(value) => JsValue::from_f64(f64::from(*value)),
                BindValue::Int64(value) => JsValue::from_f64(*value as f64),
                BindValue::Null => JsValue::NULL,
            })
            .collect::<Vec<_>>();

        self.database.prepare(sql).bind(&values)
    }

    /// Execute a D1 batch. Cloudflare D1 runs batch statements sequentially in
    /// one transaction and rolls back the batch when any statement fails.
    pub async fn batch(
        &self,
        statements: Vec<D1PreparedStatement>,
    ) -> worker::Result<Vec<D1Result>> {
        let results = self.database.batch(statements).await?;
        if let Some(result) = results.iter().find(|result| !result.success()) {
            let detail = result
                .error()
                .unwrap_or_else(|| "D1 batch statement reported failure".to_owned());
            return Err(worker::Error::RustError(format!(
                "D1 batch statement failed: {detail}"
            )));
        }
        Ok(results)
    }

    /// Return the number of rows affected when D1 supplied that metadata.
    pub fn changes(result: &D1Result) -> worker::Result<usize> {
        Ok(result
            .meta()?
            .and_then(|meta| meta.changes)
            .unwrap_or_default())
    }
}
