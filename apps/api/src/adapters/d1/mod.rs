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
        self.database.batch(statements).await
    }

    /// Return the number of rows affected when D1 supplied that metadata.
    pub fn changes(result: &D1Result) -> worker::Result<usize> {
        Ok(result
            .meta()?
            .and_then(|meta| meta.changes)
            .unwrap_or_default())
    }
}
