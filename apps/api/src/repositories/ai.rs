//! D1 persistence for the P04 catalog, credentials, routes, and inference
//! accounting. Every query is constant SQL with bound values; callers apply
//! the central authorization decision before reaching this layer.

use serde::{Deserialize, Serialize};
use worker::d1::D1PreparedStatement;

use crate::{
    adapters::d1::{BindValue, D1Adapter},
    core::Timestamp,
};

const PROVIDER_SELECT: &str = r#"
SELECT p.provider_id, p.org_id, p.provider_key, p.display_name, p.adapter,
       p.lifecycle, p.version, p.created_by_user_id, p.created_at, p.updated_at,
       (SELECT e.endpoint_id FROM provider_endpoints e
        WHERE e.provider_id = p.provider_id AND e.lifecycle = 'active'
        ORDER BY e.is_default DESC, e.endpoint_id ASC LIMIT 1) AS endpoint_id,
       (SELECT e.endpoint_url FROM provider_endpoints e
        WHERE e.provider_id = p.provider_id AND e.lifecycle = 'active'
        ORDER BY e.is_default DESC, e.endpoint_id ASC LIMIT 1) AS endpoint_url
FROM providers p
"#;

const MODEL_SELECT: &str = r#"
SELECT m.model_id, m.provider_id, m.provider_model_id, m.display_name,
       m.capabilities_json, m.max_input_tokens, m.max_output_tokens,
       m.lifecycle, m.pricing_version, m.version, m.created_by_user_id,
       m.created_at, m.updated_at
FROM models m
JOIN providers p ON p.provider_id = m.provider_id
"#;

const INSERT_PROVIDER_SQL: &str = r#"
INSERT INTO providers (
    provider_id, org_id, provider_key, display_name, adapter, lifecycle,
    version, created_by_user_id, created_at, updated_at
) VALUES (?1, ?2, ?3, ?4, ?5, 'active', 1, ?6, ?7, ?7)
"#;

const UPDATE_PROVIDER_LIFECYCLE_SQL: &str = r#"
UPDATE providers
SET lifecycle = ?3, version = version + 1, updated_at = ?4
WHERE provider_id = ?1 AND org_id = ?2 AND version = ?5 AND lifecycle <> 'disabled'
"#;

const UPDATE_MODEL_LIFECYCLE_SQL: &str = r#"
UPDATE models
SET lifecycle = ?3, version = version + 1, updated_at = ?4
WHERE model_id = ?1
  AND provider_id IN (SELECT provider_id FROM providers WHERE org_id = ?2 OR org_id IS NULL)
  AND version = ?5
"#;

const INSERT_ENDPOINT_SQL: &str = r#"
INSERT INTO provider_endpoints (
    endpoint_id, provider_id, endpoint_url, lifecycle, is_default, created_at, updated_at
) VALUES (?1, ?2, ?3, 'active', 1, ?4, ?4)
"#;

const INSERT_MODEL_SQL: &str = r#"
INSERT INTO models (
    model_id, provider_id, provider_model_id, display_name, capabilities_json,
    max_input_tokens, max_output_tokens, lifecycle, pricing_version, version,
    created_by_user_id, created_at, updated_at
) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'active', ?8, 1, ?9, ?10, ?10)
"#;

const INSERT_ALIAS_SQL: &str = r#"
INSERT INTO model_aliases (alias_id, alias_key, display_name, lifecycle, description, created_at, updated_at)
VALUES (?1, ?2, ?3, 'active', ?4, ?5, ?5)
"#;

const INSERT_POLICY_SQL: &str = r#"
INSERT INTO org_model_policies (
    org_id, policy_version, allowed_aliases_json, allowed_models_json,
    allowed_providers_json, credential_mode, managed_route_enabled, version,
    created_at, updated_at
) VALUES (?1, 1, ?2, ?3, ?4, ?5, ?6, 1, ?7, ?7)
"#;

const UPDATE_POLICY_SQL: &str = r#"
UPDATE org_model_policies
SET policy_version = policy_version + 1,
    allowed_aliases_json = ?3,
    allowed_models_json = ?4,
    allowed_providers_json = ?5,
    credential_mode = ?6,
    managed_route_enabled = ?7,
    version = version + 1,
    updated_at = ?8
WHERE org_id = ?1 AND version = ?2
"#;

const CREDENTIAL_SELECT: &str = r#"
SELECT credential_id, org_id, owner_type, owner_user_id, provider_id, label,
       ciphertext, nonce, key_version, fingerprint, status, version,
       parent_credential_id, created_by_user_id, created_at, updated_at, last_used_at
FROM credentials
"#;

const INSERT_CREDENTIAL_SQL: &str = r#"
INSERT INTO credentials (
    credential_id, org_id, owner_type, owner_user_id, provider_id, label,
    ciphertext, nonce, key_version, fingerprint, status, version,
    parent_credential_id, created_by_user_id, created_at, updated_at, last_used_at
) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, 'active', 1, ?11, ?12, ?13, ?13, NULL)
"#;

const ROUTE_SELECT: &str = r#"
SELECT route_id, org_id, alias, display_name, strategy, lifecycle,
       active_version_id, version, created_by_user_id, created_at, updated_at
FROM routes
"#;

const ROUTE_VERSION_SELECT: &str = r#"
SELECT route_version_id, route_id, org_id, version_number, config_json,
       config_hash, created_by_user_id, created_at, published_at
FROM route_versions
"#;

const INSERT_ROUTE_SQL: &str = r#"
INSERT INTO routes (
    route_id, org_id, alias, display_name, strategy, lifecycle,
    active_version_id, version, created_by_user_id, created_at, updated_at
) VALUES (?1, ?2, ?3, ?4, ?5, 'draft', NULL, 1, ?6, ?7, ?7)
"#;

const INSERT_ROUTE_VERSION_SQL: &str = r#"
INSERT INTO route_versions (
    route_version_id, route_id, org_id, version_number, config_json,
    config_hash, created_by_user_id, created_at, published_at
) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
"#;

const ASSERT_ROUTE_VERSION_SQL: &str = r#"
INSERT INTO idempotency_records (
    principal_id, organization_id, method, path, key_digest, request_fingerprint,
    state, response_status, response_body, expires_at, claim_token
)
SELECT NULL, '', '', '', '', '', 'pending', NULL, NULL, '', NULL
WHERE NOT EXISTS (
    SELECT 1 FROM routes WHERE route_id = ?1 AND org_id = ?2 AND version = ?3
)
"#;

const ASSERT_CREDENTIAL_VERSION_SQL: &str = r#"
INSERT INTO idempotency_records (
    principal_id, organization_id, method, path, key_digest, request_fingerprint,
    state, response_status, response_body, expires_at, claim_token
)
SELECT NULL, '', '', '', '', '', 'pending', NULL, NULL, '', NULL
WHERE NOT EXISTS (
    SELECT 1 FROM credentials
    WHERE credential_id = ?1 AND (org_id = ?2 OR (org_id IS NULL AND owner_type IN ('platform', 'local_only'))) AND version = ?3
)
"#;

const ASSERT_PROVIDER_VERSION_SQL: &str = r#"
INSERT INTO idempotency_records (
    principal_id, organization_id, method, path, key_digest, request_fingerprint,
    state, response_status, response_body, expires_at, claim_token
)
SELECT NULL, '', '', '', '', '', 'pending', NULL, NULL, '', NULL
WHERE NOT EXISTS (
    SELECT 1 FROM providers WHERE provider_id = ?1 AND org_id = ?2 AND version = ?3
)
"#;

const ASSERT_MODEL_VERSION_SQL: &str = r#"
INSERT INTO idempotency_records (
    principal_id, organization_id, method, path, key_digest, request_fingerprint,
    state, response_status, response_body, expires_at, claim_token
)
SELECT NULL, '', '', '', '', '', 'pending', NULL, NULL, '', NULL
WHERE NOT EXISTS (
    SELECT 1
    FROM models m
    JOIN providers p ON p.provider_id = m.provider_id
    WHERE m.model_id = ?1 AND p.org_id = ?2 AND m.version = ?3
)
"#;

const ASSERT_POLICY_VERSION_SQL: &str = r#"
INSERT INTO idempotency_records (
    principal_id, organization_id, method, path, key_digest, request_fingerprint,
    state, response_status, response_body, expires_at, claim_token
)
SELECT NULL, '', '', '', '', '', 'pending', NULL, NULL, '', NULL
WHERE NOT EXISTS (
    SELECT 1 FROM org_model_policies WHERE org_id = ?1 AND version = ?2
)
"#;

const ASSERT_POLICY_ABSENT_SQL: &str = r#"
INSERT INTO idempotency_records (
    principal_id, organization_id, method, path, key_digest, request_fingerprint,
    state, response_status, response_body, expires_at, claim_token
)
SELECT NULL, '', '', '', '', '', 'pending', NULL, NULL, '', NULL
WHERE EXISTS (
    SELECT 1 FROM org_model_policies WHERE org_id = ?1
)
"#;

const PUBLISH_ROUTE_SQL: &str = r#"
UPDATE routes
SET active_version_id = ?2, lifecycle = 'published', version = version + 1, updated_at = ?3
WHERE route_id = ?1 AND org_id = ?4 AND version = ?5 AND lifecycle IN ('draft', 'published')
"#;

const UPDATE_ROUTE_LIFECYCLE_SQL: &str = r#"
UPDATE routes
SET lifecycle = ?3, version = version + 1, updated_at = ?4
WHERE route_id = ?1 AND org_id = ?2 AND version = ?5 AND lifecycle <> 'disabled'
"#;

const ROLLBACK_ROUTE_SQL: &str = r#"
UPDATE routes
SET active_version_id = ?2, lifecycle = 'published', version = version + 1, updated_at = ?3
WHERE route_id = ?1 AND org_id = ?4 AND version = ?5 AND lifecycle = 'published'
"#;

const HEALTH_UPSERT_SQL: &str = r#"
INSERT INTO provider_health (
    provider_id, org_id, state, consecutive_failures, cooldown_until,
    last_success_at, last_failure_at, last_error_code,
    success_count, failure_count, timeout_count, rate_limit_count,
    sample_count, ttft_ms_total, completion_latency_ms_total, updated_at
) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 0, 0, 0, 0, 0, 0, 0, ?9)
ON CONFLICT(provider_id, org_id) DO UPDATE SET
    state = excluded.state,
    consecutive_failures = excluded.consecutive_failures,
    cooldown_until = excluded.cooldown_until,
    last_success_at = excluded.last_success_at,
    last_failure_at = excluded.last_failure_at,
    last_error_code = excluded.last_error_code,
    updated_at = excluded.updated_at
"#;

const INSERT_INFERENCE_REQUEST_SQL: &str = r#"
INSERT INTO inference_requests (
    request_id, org_id, project_id, run_id, principal_user_id, session_id, device_id,
    model_alias, route_id, route_version_id, provider_id, model_id, credential_id,
    response_state, fallback_count, started_at, first_output_at, completed_at, error_code
) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, NULL, NULL, NULL,
          'not_dispatched', 0, ?11, NULL, NULL, NULL)
"#;

const UPDATE_INFERENCE_REQUEST_SQL: &str = r#"
UPDATE inference_requests
SET provider_id = ?2, model_id = ?3, credential_id = ?4, response_state = ?5,
    fallback_count = ?6, first_output_at = ?7, completed_at = ?8, error_code = ?9
WHERE request_id = ?1 AND org_id = ?10
"#;

const INSERT_BUDGET_RESERVATION_IF_AVAILABLE_SQL: &str = r#"
INSERT INTO budget_reservations (
    reservation_id, request_id, org_id, reserved_minor, committed_minor,
    status, expires_at, created_at, updated_at
)
SELECT ?1, ?2, ?3, ?4, NULL, 'reserved', ?5, ?6, ?6
WHERE NOT EXISTS (
    SELECT 1
    FROM budgets b
    WHERE b.org_id = ?3 AND b.hard = 1
      AND b.period_start <= ?6 AND b.period_end > ?6
      AND b.limit_minor
          - COALESCE((SELECT SUM(COALESCE(u.actual_cost_minor, u.estimated_cost_minor, 0))
                      FROM usage_events u
                      WHERE u.org_id = b.org_id AND u.created_at >= b.period_start AND u.created_at < b.period_end), 0)
          - COALESCE((SELECT SUM(COALESCE(r.reserved_minor, 0) - COALESCE(r.committed_minor, 0))
                      FROM budget_reservations r
                      WHERE r.org_id = b.org_id AND r.status = 'reserved' AND r.expires_at > ?6), 0)
          < ?4
)
"#;

const INSERT_BUDGET_RESERVATION_SQL: &str = r#"
INSERT INTO budget_reservations (
    reservation_id, request_id, org_id, reserved_minor, committed_minor,
    status, expires_at, created_at, updated_at
) VALUES (?1, ?2, ?3, ?4, NULL, 'reserved', ?5, ?6, ?6)
"#;

const UPDATE_BUDGET_RESERVATION_SQL: &str = r#"
UPDATE budget_reservations
SET committed_minor = ?3, status = ?4, updated_at = ?5
WHERE reservation_id = ?1 AND org_id = ?2 AND request_id = ?6 AND status = 'reserved'
"#;

const INSERT_USAGE_SQL: &str = r#"
INSERT INTO usage_events (
    usage_event_id, request_id, org_id, project_id, run_id, principal_user_id,
    session_id, device_id, model_alias, route_version_id, provider_id, model_id,
    credential_id, input_tokens, output_tokens, cached_tokens, provider_usage_json,
    estimated_cost_minor, actual_cost_minor, currency, pricing_version,
    budget_decision, ttft_ms, total_latency_ms, created_at
) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14,
          ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24, ?25)
"#;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ProviderRecord {
    pub provider_id: String,
    pub org_id: Option<String>,
    pub provider_key: String,
    pub display_name: String,
    pub adapter: String,
    pub lifecycle: String,
    pub version: i64,
    pub created_by_user_id: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    pub endpoint_id: Option<String>,
    pub endpoint_url: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ModelRecord {
    pub model_id: String,
    pub provider_id: String,
    pub provider_model_id: String,
    pub display_name: String,
    pub capabilities_json: String,
    pub max_input_tokens: Option<i64>,
    pub max_output_tokens: Option<i64>,
    pub lifecycle: String,
    pub pricing_version: Option<String>,
    pub version: i64,
    pub created_by_user_id: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AliasRecord {
    pub alias_id: String,
    pub alias_key: String,
    pub display_name: String,
    pub lifecycle: String,
    pub description: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PolicyRecord {
    pub org_id: String,
    pub policy_version: i64,
    pub allowed_aliases_json: String,
    pub allowed_models_json: String,
    pub allowed_providers_json: String,
    pub credential_mode: String,
    pub managed_route_enabled: bool,
    pub version: i64,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Clone, Deserialize, Serialize)]
pub struct CredentialRecord {
    pub credential_id: String,
    pub org_id: Option<String>,
    pub owner_type: String,
    pub owner_user_id: Option<String>,
    pub provider_id: String,
    pub label: String,
    pub ciphertext: Option<String>,
    pub nonce: Option<String>,
    pub key_version: Option<String>,
    pub fingerprint: String,
    pub status: String,
    pub version: i64,
    pub parent_credential_id: Option<String>,
    pub created_by_user_id: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    pub last_used_at: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RouteRecord {
    pub route_id: String,
    pub org_id: String,
    pub alias: String,
    pub display_name: String,
    pub strategy: String,
    pub lifecycle: String,
    pub active_version_id: Option<String>,
    pub version: i64,
    pub created_by_user_id: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RouteVersionRecord {
    pub route_version_id: String,
    pub route_id: String,
    pub org_id: String,
    pub version_number: i64,
    pub config_json: String,
    pub config_hash: String,
    pub created_by_user_id: String,
    pub created_at: String,
    pub published_at: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct HealthRecord {
    pub provider_id: String,
    pub org_id: String,
    pub state: String,
    pub consecutive_failures: i64,
    pub cooldown_until: Option<String>,
    pub last_success_at: Option<String>,
    pub last_failure_at: Option<String>,
    pub last_error_code: Option<String>,
    pub success_count: i64,
    pub failure_count: i64,
    pub timeout_count: i64,
    pub rate_limit_count: i64,
    pub sample_count: i64,
    pub ttft_ms_total: i64,
    pub completion_latency_ms_total: i64,
    pub updated_at: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InferenceRequestRecord {
    pub request_id: String,
    pub org_id: String,
    pub project_id: Option<String>,
    pub run_id: Option<String>,
    pub principal_user_id: String,
    pub session_id: Option<String>,
    pub device_id: Option<String>,
    pub model_alias: String,
    pub route_id: String,
    pub route_version_id: String,
    pub provider_id: Option<String>,
    pub model_id: Option<String>,
    pub credential_id: Option<String>,
    pub response_state: String,
    pub fallback_count: i64,
    pub started_at: String,
    pub first_output_at: Option<String>,
    pub completed_at: Option<String>,
    pub error_code: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct UsageRecord {
    pub usage_event_id: String,
    pub request_id: String,
    pub org_id: String,
    pub project_id: Option<String>,
    pub run_id: Option<String>,
    pub principal_user_id: String,
    pub session_id: Option<String>,
    pub device_id: Option<String>,
    pub model_alias: String,
    pub route_version_id: String,
    pub provider_id: String,
    pub model_id: String,
    pub credential_id: Option<String>,
    pub input_tokens: Option<i64>,
    pub output_tokens: Option<i64>,
    pub cached_tokens: Option<i64>,
    pub provider_usage_json: String,
    pub estimated_cost_minor: Option<i64>,
    pub actual_cost_minor: Option<i64>,
    pub currency: Option<String>,
    pub pricing_version: Option<String>,
    pub budget_decision: String,
    pub ttft_ms: Option<i64>,
    pub total_latency_ms: Option<i64>,
    pub created_at: String,
}

pub struct AiRepository<'a> {
    database: &'a D1Adapter,
}

impl<'a> AiRepository<'a> {
    pub fn new(database: &'a D1Adapter) -> Self {
        Self { database }
    }

    pub async fn list_providers(&self, org_id: &str) -> worker::Result<Vec<ProviderRecord>> {
        let result = self
            .database
            .prepare(
                &format!(
                    "{PROVIDER_SELECT} WHERE (p.org_id IS NULL OR p.org_id = ?1) AND p.lifecycle <> 'disabled' ORDER BY p.display_name ASC, p.provider_id ASC"
                ),
                &[BindValue::Text(org_id)],
            )?
            .all()
            .await?;
        rows_to_records(result.results::<ProviderRow>())
    }

    pub async fn find_provider(
        &self,
        provider_id: &str,
        org_id: &str,
    ) -> worker::Result<Option<ProviderRecord>> {
        let result = self
            .database
            .prepare(
                &format!(
                    "{PROVIDER_SELECT} WHERE p.provider_id = ?1 AND (p.org_id IS NULL OR p.org_id = ?2) LIMIT 1"
                ),
                &[BindValue::Text(provider_id), BindValue::Text(org_id)],
            )?
            .first::<ProviderRow>(None)
            .await?;
        result.map(TryInto::try_into).transpose()
    }

    #[allow(clippy::too_many_arguments)]
    pub fn insert_provider_statement(
        &self,
        provider_id: &str,
        org_id: Option<&str>,
        provider_key: &str,
        display_name: &str,
        adapter: &str,
        created_by: Option<&str>,
        now: &Timestamp,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            INSERT_PROVIDER_SQL,
            &[
                BindValue::Text(provider_id),
                org_id.map_or(BindValue::Null, BindValue::Text),
                BindValue::Text(provider_key),
                BindValue::Text(display_name),
                BindValue::Text(adapter),
                created_by.map_or(BindValue::Null, BindValue::Text),
                BindValue::Text(now.as_str()),
            ],
        )
    }

    pub fn update_provider_lifecycle_statement(
        &self,
        provider_id: &str,
        org_id: &str,
        lifecycle: &str,
        expected_version: i64,
        now: &Timestamp,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            UPDATE_PROVIDER_LIFECYCLE_SQL,
            &[
                BindValue::Text(provider_id),
                BindValue::Text(org_id),
                BindValue::Text(lifecycle),
                BindValue::Text(now.as_str()),
                BindValue::Integer(expected_version as i32),
            ],
        )
    }

    pub fn update_model_lifecycle_statement(
        &self,
        model_id: &str,
        org_id: &str,
        lifecycle: &str,
        expected_version: i64,
        now: &Timestamp,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            UPDATE_MODEL_LIFECYCLE_SQL,
            &[
                BindValue::Text(model_id),
                BindValue::Text(org_id),
                BindValue::Text(lifecycle),
                BindValue::Text(now.as_str()),
                BindValue::Integer(expected_version as i32),
            ],
        )
    }

    pub fn insert_endpoint_statement(
        &self,
        endpoint_id: &str,
        provider_id: &str,
        endpoint_url: &str,
        now: &Timestamp,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            INSERT_ENDPOINT_SQL,
            &[
                BindValue::Text(endpoint_id),
                BindValue::Text(provider_id),
                BindValue::Text(endpoint_url),
                BindValue::Text(now.as_str()),
            ],
        )
    }

    pub async fn list_models(&self, org_id: &str) -> worker::Result<Vec<ModelRecord>> {
        let result = self
            .database
            .prepare(
                &format!(
                    "{MODEL_SELECT} WHERE (p.org_id IS NULL OR p.org_id = ?1) AND m.lifecycle <> 'disabled' ORDER BY m.display_name ASC, m.model_id ASC"
                ),
                &[BindValue::Text(org_id)],
            )?
            .all()
            .await?;
        rows_to_records(result.results::<ModelRow>())
    }

    pub async fn find_model(
        &self,
        model_id: &str,
        org_id: &str,
    ) -> worker::Result<Option<ModelRecord>> {
        let result = self
            .database
            .prepare(
                &format!(
                    "{MODEL_SELECT} WHERE m.model_id = ?1 AND (p.org_id IS NULL OR p.org_id = ?2) LIMIT 1"
                ),
                &[BindValue::Text(model_id), BindValue::Text(org_id)],
            )?
            .first::<ModelRow>(None)
            .await?;
        result.map(TryInto::try_into).transpose()
    }

    #[allow(clippy::too_many_arguments)]
    pub fn insert_model_statement(
        &self,
        model_id: &str,
        provider_id: &str,
        provider_model_id: &str,
        display_name: &str,
        capabilities_json: &str,
        max_input_tokens: Option<i64>,
        max_output_tokens: Option<i64>,
        pricing_version: Option<&str>,
        created_by: Option<&str>,
        now: &Timestamp,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            INSERT_MODEL_SQL,
            &[
                BindValue::Text(model_id),
                BindValue::Text(provider_id),
                BindValue::Text(provider_model_id),
                BindValue::Text(display_name),
                BindValue::Text(capabilities_json),
                optional_integer(max_input_tokens),
                optional_integer(max_output_tokens),
                pricing_version.map_or(BindValue::Null, BindValue::Text),
                created_by.map_or(BindValue::Null, BindValue::Text),
                BindValue::Text(now.as_str()),
            ],
        )
    }

    pub fn insert_alias_statement(
        &self,
        alias_id: &str,
        alias_key: &str,
        display_name: &str,
        description: Option<&str>,
        now: &Timestamp,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            INSERT_ALIAS_SQL,
            &[
                BindValue::Text(alias_id),
                BindValue::Text(alias_key),
                BindValue::Text(display_name),
                description.map_or(BindValue::Null, BindValue::Text),
                BindValue::Text(now.as_str()),
            ],
        )
    }

    pub async fn list_aliases(&self) -> worker::Result<Vec<AliasRecord>> {
        let result = self
            .database
            .prepare(
                "SELECT alias_id, alias_key, display_name, lifecycle, description, created_at, updated_at FROM model_aliases WHERE lifecycle <> 'disabled' ORDER BY display_name ASC, alias_id ASC",
                &[],
            )?
            .all()
            .await?;
        rows_to_records(result.results::<AliasRow>())
    }

    pub async fn find_alias(&self, alias: &str) -> worker::Result<Option<AliasRecord>> {
        let result = self
            .database
            .prepare(
                "SELECT alias_id, alias_key, display_name, lifecycle, description, created_at, updated_at FROM model_aliases WHERE alias_key = ?1 LIMIT 1",
                &[BindValue::Text(alias)],
            )?
            .first::<AliasRow>(None)
            .await?;
        result.map(TryInto::try_into).transpose()
    }

    pub async fn find_policy(&self, org_id: &str) -> worker::Result<Option<PolicyRecord>> {
        let result = self
            .database
            .prepare(
                "SELECT org_id, policy_version, allowed_aliases_json, allowed_models_json, allowed_providers_json, credential_mode, managed_route_enabled, version, created_at, updated_at FROM org_model_policies WHERE org_id = ?1 LIMIT 1",
                &[BindValue::Text(org_id)],
            )?
            .first::<PolicyRow>(None)
            .await?;
        result.map(TryInto::try_into).transpose()
    }

    #[allow(clippy::too_many_arguments)]
    pub fn insert_policy_statement(
        &self,
        org_id: &str,
        allowed_aliases_json: &str,
        allowed_models_json: &str,
        allowed_providers_json: &str,
        credential_mode: &str,
        managed_route_enabled: bool,
        now: &Timestamp,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            INSERT_POLICY_SQL,
            &[
                BindValue::Text(org_id),
                BindValue::Text(allowed_aliases_json),
                BindValue::Text(allowed_models_json),
                BindValue::Text(allowed_providers_json),
                BindValue::Text(credential_mode),
                BindValue::Integer(if managed_route_enabled { 1 } else { 0 }),
                BindValue::Text(now.as_str()),
            ],
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn update_policy_statement(
        &self,
        org_id: &str,
        expected_version: i64,
        allowed_aliases_json: &str,
        allowed_models_json: &str,
        allowed_providers_json: &str,
        credential_mode: &str,
        managed_route_enabled: bool,
        now: &Timestamp,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            UPDATE_POLICY_SQL,
            &[
                BindValue::Text(org_id),
                BindValue::Integer(expected_version as i32),
                BindValue::Text(allowed_aliases_json),
                BindValue::Text(allowed_models_json),
                BindValue::Text(allowed_providers_json),
                BindValue::Text(credential_mode),
                BindValue::Integer(if managed_route_enabled { 1 } else { 0 }),
                BindValue::Text(now.as_str()),
            ],
        )
    }

    pub async fn list_credentials(
        &self,
        org_id: &str,
        limit: u16,
        offset: u32,
    ) -> worker::Result<Vec<CredentialRecord>> {
        let result = self
            .database
            .prepare(
                &format!(
                    "{CREDENTIAL_SELECT} WHERE org_id = ?1 OR (org_id IS NULL AND owner_type = 'platform') ORDER BY created_at DESC, credential_id DESC LIMIT ?2 OFFSET ?3"
                ),
                &[
                    BindValue::Text(org_id),
                    BindValue::Integer(i32::from(limit)),
                    BindValue::Integer(offset as i32),
                ],
            )?
            .all()
            .await?;
        rows_to_records(result.results::<CredentialRow>())
    }

    pub async fn find_credential_for_org(
        &self,
        credential_id: &str,
        org_id: &str,
    ) -> worker::Result<Option<CredentialRecord>> {
        let result = self
            .database
            .prepare(
                &format!("{CREDENTIAL_SELECT} WHERE credential_id = ?1 AND org_id = ?2 AND status <> 'revoked' LIMIT 1"),
                &[BindValue::Text(credential_id), BindValue::Text(org_id)],
            )?
            .first::<CredentialRow>(None)
            .await?;
        result.map(TryInto::try_into).transpose()
    }

    pub async fn find_credential_for_owner(
        &self,
        credential_id: &str,
        org_id: &str,
        user_id: &str,
    ) -> worker::Result<Option<CredentialRecord>> {
        let result = self
            .database
            .prepare(
                &format!(
                    "{CREDENTIAL_SELECT} WHERE credential_id = ?1 AND status <> 'revoked' AND (org_id = ?2 OR (org_id IS NULL AND owner_type = 'platform') OR (org_id IS NULL AND owner_type = 'local_only' AND created_by_user_id = ?3)) AND (owner_type NOT IN ('user', 'service_account') OR owner_user_id = ?3) LIMIT 1"
                ),
                &[
                    BindValue::Text(credential_id),
                    BindValue::Text(org_id),
                    BindValue::Text(user_id),
                ],
            )?
            .first::<CredentialRow>(None)
            .await?;
        result.map(TryInto::try_into).transpose()
    }

    pub async fn list_active_credentials(
        &self,
        org_id: &str,
        provider_id: &str,
        user_id: &str,
    ) -> worker::Result<Vec<CredentialRecord>> {
        let result = self
            .database
            .prepare(
                &format!(
                    "{CREDENTIAL_SELECT} WHERE provider_id = ?1 AND status IN ('active', 'rotating') AND (org_id = ?2 OR (org_id IS NULL AND owner_type = 'platform')) AND (owner_type NOT IN ('user', 'service_account') OR owner_user_id = ?3) ORDER BY CASE owner_type WHEN 'organization' THEN 1 WHEN 'user' THEN 2 WHEN 'platform' THEN 3 ELSE 4 END, created_at DESC LIMIT 32"
                ),
                &[
                    BindValue::Text(provider_id),
                    BindValue::Text(org_id),
                    BindValue::Text(user_id),
                ],
            )?
            .all()
            .await?;
        rows_to_records(result.results::<CredentialRow>())
    }

    pub async fn find_active_credential(
        &self,
        org_id: &str,
        provider_id: &str,
        user_id: &str,
    ) -> worker::Result<Option<CredentialRecord>> {
        Ok(self
            .list_active_credentials(org_id, provider_id, user_id)
            .await?
            .into_iter()
            .next())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn insert_credential_statement(
        &self,
        credential_id: &str,
        org_id: Option<&str>,
        owner_type: &str,
        owner_user_id: Option<&str>,
        provider_id: &str,
        label: &str,
        ciphertext: Option<&str>,
        nonce: Option<&str>,
        key_version: Option<&str>,
        fingerprint: &str,
        parent_credential_id: Option<&str>,
        created_by: Option<&str>,
        now: &Timestamp,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            INSERT_CREDENTIAL_SQL,
            &[
                BindValue::Text(credential_id),
                org_id.map_or(BindValue::Null, BindValue::Text),
                BindValue::Text(owner_type),
                owner_user_id.map_or(BindValue::Null, BindValue::Text),
                BindValue::Text(provider_id),
                BindValue::Text(label),
                ciphertext.map_or(BindValue::Null, BindValue::Text),
                nonce.map_or(BindValue::Null, BindValue::Text),
                key_version.map_or(BindValue::Null, BindValue::Text),
                BindValue::Text(fingerprint),
                parent_credential_id.map_or(BindValue::Null, BindValue::Text),
                created_by.map_or(BindValue::Null, BindValue::Text),
                BindValue::Text(now.as_str()),
            ],
        )
    }

    pub fn revoke_credential_statement(
        &self,
        credential_id: &str,
        org_id: &str,
        expected_version: i64,
        now: &Timestamp,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            "UPDATE credentials SET status = 'revoked', version = version + 1, updated_at = ?3 WHERE credential_id = ?1 AND org_id = ?2 AND status <> 'revoked' AND version = ?4",
            &[
                BindValue::Text(credential_id),
                BindValue::Text(org_id),
                BindValue::Text(now.as_str()),
                BindValue::Integer(expected_version as i32),
            ],
        )
    }

    pub fn touch_credential_statement(
        &self,
        credential_id: &str,
        now: &Timestamp,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            "UPDATE credentials SET last_used_at = ?2, updated_at = ?2 WHERE credential_id = ?1 AND status <> 'revoked'",
            &[BindValue::Text(credential_id), BindValue::Text(now.as_str())],
        )
    }

    pub async fn find_route(
        &self,
        org_id: &str,
        route_id: &str,
    ) -> worker::Result<Option<RouteRecord>> {
        let result = self
            .database
            .prepare(
                &format!("{ROUTE_SELECT} WHERE org_id = ?1 AND route_id = ?2 LIMIT 1"),
                &[BindValue::Text(org_id), BindValue::Text(route_id)],
            )?
            .first::<RouteRow>(None)
            .await?;
        result.map(TryInto::try_into).transpose()
    }

    pub async fn find_route_by_alias(
        &self,
        org_id: &str,
        alias: &str,
    ) -> worker::Result<Option<RouteRecord>> {
        let result = self
            .database
            .prepare(
                &format!("{ROUTE_SELECT} WHERE org_id = ?1 AND alias = ?2 LIMIT 1"),
                &[BindValue::Text(org_id), BindValue::Text(alias)],
            )?
            .first::<RouteRow>(None)
            .await?;
        result.map(TryInto::try_into).transpose()
    }

    pub async fn list_routes(
        &self,
        org_id: &str,
        limit: u16,
        offset: u32,
    ) -> worker::Result<Vec<RouteRecord>> {
        let result = self
            .database
            .prepare(
                &format!("{ROUTE_SELECT} WHERE org_id = ?1 ORDER BY alias ASC LIMIT ?2 OFFSET ?3"),
                &[
                    BindValue::Text(org_id),
                    BindValue::Integer(i32::from(limit)),
                    BindValue::Integer(offset as i32),
                ],
            )?
            .all()
            .await?;
        rows_to_records(result.results::<RouteRow>())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn insert_route_statement(
        &self,
        route_id: &str,
        org_id: &str,
        alias: &str,
        display_name: &str,
        strategy: &str,
        created_by: &str,
        now: &Timestamp,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            INSERT_ROUTE_SQL,
            &[
                BindValue::Text(route_id),
                BindValue::Text(org_id),
                BindValue::Text(alias),
                BindValue::Text(display_name),
                BindValue::Text(strategy),
                BindValue::Text(created_by),
                BindValue::Text(now.as_str()),
            ],
        )
    }

    pub async fn find_route_version(
        &self,
        org_id: &str,
        route_version_id: &str,
    ) -> worker::Result<Option<RouteVersionRecord>> {
        let result = self
            .database
            .prepare(
                &format!(
                    "{ROUTE_VERSION_SELECT} WHERE org_id = ?1 AND route_version_id = ?2 LIMIT 1"
                ),
                &[BindValue::Text(org_id), BindValue::Text(route_version_id)],
            )?
            .first::<RouteVersionRow>(None)
            .await?;
        result.map(TryInto::try_into).transpose()
    }

    pub async fn find_active_route_version(
        &self,
        org_id: &str,
        route_id: &str,
    ) -> worker::Result<Option<RouteVersionRecord>> {
        let result = self
            .database
            .prepare(
                &format!("{ROUTE_VERSION_SELECT} WHERE org_id = ?1 AND route_id = ?2 AND published_at IS NOT NULL ORDER BY version_number DESC LIMIT 1"),
                &[BindValue::Text(org_id), BindValue::Text(route_id)],
            )?
            .first::<RouteVersionRow>(None)
            .await?;
        result.map(TryInto::try_into).transpose()
    }

    pub async fn list_route_versions(
        &self,
        org_id: &str,
        route_id: &str,
        limit: u16,
        offset: u32,
    ) -> worker::Result<Vec<RouteVersionRecord>> {
        let result = self
            .database
            .prepare(
                &format!("{ROUTE_VERSION_SELECT} WHERE org_id = ?1 AND route_id = ?2 ORDER BY version_number DESC LIMIT ?3 OFFSET ?4"),
                &[
                    BindValue::Text(org_id),
                    BindValue::Text(route_id),
                    BindValue::Integer(i32::from(limit)),
                    BindValue::Integer(offset as i32),
                ],
            )?
            .all()
            .await?;
        rows_to_records(result.results::<RouteVersionRow>())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn assert_route_version_statement(
        &self,
        route_id: &str,
        org_id: &str,
        expected_version: i64,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            ASSERT_ROUTE_VERSION_SQL,
            &[
                BindValue::Text(route_id),
                BindValue::Text(org_id),
                BindValue::Integer(expected_version as i32),
            ],
        )
    }

    pub fn assert_credential_version_statement(
        &self,
        credential_id: &str,
        org_id: &str,
        expected_version: i64,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            ASSERT_CREDENTIAL_VERSION_SQL,
            &[
                BindValue::Text(credential_id),
                BindValue::Text(org_id),
                BindValue::Integer(expected_version as i32),
            ],
        )
    }

    pub fn assert_provider_version_statement(
        &self,
        provider_id: &str,
        org_id: &str,
        expected_version: i64,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            ASSERT_PROVIDER_VERSION_SQL,
            &[
                BindValue::Text(provider_id),
                BindValue::Text(org_id),
                BindValue::Integer(expected_version as i32),
            ],
        )
    }

    pub fn assert_model_version_statement(
        &self,
        model_id: &str,
        org_id: &str,
        expected_version: i64,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            ASSERT_MODEL_VERSION_SQL,
            &[
                BindValue::Text(model_id),
                BindValue::Text(org_id),
                BindValue::Integer(expected_version as i32),
            ],
        )
    }

    pub fn assert_policy_version_statement(
        &self,
        org_id: &str,
        expected_version: i64,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            ASSERT_POLICY_VERSION_SQL,
            &[
                BindValue::Text(org_id),
                BindValue::Integer(expected_version as i32),
            ],
        )
    }

    pub fn assert_policy_absent_statement(
        &self,
        org_id: &str,
    ) -> worker::Result<D1PreparedStatement> {
        self.database
            .prepare(ASSERT_POLICY_ABSENT_SQL, &[BindValue::Text(org_id)])
    }

    #[allow(clippy::too_many_arguments)]
    pub fn insert_route_version_statement(
        &self,
        route_version_id: &str,
        route_id: &str,
        org_id: &str,
        version_number: i64,
        config_json: &str,
        config_hash: &str,
        created_by: &str,
        published_at: Option<&str>,
        now: &Timestamp,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            INSERT_ROUTE_VERSION_SQL,
            &[
                BindValue::Text(route_version_id),
                BindValue::Text(route_id),
                BindValue::Text(org_id),
                BindValue::Integer(version_number as i32),
                BindValue::Text(config_json),
                BindValue::Text(config_hash),
                BindValue::Text(created_by),
                BindValue::Text(now.as_str()),
                published_at.map_or(BindValue::Null, BindValue::Text),
            ],
        )
    }

    pub fn publish_route_statement(
        &self,
        route_id: &str,
        route_version_id: &str,
        org_id: &str,
        expected_version: i64,
        now: &Timestamp,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            PUBLISH_ROUTE_SQL,
            &[
                BindValue::Text(route_id),
                BindValue::Text(route_version_id),
                BindValue::Text(now.as_str()),
                BindValue::Text(org_id),
                BindValue::Integer(expected_version as i32),
            ],
        )
    }

    pub fn update_route_lifecycle_statement(
        &self,
        route_id: &str,
        org_id: &str,
        lifecycle: &str,
        expected_version: i64,
        now: &Timestamp,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            UPDATE_ROUTE_LIFECYCLE_SQL,
            &[
                BindValue::Text(route_id),
                BindValue::Text(org_id),
                BindValue::Text(lifecycle),
                BindValue::Text(now.as_str()),
                BindValue::Integer(expected_version as i32),
            ],
        )
    }

    pub fn rollback_route_statement(
        &self,
        route_id: &str,
        route_version_id: &str,
        org_id: &str,
        expected_version: i64,
        now: &Timestamp,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            ROLLBACK_ROUTE_SQL,
            &[
                BindValue::Text(route_id),
                BindValue::Text(route_version_id),
                BindValue::Text(now.as_str()),
                BindValue::Text(org_id),
                BindValue::Integer(expected_version as i32),
            ],
        )
    }

    pub async fn list_health(&self, org_id: &str) -> worker::Result<Vec<HealthRecord>> {
        let result = self
            .database
            .prepare(
                "SELECT provider_id, org_id, state, consecutive_failures, cooldown_until, last_success_at, last_failure_at, last_error_code, success_count, failure_count, timeout_count, rate_limit_count, sample_count, ttft_ms_total, completion_latency_ms_total, updated_at FROM provider_health WHERE org_id = '' OR org_id = ?1 ORDER BY provider_id ASC",
                &[BindValue::Text(org_id)],
            )?
            .all()
            .await?;
        rows_to_records(result.results::<HealthRow>())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record_health_latency_statement(
        &self,
        provider_id: &str,
        org_id: &str,
        ttft_ms: Option<i64>,
        completion_latency_ms: Option<i64>,
        now: &Timestamp,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            "UPDATE provider_health SET ttft_ms_total = ttft_ms_total + COALESCE(?3, 0), completion_latency_ms_total = completion_latency_ms_total + COALESCE(?4, 0), updated_at = ?5 WHERE provider_id = ?1 AND org_id = ?2",
            &[
                BindValue::Text(provider_id),
                BindValue::Text(org_id),
                BindValue::Integer(ttft_ms.unwrap_or(0) as i32),
                BindValue::Integer(completion_latency_ms.unwrap_or(0) as i32),
                BindValue::Text(now.as_str()),
            ],
        )
    }

    pub fn increment_health_success_statement(
        &self,
        provider_id: &str,
        org_id: &str,
        now: &Timestamp,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            "UPDATE provider_health SET success_count = success_count + 1, sample_count = sample_count + 1, consecutive_failures = 0, updated_at = ?3 WHERE provider_id = ?1 AND org_id = ?2",
            &[
                BindValue::Text(provider_id),
                BindValue::Text(org_id),
                BindValue::Text(now.as_str()),
            ],
        )
    }

    pub fn increment_health_failure_statement(
        &self,
        provider_id: &str,
        org_id: &str,
        error_code: &str,
        now: &Timestamp,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            "UPDATE provider_health SET failure_count = failure_count + 1, sample_count = sample_count + 1, timeout_count = timeout_count + CASE WHEN ?3 IN ('timeout', 'request_timeout') THEN 1 ELSE 0 END, rate_limit_count = rate_limit_count + CASE WHEN ?3 IN ('rate_limited', 'provider_rate_limited') THEN 1 ELSE 0 END, updated_at = ?4 WHERE provider_id = ?1 AND org_id = ?2",
            &[
                BindValue::Text(provider_id),
                BindValue::Text(org_id),
                BindValue::Text(error_code),
                BindValue::Text(now.as_str()),
            ],
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn upsert_health_statement(
        &self,
        provider_id: &str,
        org_id: &str,
        state: &str,
        consecutive_failures: i64,
        cooldown_until: Option<&str>,
        last_success_at: Option<&str>,
        last_failure_at: Option<&str>,
        last_error_code: Option<&str>,
        now: &Timestamp,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            HEALTH_UPSERT_SQL,
            &[
                BindValue::Text(provider_id),
                BindValue::Text(org_id),
                BindValue::Text(state),
                BindValue::Integer(consecutive_failures as i32),
                cooldown_until.map_or(BindValue::Null, BindValue::Text),
                last_success_at.map_or(BindValue::Null, BindValue::Text),
                last_failure_at.map_or(BindValue::Null, BindValue::Text),
                last_error_code.map_or(BindValue::Null, BindValue::Text),
                BindValue::Text(now.as_str()),
            ],
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn insert_inference_request_statement(
        &self,
        request_id: &str,
        org_id: &str,
        project_id: Option<&str>,
        run_id: Option<&str>,
        principal_user_id: &str,
        session_id: Option<&str>,
        device_id: Option<&str>,
        model_alias: &str,
        route_id: &str,
        route_version_id: &str,
        now: &Timestamp,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            INSERT_INFERENCE_REQUEST_SQL,
            &[
                BindValue::Text(request_id),
                BindValue::Text(org_id),
                project_id.map_or(BindValue::Null, BindValue::Text),
                run_id.map_or(BindValue::Null, BindValue::Text),
                BindValue::Text(principal_user_id),
                session_id.map_or(BindValue::Null, BindValue::Text),
                device_id.map_or(BindValue::Null, BindValue::Text),
                BindValue::Text(model_alias),
                BindValue::Text(route_id),
                BindValue::Text(route_version_id),
                BindValue::Text(now.as_str()),
            ],
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn update_inference_request_statement(
        &self,
        request_id: &str,
        org_id: &str,
        provider_id: Option<&str>,
        model_id: Option<&str>,
        credential_id: Option<&str>,
        state: &str,
        fallback_count: i64,
        first_output_at: Option<&str>,
        completed_at: Option<&str>,
        error_code: Option<&str>,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            UPDATE_INFERENCE_REQUEST_SQL,
            &[
                BindValue::Text(request_id),
                provider_id.map_or(BindValue::Null, BindValue::Text),
                model_id.map_or(BindValue::Null, BindValue::Text),
                credential_id.map_or(BindValue::Null, BindValue::Text),
                BindValue::Text(state),
                BindValue::Integer(fallback_count as i32),
                first_output_at.map_or(BindValue::Null, BindValue::Text),
                completed_at.map_or(BindValue::Null, BindValue::Text),
                error_code.map_or(BindValue::Null, BindValue::Text),
                BindValue::Text(org_id),
            ],
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn insert_usage_statement(
        &self,
        usage_event_id: &str,
        request_id: &str,
        org_id: &str,
        project_id: Option<&str>,
        run_id: Option<&str>,
        principal_user_id: &str,
        session_id: Option<&str>,
        device_id: Option<&str>,
        model_alias: &str,
        route_version_id: &str,
        provider_id: &str,
        model_id: &str,
        credential_id: Option<&str>,
        input_tokens: Option<i64>,
        output_tokens: Option<i64>,
        cached_tokens: Option<i64>,
        provider_usage_json: &str,
        estimated_cost_minor: Option<i64>,
        actual_cost_minor: Option<i64>,
        currency: Option<&str>,
        pricing_version: Option<&str>,
        budget_decision: &str,
        ttft_ms: Option<i64>,
        total_latency_ms: Option<i64>,
        now: &Timestamp,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            INSERT_USAGE_SQL,
            &[
                BindValue::Text(usage_event_id),
                BindValue::Text(request_id),
                BindValue::Text(org_id),
                project_id.map_or(BindValue::Null, BindValue::Text),
                run_id.map_or(BindValue::Null, BindValue::Text),
                BindValue::Text(principal_user_id),
                session_id.map_or(BindValue::Null, BindValue::Text),
                device_id.map_or(BindValue::Null, BindValue::Text),
                BindValue::Text(model_alias),
                BindValue::Text(route_version_id),
                BindValue::Text(provider_id),
                BindValue::Text(model_id),
                credential_id.map_or(BindValue::Null, BindValue::Text),
                optional_integer(input_tokens),
                optional_integer(output_tokens),
                optional_integer(cached_tokens),
                BindValue::Text(provider_usage_json),
                optional_integer(estimated_cost_minor),
                optional_integer(actual_cost_minor),
                currency.map_or(BindValue::Null, BindValue::Text),
                pricing_version.map_or(BindValue::Null, BindValue::Text),
                BindValue::Text(budget_decision),
                optional_integer(ttft_ms),
                optional_integer(total_latency_ms),
                BindValue::Text(now.as_str()),
            ],
        )
    }

    pub fn insert_budget_reservation_if_available_statement(
        &self,
        reservation_id: &str,
        request_id: &str,
        org_id: &str,
        reserved_minor: i64,
        expires_at: &str,
        now: &Timestamp,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            INSERT_BUDGET_RESERVATION_IF_AVAILABLE_SQL,
            &[
                BindValue::Text(reservation_id),
                BindValue::Text(request_id),
                BindValue::Text(org_id),
                BindValue::Integer(reserved_minor as i32),
                BindValue::Text(expires_at),
                BindValue::Text(now.as_str()),
            ],
        )
    }

    pub fn insert_budget_reservation_statement(
        &self,
        reservation_id: &str,
        request_id: &str,
        org_id: &str,
        reserved_minor: i64,
        expires_at: &str,
        now: &Timestamp,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            INSERT_BUDGET_RESERVATION_SQL,
            &[
                BindValue::Text(reservation_id),
                BindValue::Text(request_id),
                BindValue::Text(org_id),
                BindValue::Integer(reserved_minor as i32),
                BindValue::Text(expires_at),
                BindValue::Text(now.as_str()),
            ],
        )
    }

    pub fn mark_credential_used_statement(
        &self,
        credential_id: &str,
        now: &Timestamp,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            "UPDATE credentials SET last_used_at = ?2, updated_at = ?2 WHERE credential_id = ?1 AND status IN ('active', 'rotating')",
            &[
                BindValue::Text(credential_id),
                BindValue::Text(now.as_str()),
            ],
        )
    }

    pub fn update_budget_reservation_statement(
        &self,
        reservation_id: &str,
        org_id: &str,
        request_id: &str,
        committed_minor: Option<i64>,
        status: &str,
        now: &Timestamp,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            UPDATE_BUDGET_RESERVATION_SQL,
            &[
                BindValue::Text(reservation_id),
                BindValue::Text(org_id),
                committed_minor.map_or(BindValue::Null, |value| BindValue::Integer(value as i32)),
                BindValue::Text(status),
                BindValue::Text(now.as_str()),
                BindValue::Text(request_id),
            ],
        )
    }

    pub async fn hard_budget_remaining(
        &self,
        org_id: &str,
        now: &str,
    ) -> worker::Result<Option<i64>> {
        let result = self
            .database
            .prepare(
                "SELECT MIN(limit_minor - COALESCE((SELECT SUM(COALESCE(actual_cost_minor, estimated_cost_minor, 0)) FROM usage_events u WHERE u.org_id = b.org_id AND u.created_at >= b.period_start AND u.created_at < b.period_end), 0) - COALESCE((SELECT SUM(COALESCE(reserved_minor, 0) - COALESCE(committed_minor, 0)) FROM budget_reservations r WHERE r.org_id = b.org_id AND r.status = 'reserved' AND r.expires_at > ?2), 0)) AS remaining FROM budgets b WHERE b.org_id = ?1 AND b.hard = 1 AND b.period_start <= ?2 AND b.period_end > ?2",
                &[
                    BindValue::Text(org_id),
                    BindValue::Text(now),
                ],
            )?
            .first::<BudgetRemainingRow>(None)
            .await?;
        Ok(result.and_then(|row| row.remaining))
    }

    pub async fn list_usage(
        &self,
        org_id: &str,
        limit: u16,
        offset: u32,
    ) -> worker::Result<Vec<UsageRecord>> {
        let result = self
            .database
            .prepare(
                "SELECT usage_event_id, request_id, org_id, project_id, run_id, principal_user_id, session_id, device_id, model_alias, route_version_id, provider_id, model_id, credential_id, input_tokens, output_tokens, cached_tokens, provider_usage_json, estimated_cost_minor, actual_cost_minor, currency, pricing_version, budget_decision, ttft_ms, total_latency_ms, created_at FROM usage_events WHERE org_id = ?1 ORDER BY created_at DESC, usage_event_id DESC LIMIT ?2 OFFSET ?3",
                &[
                    BindValue::Text(org_id),
                    BindValue::Integer(i32::from(limit)),
                    BindValue::Integer(offset as i32),
                ],
            )?
            .all()
            .await?;
        rows_to_records(result.results::<UsageRow>())
    }
}

fn rows_to_records<R, T>(rows: worker::Result<Vec<R>>) -> worker::Result<Vec<T>>
where
    R: TryInto<T, Error = worker::Error>,
{
    rows?.into_iter().map(TryInto::try_into).collect()
}

fn optional_integer(value: Option<i64>) -> BindValue<'static> {
    // The SQL adapter only accepts borrowed strings/owned integer values. A
    // missing integer is represented by NULL; callers pass small values that
    // fit i32 on the Worker target.
    match value {
        Some(value) => BindValue::Integer(value as i32),
        None => BindValue::Null,
    }
}

#[derive(Deserialize)]
struct ProviderRow {
    provider_id: String,
    org_id: Option<String>,
    provider_key: String,
    display_name: String,
    adapter: String,
    lifecycle: String,
    version: i64,
    created_by_user_id: Option<String>,
    created_at: String,
    updated_at: String,
    endpoint_id: Option<String>,
    endpoint_url: Option<String>,
}

impl TryFrom<ProviderRow> for ProviderRecord {
    type Error = worker::Error;
    fn try_from(row: ProviderRow) -> Result<Self, Self::Error> {
        Ok(Self {
            provider_id: row.provider_id,
            org_id: row.org_id,
            provider_key: row.provider_key,
            display_name: row.display_name,
            adapter: row.adapter,
            lifecycle: row.lifecycle,
            version: row.version,
            created_by_user_id: row.created_by_user_id,
            created_at: row.created_at,
            updated_at: row.updated_at,
            endpoint_id: row.endpoint_id,
            endpoint_url: row.endpoint_url,
        })
    }
}

#[derive(Deserialize)]
struct ModelRow {
    model_id: String,
    provider_id: String,
    provider_model_id: String,
    display_name: String,
    capabilities_json: String,
    max_input_tokens: Option<i64>,
    max_output_tokens: Option<i64>,
    lifecycle: String,
    pricing_version: Option<String>,
    version: i64,
    created_by_user_id: Option<String>,
    created_at: String,
    updated_at: String,
}

impl TryFrom<ModelRow> for ModelRecord {
    type Error = worker::Error;
    fn try_from(row: ModelRow) -> Result<Self, Self::Error> {
        Ok(Self {
            model_id: row.model_id,
            provider_id: row.provider_id,
            provider_model_id: row.provider_model_id,
            display_name: row.display_name,
            capabilities_json: row.capabilities_json,
            max_input_tokens: row.max_input_tokens,
            max_output_tokens: row.max_output_tokens,
            lifecycle: row.lifecycle,
            pricing_version: row.pricing_version,
            version: row.version,
            created_by_user_id: row.created_by_user_id,
            created_at: row.created_at,
            updated_at: row.updated_at,
        })
    }
}

#[derive(Deserialize)]
struct AliasRow {
    alias_id: String,
    alias_key: String,
    display_name: String,
    lifecycle: String,
    description: Option<String>,
    created_at: String,
    updated_at: String,
}

impl TryFrom<AliasRow> for AliasRecord {
    type Error = worker::Error;
    fn try_from(row: AliasRow) -> Result<Self, Self::Error> {
        Ok(Self {
            alias_id: row.alias_id,
            alias_key: row.alias_key,
            display_name: row.display_name,
            lifecycle: row.lifecycle,
            description: row.description,
            created_at: row.created_at,
            updated_at: row.updated_at,
        })
    }
}

#[derive(Deserialize)]
struct PolicyRow {
    org_id: String,
    policy_version: i64,
    allowed_aliases_json: String,
    allowed_models_json: String,
    allowed_providers_json: String,
    credential_mode: String,
    managed_route_enabled: i64,
    version: i64,
    created_at: String,
    updated_at: String,
}

impl TryFrom<PolicyRow> for PolicyRecord {
    type Error = worker::Error;
    fn try_from(row: PolicyRow) -> Result<Self, Self::Error> {
        Ok(Self {
            org_id: row.org_id,
            policy_version: row.policy_version,
            allowed_aliases_json: row.allowed_aliases_json,
            allowed_models_json: row.allowed_models_json,
            allowed_providers_json: row.allowed_providers_json,
            credential_mode: row.credential_mode,
            managed_route_enabled: row.managed_route_enabled == 1,
            version: row.version,
            created_at: row.created_at,
            updated_at: row.updated_at,
        })
    }
}

#[derive(Deserialize)]
struct CredentialRow {
    credential_id: String,
    org_id: Option<String>,
    owner_type: String,
    owner_user_id: Option<String>,
    provider_id: String,
    label: String,
    ciphertext: Option<String>,
    nonce: Option<String>,
    key_version: Option<String>,
    fingerprint: String,
    status: String,
    version: i64,
    parent_credential_id: Option<String>,
    created_by_user_id: Option<String>,
    created_at: String,
    updated_at: String,
    last_used_at: Option<String>,
}

impl TryFrom<CredentialRow> for CredentialRecord {
    type Error = worker::Error;
    fn try_from(row: CredentialRow) -> Result<Self, Self::Error> {
        Ok(Self {
            credential_id: row.credential_id,
            org_id: row.org_id,
            owner_type: row.owner_type,
            owner_user_id: row.owner_user_id,
            provider_id: row.provider_id,
            label: row.label,
            ciphertext: row.ciphertext,
            nonce: row.nonce,
            key_version: row.key_version,
            fingerprint: row.fingerprint,
            status: row.status,
            version: row.version,
            parent_credential_id: row.parent_credential_id,
            created_by_user_id: row.created_by_user_id,
            created_at: row.created_at,
            updated_at: row.updated_at,
            last_used_at: row.last_used_at,
        })
    }
}

#[derive(Deserialize)]
struct RouteRow {
    route_id: String,
    org_id: String,
    alias: String,
    display_name: String,
    strategy: String,
    lifecycle: String,
    active_version_id: Option<String>,
    version: i64,
    created_by_user_id: String,
    created_at: String,
    updated_at: String,
}

impl TryFrom<RouteRow> for RouteRecord {
    type Error = worker::Error;
    fn try_from(row: RouteRow) -> Result<Self, Self::Error> {
        Ok(Self {
            route_id: row.route_id,
            org_id: row.org_id,
            alias: row.alias,
            display_name: row.display_name,
            strategy: row.strategy,
            lifecycle: row.lifecycle,
            active_version_id: row.active_version_id,
            version: row.version,
            created_by_user_id: row.created_by_user_id,
            created_at: row.created_at,
            updated_at: row.updated_at,
        })
    }
}

#[derive(Deserialize)]
struct RouteVersionRow {
    route_version_id: String,
    route_id: String,
    org_id: String,
    version_number: i64,
    config_json: String,
    config_hash: String,
    created_by_user_id: String,
    created_at: String,
    published_at: Option<String>,
}

impl TryFrom<RouteVersionRow> for RouteVersionRecord {
    type Error = worker::Error;
    fn try_from(row: RouteVersionRow) -> Result<Self, Self::Error> {
        Ok(Self {
            route_version_id: row.route_version_id,
            route_id: row.route_id,
            org_id: row.org_id,
            version_number: row.version_number,
            config_json: row.config_json,
            config_hash: row.config_hash,
            created_by_user_id: row.created_by_user_id,
            created_at: row.created_at,
            published_at: row.published_at,
        })
    }
}

#[derive(Deserialize)]
struct HealthRow {
    provider_id: String,
    org_id: String,
    state: String,
    consecutive_failures: i64,
    cooldown_until: Option<String>,
    last_success_at: Option<String>,
    last_failure_at: Option<String>,
    last_error_code: Option<String>,
    success_count: i64,
    failure_count: i64,
    timeout_count: i64,
    rate_limit_count: i64,
    sample_count: i64,
    ttft_ms_total: i64,
    completion_latency_ms_total: i64,
    updated_at: String,
}

impl TryFrom<HealthRow> for HealthRecord {
    type Error = worker::Error;
    fn try_from(row: HealthRow) -> Result<Self, Self::Error> {
        Ok(Self {
            provider_id: row.provider_id,
            org_id: row.org_id,
            state: row.state,
            consecutive_failures: row.consecutive_failures,
            cooldown_until: row.cooldown_until,
            last_success_at: row.last_success_at,
            last_failure_at: row.last_failure_at,
            last_error_code: row.last_error_code,
            success_count: row.success_count,
            failure_count: row.failure_count,
            timeout_count: row.timeout_count,
            rate_limit_count: row.rate_limit_count,
            sample_count: row.sample_count,
            ttft_ms_total: row.ttft_ms_total,
            completion_latency_ms_total: row.completion_latency_ms_total,
            updated_at: row.updated_at,
        })
    }
}

#[derive(Deserialize)]
struct BudgetRemainingRow {
    remaining: Option<i64>,
}

#[derive(Deserialize)]
struct UsageRow {
    usage_event_id: String,
    request_id: String,
    org_id: String,
    project_id: Option<String>,
    run_id: Option<String>,
    principal_user_id: String,
    session_id: Option<String>,
    device_id: Option<String>,
    model_alias: String,
    route_version_id: String,
    provider_id: String,
    model_id: String,
    credential_id: Option<String>,
    input_tokens: Option<i64>,
    output_tokens: Option<i64>,
    cached_tokens: Option<i64>,
    provider_usage_json: String,
    estimated_cost_minor: Option<i64>,
    actual_cost_minor: Option<i64>,
    currency: Option<String>,
    pricing_version: Option<String>,
    budget_decision: String,
    ttft_ms: Option<i64>,
    total_latency_ms: Option<i64>,
    created_at: String,
}

impl TryFrom<UsageRow> for UsageRecord {
    type Error = worker::Error;
    fn try_from(row: UsageRow) -> Result<Self, Self::Error> {
        Ok(Self {
            usage_event_id: row.usage_event_id,
            request_id: row.request_id,
            org_id: row.org_id,
            project_id: row.project_id,
            run_id: row.run_id,
            principal_user_id: row.principal_user_id,
            session_id: row.session_id,
            device_id: row.device_id,
            model_alias: row.model_alias,
            route_version_id: row.route_version_id,
            provider_id: row.provider_id,
            model_id: row.model_id,
            credential_id: row.credential_id,
            input_tokens: row.input_tokens,
            output_tokens: row.output_tokens,
            cached_tokens: row.cached_tokens,
            provider_usage_json: row.provider_usage_json,
            estimated_cost_minor: row.estimated_cost_minor,
            actual_cost_minor: row.actual_cost_minor,
            currency: row.currency,
            pricing_version: row.pricing_version,
            budget_decision: row.budget_decision,
            ttft_ms: row.ttft_ms,
            total_latency_ms: row.total_latency_ms,
            created_at: row.created_at,
        })
    }
}
