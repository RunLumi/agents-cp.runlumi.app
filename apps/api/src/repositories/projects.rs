//! D1 persistence for P03 projects, access grants, and workspace bindings.

use serde::{Deserialize, Serialize};
use worker::d1::D1PreparedStatement;

use crate::{
    adapters::d1::{BindValue, D1Adapter},
    core::Timestamp,
};

const INSERT_PROJECT_SQL: &str = r#"
INSERT INTO projects (
    project_id, org_id, name, slug, visibility, archived_at,
    default_model_route, version, created_by_user_id, created_at, updated_at
) VALUES (?1, ?2, ?3, ?4, ?5, NULL, ?6, 1, ?7, ?8, ?8)
"#;

const PROJECT_BY_ID_SQL: &str = r#"
SELECT project_id, org_id, name, slug, visibility, archived_at, default_model_route,
       version, created_by_user_id, created_at, updated_at
FROM projects
WHERE project_id = ?1
LIMIT 1
"#;

const UPDATE_PROJECT_SQL: &str = r#"
UPDATE projects
SET name = ?2, visibility = ?3, archived_at = ?4, default_model_route = ?5,
    version = version + 1, updated_at = ?6
WHERE project_id = ?1 AND org_id = ?7 AND version = ?8
"#;

const PROJECT_SLUG_COUNT_SQL: &str = r#"
SELECT COUNT(*) AS n FROM projects WHERE org_id = ?1 AND slug = ?2
"#;

/// Org-visible projects plus restricted projects where the member has an
/// explicit member or team grant. Keyset-paged on `(created_at, project_id)`.
const PROJECTS_PAGE_SQL: &str = r#"
SELECT project_id, org_id, name, slug, visibility, archived_at, default_model_route,
       version, created_by_user_id, created_at, updated_at
FROM projects
WHERE org_id = ?1
  AND (created_at, project_id) < (?2, ?3)
  AND (visibility = 'org' OR EXISTS (
       SELECT 1 FROM project_access_grants g
       WHERE g.project_id = projects.project_id
         AND (g.member_id IN (
                 SELECT membership_id FROM memberships
                 WHERE org_id = projects.org_id AND user_id = ?4 AND status = 'active')
            OR g.team_id IN (
                 SELECT tm.team_id FROM team_members tm
                 JOIN memberships m ON m.membership_id = tm.membership_id
                 WHERE m.org_id = projects.org_id AND m.user_id = ?4 AND m.status = 'active'))))
ORDER BY created_at DESC, project_id DESC
LIMIT ?5
"#;

const FIRST_PROJECTS_PAGE_SQL: &str = r#"
SELECT project_id, org_id, name, slug, visibility, archived_at, default_model_route,
       version, created_by_user_id, created_at, updated_at
FROM projects
WHERE org_id = ?1
  AND (visibility = 'org' OR EXISTS (
       SELECT 1 FROM project_access_grants g
       WHERE g.project_id = projects.project_id
         AND (g.member_id IN (
                 SELECT membership_id FROM memberships
                 WHERE org_id = projects.org_id AND user_id = ?2 AND status = 'active')
            OR g.team_id IN (
                 SELECT tm.team_id FROM team_members tm
                 JOIN memberships m ON m.membership_id = tm.membership_id
                 WHERE m.org_id = projects.org_id AND m.user_id = ?2 AND m.status = 'active'))))
ORDER BY created_at DESC, project_id DESC
LIMIT ?3
"#;

const INSERT_GRANT_SQL: &str = r#"
INSERT INTO project_access_grants (grant_id, project_id, org_id, member_id, team_id, created_at)
VALUES (?1, ?2, ?3, ?4, ?5, ?6)
"#;

const DELETE_GRANT_SQL: &str = r#"
DELETE FROM project_access_grants
WHERE grant_id = ?1 AND project_id = ?2
"#;

const GRANT_BY_ID_SQL: &str = r#"
SELECT grant_id, project_id, org_id, member_id, team_id, created_at
FROM project_access_grants
WHERE grant_id = ?1
LIMIT 1
"#;

const GRANTS_BY_PROJECT_SQL: &str = r#"
SELECT grant_id, project_id, org_id, member_id, team_id, created_at
FROM project_access_grants
WHERE project_id = ?1
ORDER BY created_at DESC, grant_id DESC
LIMIT ?2
"#;

const GRANT_FOR_MEMBER_SQL: &str = r#"
SELECT 1 AS allowed
FROM project_access_grants g
WHERE g.project_id = ?1
  AND (g.member_id IN (
          SELECT membership_id FROM memberships
          WHERE org_id = ?2 AND user_id = ?3 AND status = 'active')
       OR g.team_id IN (
          SELECT tm.team_id FROM team_members tm
          JOIN memberships m ON m.membership_id = tm.membership_id
          WHERE m.org_id = ?2 AND m.user_id = ?3 AND m.status = 'active'))
LIMIT 1
"#;

const INSERT_BINDING_SQL: &str = r#"
INSERT INTO workspace_bindings (
    binding_id, org_id, project_id, device_id, workspace_identity,
    display_name, environment_type, created_at, updated_at
) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?8)
"#;

const BINDING_BY_ID_SQL: &str = r#"
SELECT binding_id, org_id, project_id, device_id, workspace_identity, display_name,
       environment_type, last_seen_at, created_at, updated_at
FROM workspace_bindings
WHERE binding_id = ?1
LIMIT 1
"#;

const BINDINGS_BY_PROJECT_SQL: &str = r#"
SELECT binding_id, org_id, project_id, device_id, workspace_identity, display_name,
       environment_type, last_seen_at, created_at, updated_at
FROM workspace_bindings
WHERE project_id = ?1
ORDER BY created_at DESC, binding_id DESC
LIMIT ?2
"#;

const BINDINGS_BY_DEVICE_SQL: &str = r#"
SELECT binding_id, org_id, project_id, device_id, workspace_identity, display_name,
       environment_type, last_seen_at, created_at, updated_at
FROM workspace_bindings
WHERE device_id = ?1
ORDER BY created_at DESC, binding_id DESC
LIMIT ?2
"#;

const DELETE_BINDING_SQL: &str = r#"
DELETE FROM workspace_bindings WHERE binding_id = ?1 AND project_id = ?2
"#;

const BINDING_COUNT_FOR_DEVICE_SQL: &str = r#"
SELECT COUNT(*) AS n FROM workspace_bindings
WHERE device_id = ?1 AND workspace_identity = ?2
"#;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectRecord {
    pub project_id: String,
    pub org_id: String,
    pub name: String,
    pub slug: String,
    pub visibility: String,
    pub archived_at: Option<String>,
    pub default_model_route: Option<String>,
    pub version: i64,
    pub created_by_user_id: String,
    pub created_at: String,
    pub updated_at: String,
}

/// Statement input for a new project.
pub struct NewProjectInput<'a> {
    pub project_id: &'a str,
    pub org_id: &'a str,
    pub name: &'a str,
    pub slug: &'a str,
    pub visibility: &'a str,
    pub created_by_user_id: &'a str,
}

/// Statement input for an optimistic-version project mutation.
pub struct ProjectUpdateInput<'a> {
    pub project_id: &'a str,
    pub org_id: &'a str,
    pub name: &'a str,
    pub visibility: &'a str,
    pub archived_at: Option<&'a str>,
    pub now: &'a Timestamp,
    pub expected_version: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectGrantRecord {
    pub grant_id: String,
    pub project_id: String,
    pub org_id: String,
    pub member_id: Option<String>,
    pub team_id: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkspaceBindingRecord {
    pub binding_id: String,
    pub org_id: String,
    pub project_id: String,
    pub device_id: String,
    pub workspace_identity: String,
    pub display_name: String,
    pub environment_type: String,
    pub last_seen_at: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

pub struct ProjectRepository<'a> {
    database: &'a D1Adapter,
}

impl<'a> ProjectRepository<'a> {
    pub fn new(database: &'a D1Adapter) -> Self {
        Self { database }
    }

    pub fn insert_project_statement(
        &self,
        project: &NewProjectInput<'_>,
        now: &Timestamp,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            INSERT_PROJECT_SQL,
            &[
                BindValue::Text(project.project_id),
                BindValue::Text(project.org_id),
                BindValue::Text(project.name),
                BindValue::Text(project.slug),
                BindValue::Text(project.visibility),
                BindValue::Null,
                BindValue::Text(project.created_by_user_id),
                BindValue::Text(now.as_str()),
            ],
        )
    }

    pub async fn find_project(&self, project_id: &str) -> worker::Result<Option<ProjectRecord>> {
        let statement = self
            .database
            .prepare(PROJECT_BY_ID_SQL, &[BindValue::Text(project_id)])?;
        statement.first::<ProjectRecord>(None).await
    }

    pub async fn project_slug_count(&self, org_id: &str, slug: &str) -> worker::Result<u32> {
        let statement = self.database.prepare(
            PROJECT_SLUG_COUNT_SQL,
            &[BindValue::Text(org_id), BindValue::Text(slug)],
        )?;
        let row = statement
            .first::<serde_json::Value>(None)
            .await?
            .ok_or_else(|| worker::Error::RustError("slug count missing".into()))?;
        Ok(row
            .get("n")
            .and_then(|value| value.as_u64())
            .unwrap_or_default() as u32)
    }

    pub async fn list_projects_for_member(
        &self,
        org_id: &str,
        user_id: &str,
        cursor: Option<(&str, &str)>,
        limit: i32,
    ) -> worker::Result<Vec<ProjectRecord>> {
        let statement = match cursor {
            Some((created_at, project_id)) => self.database.prepare(
                PROJECTS_PAGE_SQL,
                &[
                    BindValue::Text(org_id),
                    BindValue::Text(created_at),
                    BindValue::Text(project_id),
                    BindValue::Text(user_id),
                    BindValue::Integer(limit),
                ],
            )?,
            None => self.database.prepare(
                FIRST_PROJECTS_PAGE_SQL,
                &[
                    BindValue::Text(org_id),
                    BindValue::Text(user_id),
                    BindValue::Integer(limit),
                ],
            )?,
        };
        statement.all().await?.results::<ProjectRecord>()
    }

    /// Apply a project mutation guarded by the optimistic version. `archived_at`
    /// is set or cleared according to the requested archive state.
    pub async fn update_project(
        &self,
        update: &ProjectUpdateInput<'_>,
    ) -> worker::Result<Option<ProjectRecord>> {
        let archive_value = match update.archived_at {
            Some(value) => BindValue::Text(value),
            None => BindValue::Null,
        };
        let statement = self.database.prepare(
            UPDATE_PROJECT_SQL,
            &[
                BindValue::Text(update.name),
                BindValue::Text(update.visibility),
                archive_value,
                BindValue::Null,
                BindValue::Text(update.now.as_str()),
                BindValue::Text(update.project_id),
                BindValue::Text(update.org_id),
                BindValue::Integer(i32::try_from(update.expected_version).unwrap_or_default()),
            ],
        );
        let result = statement?.run().await?;
        if D1Adapter::changes(&result)? == 0 {
            return Ok(None);
        }
        self.find_project(update.project_id).await
    }

    pub async fn insert_grant(
        &self,
        grant_id: &str,
        project_id: &str,
        org_id: &str,
        member_id: Option<&str>,
        team_id: Option<&str>,
        now: &Timestamp,
    ) -> worker::Result<()> {
        let statement = match (member_id, team_id) {
            (Some(member), None) => self.database.prepare(
                INSERT_GRANT_SQL,
                &[
                    BindValue::Text(grant_id),
                    BindValue::Text(project_id),
                    BindValue::Text(org_id),
                    BindValue::Text(member),
                    BindValue::Null,
                    BindValue::Text(now.as_str()),
                ],
            )?,
            (None, Some(team)) => self.database.prepare(
                INSERT_GRANT_SQL,
                &[
                    BindValue::Text(grant_id),
                    BindValue::Text(project_id),
                    BindValue::Text(org_id),
                    BindValue::Null,
                    BindValue::Text(team),
                    BindValue::Text(now.as_str()),
                ],
            )?,
            _ => {
                return Err(worker::Error::RustError(
                    "project grant requires exactly one of member_id or team_id".into(),
                ));
            }
        };
        statement.run().await?;
        Ok(())
    }

    pub async fn find_grant(&self, grant_id: &str) -> worker::Result<Option<ProjectGrantRecord>> {
        let statement = self
            .database
            .prepare(GRANT_BY_ID_SQL, &[BindValue::Text(grant_id)])?;
        statement.first::<ProjectGrantRecord>(None).await
    }

    pub async fn delete_grant(&self, grant_id: &str, project_id: &str) -> worker::Result<bool> {
        let statement = self.database.prepare(
            DELETE_GRANT_SQL,
            &[BindValue::Text(grant_id), BindValue::Text(project_id)],
        )?;
        let result = statement.run().await?;
        Ok(D1Adapter::changes(&result)? > 0)
    }

    pub async fn list_grants_by_project(
        &self,
        project_id: &str,
        limit: i32,
    ) -> worker::Result<Vec<ProjectGrantRecord>> {
        let statement = self.database.prepare(
            GRANTS_BY_PROJECT_SQL,
            &[BindValue::Text(project_id), BindValue::Integer(limit)],
        )?;
        statement.all().await?.results::<ProjectGrantRecord>()
    }

    /// True when the member holds an explicit grant (direct or via team).
    pub async fn member_has_explicit_grant(
        &self,
        project_id: &str,
        org_id: &str,
        user_id: &str,
    ) -> worker::Result<bool> {
        let statement = self.database.prepare(
            GRANT_FOR_MEMBER_SQL,
            &[
                BindValue::Text(project_id),
                BindValue::Text(org_id),
                BindValue::Text(user_id),
            ],
        )?;
        let row = statement.first::<serde_json::Value>(None).await?;
        Ok(row.is_some())
    }

    pub async fn insert_binding(&self, binding: &WorkspaceBindingRecord) -> worker::Result<()> {
        let statement = self.database.prepare(
            INSERT_BINDING_SQL,
            &[
                BindValue::Text(&binding.binding_id),
                BindValue::Text(&binding.org_id),
                BindValue::Text(&binding.project_id),
                BindValue::Text(&binding.device_id),
                BindValue::Text(&binding.workspace_identity),
                BindValue::Text(&binding.display_name),
                BindValue::Text(&binding.environment_type),
                BindValue::Text(&binding.created_at),
            ],
        )?;
        statement.run().await?;
        Ok(())
    }

    pub async fn find_binding(
        &self,
        binding_id: &str,
    ) -> worker::Result<Option<WorkspaceBindingRecord>> {
        let statement = self
            .database
            .prepare(BINDING_BY_ID_SQL, &[BindValue::Text(binding_id)])?;
        statement.first::<WorkspaceBindingRecord>(None).await
    }

    pub async fn binding_identity_count(
        &self,
        device_id: &str,
        workspace_identity: &str,
    ) -> worker::Result<u32> {
        let statement = self.database.prepare(
            BINDING_COUNT_FOR_DEVICE_SQL,
            &[
                BindValue::Text(device_id),
                BindValue::Text(workspace_identity),
            ],
        )?;
        let row = statement
            .first::<serde_json::Value>(None)
            .await?
            .ok_or_else(|| worker::Error::RustError("binding count missing".into()))?;
        Ok(row
            .get("n")
            .and_then(|value| value.as_u64())
            .unwrap_or_default() as u32)
    }

    pub async fn list_bindings_by_project(
        &self,
        project_id: &str,
        limit: i32,
    ) -> worker::Result<Vec<WorkspaceBindingRecord>> {
        let statement = self.database.prepare(
            BINDINGS_BY_PROJECT_SQL,
            &[BindValue::Text(project_id), BindValue::Integer(limit)],
        )?;
        statement.all().await?.results::<WorkspaceBindingRecord>()
    }

    pub async fn list_bindings_by_device(
        &self,
        device_id: &str,
        limit: i32,
    ) -> worker::Result<Vec<WorkspaceBindingRecord>> {
        let statement = self.database.prepare(
            BINDINGS_BY_DEVICE_SQL,
            &[BindValue::Text(device_id), BindValue::Integer(limit)],
        )?;
        statement.all().await?.results::<WorkspaceBindingRecord>()
    }

    pub async fn delete_binding(&self, binding_id: &str, project_id: &str) -> worker::Result<bool> {
        let statement = self.database.prepare(
            DELETE_BINDING_SQL,
            &[BindValue::Text(binding_id), BindValue::Text(project_id)],
        )?;
        let result = statement.run().await?;
        Ok(D1Adapter::changes(&result)? > 0)
    }
}
