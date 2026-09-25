use serde::{Deserialize, Serialize};
use worker::d1::D1PreparedStatement;

use crate::{
    adapters::d1::{BindValue, D1Adapter},
    core::Timestamp,
};

const INSERT_ORG_SQL: &str = r#"
INSERT INTO organizations (org_id, display_name, slug, state, version, created_by_user_id, created_at, updated_at)
VALUES (?1, ?2, ?3, 'active', 1, ?4, ?5, ?5)
"#;

const UPDATE_ORG_STATE_SQL: &str = r#"
UPDATE organizations
SET state = ?2, version = version + 1, updated_at = ?3
WHERE org_id = ?1 AND state = ?4 AND version = ?5
"#;

const INSERT_MEMBERSHIP_SQL: &str = r#"
INSERT INTO memberships (
    membership_id, org_id, user_id, role, status, version, invited_by_user_id, joined_at, created_at, updated_at
) VALUES (?1, ?2, ?3, 'owner', 'active', 1, ?4, ?5, ?5, ?5)
"#;

const ORG_BY_ID_SQL: &str = r#"
SELECT org_id, display_name, slug, state, version, created_by_user_id, created_at, updated_at
FROM organizations
WHERE org_id = ?1
LIMIT 1
"#;

const ORGS_FOR_USER_SQL: &str = r#"
SELECT o.org_id, o.display_name, o.slug, o.state, o.version,
       o.created_by_user_id, o.created_at, o.updated_at, m.membership_id, m.role, m.status, m.version
FROM organizations o
JOIN memberships m ON m.org_id = o.org_id
WHERE m.user_id = ?1 AND m.status = 'active'
ORDER BY o.display_name ASC, o.org_id ASC
LIMIT ?2 OFFSET ?3
"#;

const MEMBERSHIP_BY_USER_ORG_SQL: &str = r#"
SELECT membership_id, org_id, user_id, role, status, version, invited_by_user_id, joined_at, created_at, updated_at
FROM memberships
WHERE org_id = ?1 AND user_id = ?2
LIMIT 1
"#;

const MEMBERS_BY_ORG_SQL: &str = r#"
SELECT membership_id, org_id, user_id, role, status, version, invited_by_user_id, joined_at, created_at, updated_at
FROM memberships
WHERE org_id = ?1
ORDER BY created_at ASC, membership_id ASC
LIMIT ?2 OFFSET ?3
"#;

const UPDATE_ORG_SQL: &str = r#"
UPDATE organizations
SET display_name = ?2, slug = ?3, version = version + 1, updated_at = ?4
WHERE org_id = ?1 AND state = 'active' AND version = ?5
"#;

const INSERT_INVITATION_SQL: &str = r#"
INSERT INTO invitations (
    invitation_id, org_id, email, role, invited_by_user_id, token_hash,
    status, expires_at, created_at, updated_at
) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'pending', ?7, ?8, ?8)
"#;

const PENDING_INVITATION_SQL: &str = r#"
SELECT invitation_id, org_id, email, role, invited_by_user_id, token_hash, status, expires_at, accepted_by_user_id, accepted_at, created_at, updated_at
FROM invitations
WHERE org_id = ?1 AND email = ?2 AND status = 'pending'
ORDER BY created_at DESC
LIMIT 1
"#;

const INVITATION_BY_ID_SQL: &str = r#"
SELECT invitation_id, org_id, email, role, invited_by_user_id, token_hash, status, expires_at, accepted_by_user_id, accepted_at, created_at, updated_at
FROM invitations
WHERE invitation_id = ?1
LIMIT 1
"#;

const INVITATIONS_BY_ORG_SQL: &str = r#"
SELECT invitation_id, org_id, email, role, invited_by_user_id, token_hash, status, expires_at, accepted_by_user_id, accepted_at, created_at, updated_at
FROM invitations
WHERE org_id = ?1 AND status IN ('pending', 'accepted', 'expired', 'revoked')
ORDER BY created_at DESC, invitation_id DESC
LIMIT ?2 OFFSET ?3
"#;

const REVOKE_INVITATION_SQL: &str = r#"
UPDATE invitations
SET status = 'revoked', updated_at = ?3
WHERE invitation_id = ?1 AND org_id = ?2 AND status = 'pending' AND expires_at > ?3
"#;

const ROTATE_INVITATION_SQL: &str = r#"
UPDATE invitations
SET token_hash = ?3, status = 'pending', expires_at = ?4, updated_at = ?5
WHERE invitation_id = ?1 AND org_id = ?2 AND status IN ('pending', 'expired', 'revoked')
"#;

const ACCEPT_INVITATION_SQL: &str = r#"
UPDATE invitations
SET status = 'accepted', accepted_by_user_id = ?2, accepted_at = ?3, updated_at = ?3
WHERE invitation_id = ?1
  AND status = 'pending'
  AND expires_at > ?3
  AND token_hash = ?4
"#;

const INSERT_INVITED_MEMBERSHIP_SQL: &str = r#"
INSERT INTO memberships (
    membership_id, org_id, user_id, role, status, version, invited_by_user_id, joined_at, created_at, updated_at
)
SELECT ?1, ?2, ?3, ?4, 'active', 1, ?5, ?6, ?6, ?6
WHERE EXISTS (
    SELECT 1 FROM invitations
    WHERE invitation_id = ?7
      AND status = 'accepted'
      AND accepted_by_user_id = ?3
      AND token_hash = ?8
)
ON CONFLICT (org_id, user_id) DO UPDATE SET
    status = 'active', role = excluded.role, version = memberships.version + 1,
    updated_at = excluded.updated_at
"#;

const CHANGE_ROLE_SQL: &str = r#"
UPDATE memberships
SET role = ?3, version = version + 1, updated_at = ?4
WHERE membership_id = ?1 AND org_id = ?2 AND status = 'active' AND version = ?5
  AND (
    role <> 'owner'
    OR ?3 = 'owner'
    OR (SELECT COUNT(*) FROM memberships
        WHERE org_id = ?2 AND role = 'owner' AND status = 'active') > 1
  )
"#;

const REMOVE_MEMBERSHIP_SQL: &str = r#"
UPDATE memberships
SET status = 'removed', version = version + 1, updated_at = ?2
WHERE membership_id = ?1 AND org_id = ?3 AND status = 'active' AND version = ?4
  AND (
    role <> 'owner'
    OR (SELECT COUNT(*) FROM memberships
        WHERE org_id = ?3 AND role = 'owner' AND status = 'active') > 1
  )
"#;

const TRANSFER_OWNERSHIP_SQL: &str = r#"
UPDATE memberships
SET role = CASE
        WHEN membership_id = ?1 THEN 'owner'
        WHEN role = 'owner' THEN 'admin'
        ELSE role
    END,
    version = version + 1,
    updated_at = ?4
WHERE org_id = ?2
  AND status = 'active'
  AND (membership_id = ?1 OR role = 'owner')
"#;

const INSERT_TEAM_SQL: &str = r#"
INSERT INTO teams (team_id, org_id, display_name, slug, created_by_user_id, version, created_at, updated_at)
VALUES (?1, ?2, ?3, ?4, ?5, 1, ?6, ?6)
"#;

const TEAMS_BY_ORG_SQL: &str = r#"
SELECT team_id, org_id, display_name, slug, created_by_user_id, version, created_at, updated_at
FROM teams
WHERE org_id = ?1
ORDER BY display_name ASC, team_id ASC
LIMIT ?2 OFFSET ?3
"#;

const INSERT_TEAM_MEMBER_SQL: &str = r#"
INSERT INTO team_members (team_member_id, org_id, team_id, membership_id, created_at)
VALUES (?1, ?2, ?3, ?4, ?5)
"#;

const DELETE_TEAM_MEMBER_SQL: &str = r#"
DELETE FROM team_members
WHERE org_id = ?1 AND team_id = ?2 AND membership_id = ?3
"#;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OrganizationRecord {
    pub org_id: String,
    pub display_name: String,
    pub slug: String,
    pub state: String,
    pub version: i64,
    pub created_by_user_id: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OrganizationSummary {
    pub organization: OrganizationRecord,
    pub membership_id: String,
    pub role: String,
    pub status: String,
    pub membership_version: i64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MembershipRecord {
    pub membership_id: String,
    pub org_id: String,
    pub user_id: String,
    pub role: String,
    pub status: String,
    pub version: i64,
    pub invited_by_user_id: Option<String>,
    pub joined_at: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InvitationRecord {
    pub invitation_id: String,
    pub org_id: String,
    pub email: String,
    pub role: String,
    pub invited_by_user_id: String,
    pub token_hash: String,
    pub status: String,
    pub expires_at: String,
    pub accepted_by_user_id: Option<String>,
    pub accepted_at: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TeamRecord {
    pub team_id: String,
    pub org_id: String,
    pub display_name: String,
    pub slug: String,
    pub created_by_user_id: String,
    pub version: i64,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Deserialize)]
struct OrgRow {
    org_id: String,
    display_name: String,
    slug: String,
    state: String,
    version: i64,
    created_by_user_id: String,
    created_at: String,
    updated_at: String,
}

#[derive(Deserialize)]
struct OrgSummaryRow {
    org_id: String,
    display_name: String,
    slug: String,
    state: String,
    version: i64,
    created_by_user_id: String,
    created_at: String,
    updated_at: String,
    membership_id: String,
    role: String,
    status: String,
    membership_version: i64,
}

#[derive(Deserialize)]
struct OwnerCountRow {
    owner_count: i64,
}

#[derive(Deserialize)]
struct MembershipRow {
    membership_id: String,
    org_id: String,
    user_id: String,
    role: String,
    status: String,
    version: i64,
    invited_by_user_id: Option<String>,
    joined_at: Option<String>,
    created_at: String,
    updated_at: String,
}

#[derive(Deserialize)]
struct InvitationRow {
    invitation_id: String,
    org_id: String,
    email: String,
    role: String,
    invited_by_user_id: String,
    token_hash: String,
    status: String,
    expires_at: String,
    accepted_by_user_id: Option<String>,
    accepted_at: Option<String>,
    created_at: String,
    updated_at: String,
}

#[derive(Deserialize)]
struct TeamRow {
    team_id: String,
    org_id: String,
    display_name: String,
    slug: String,
    created_by_user_id: String,
    version: i64,
    created_at: String,
    updated_at: String,
}

pub struct OrganizationRepository<'a> {
    database: &'a D1Adapter,
}

impl<'a> OrganizationRepository<'a> {
    pub fn new(database: &'a D1Adapter) -> Self {
        Self { database }
    }

    pub fn insert_organization_statement(
        &self,
        org_id: &str,
        display_name: &str,
        slug: &str,
        created_by: &str,
        now: &Timestamp,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            INSERT_ORG_SQL,
            &[
                BindValue::Text(org_id),
                BindValue::Text(display_name),
                BindValue::Text(slug),
                BindValue::Text(created_by),
                BindValue::Text(now.as_str()),
            ],
        )
    }

    pub fn insert_owner_membership_statement(
        &self,
        membership_id: &str,
        org_id: &str,
        user_id: &str,
        now: &Timestamp,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            INSERT_MEMBERSHIP_SQL,
            &[
                BindValue::Text(membership_id),
                BindValue::Text(org_id),
                BindValue::Text(user_id),
                BindValue::Text(user_id),
                BindValue::Text(now.as_str()),
            ],
        )
    }

    pub async fn create_organization(
        &self,
        org_id: &str,
        membership_id: &str,
        display_name: &str,
        slug: &str,
        created_by: &str,
        now: &Timestamp,
    ) -> worker::Result<OrganizationRecord> {
        self.database
            .batch(vec![
                self.insert_organization_statement(org_id, display_name, slug, created_by, now)?,
                self.insert_owner_membership_statement(membership_id, org_id, created_by, now)?,
            ])
            .await?;
        self.find_organization(org_id).await?.ok_or_else(|| {
            worker::Error::RustError("created organization could not be read".into())
        })
    }

    pub async fn find_organization(
        &self,
        org_id: &str,
    ) -> worker::Result<Option<OrganizationRecord>> {
        let row = self
            .database
            .prepare(ORG_BY_ID_SQL, &[BindValue::Text(org_id)])?
            .first::<OrgRow>(None)
            .await?;
        row.map(TryInto::try_into).transpose()
    }

    pub async fn list_for_user(
        &self,
        user_id: &str,
        limit: u16,
        offset: u32,
    ) -> worker::Result<Vec<OrganizationSummary>> {
        let result = self
            .database
            .prepare(
                ORGS_FOR_USER_SQL,
                &[
                    BindValue::Text(user_id),
                    BindValue::Integer(i32::from(limit)),
                    BindValue::Integer(offset as i32),
                ],
            )?
            .all()
            .await?;
        result
            .results::<OrgSummaryRow>()?
            .into_iter()
            .map(|row| {
                Ok(OrganizationSummary {
                    organization: OrganizationRecord {
                        org_id: row.org_id,
                        display_name: row.display_name,
                        slug: row.slug,
                        state: row.state,
                        version: row.version,
                        created_by_user_id: row.created_by_user_id,
                        created_at: row.created_at,
                        updated_at: row.updated_at,
                    },
                    membership_id: row.membership_id,
                    role: row.role,
                    status: row.status,
                    membership_version: row.membership_version,
                })
            })
            .collect()
    }

    pub async fn find_membership(
        &self,
        org_id: &str,
        user_id: &str,
    ) -> worker::Result<Option<MembershipRecord>> {
        let row = self
            .database
            .prepare(
                MEMBERSHIP_BY_USER_ORG_SQL,
                &[BindValue::Text(org_id), BindValue::Text(user_id)],
            )?
            .first::<MembershipRow>(None)
            .await?;
        row.map(TryInto::try_into).transpose()
    }

    pub async fn find_membership_by_id(
        &self,
        org_id: &str,
        membership_id: &str,
    ) -> worker::Result<Option<MembershipRecord>> {
        let result = self
            .database
            .prepare(
                "SELECT membership_id, org_id, user_id, role, status, version, invited_by_user_id, joined_at, created_at, updated_at FROM memberships WHERE org_id = ?1 AND membership_id = ?2 LIMIT 1",
                &[BindValue::Text(org_id), BindValue::Text(membership_id)],
            )?
            .first::<MembershipRow>(None)
            .await?;
        result.map(TryInto::try_into).transpose()
    }

    pub async fn find_team(
        &self,
        org_id: &str,
        team_id: &str,
    ) -> worker::Result<Option<TeamRecord>> {
        let result = self
            .database
            .prepare(
                "SELECT team_id, org_id, display_name, slug, created_by_user_id, version, created_at, updated_at FROM teams WHERE org_id = ?1 AND team_id = ?2 LIMIT 1",
                &[BindValue::Text(org_id), BindValue::Text(team_id)],
            )?
            .first::<TeamRow>(None)
            .await?;
        result.map(TryInto::try_into).transpose()
    }

    pub async fn active_owner_count(&self, org_id: &str) -> worker::Result<u32> {
        let row = self
            .database
            .prepare(
                "SELECT COUNT(*) AS owner_count FROM memberships WHERE org_id = ?1 AND role = 'owner' AND status = 'active'",
                &[BindValue::Text(org_id)],
            )?
            .first::<OwnerCountRow>(None)
            .await?;
        Ok(row.map_or(0, |row| row.owner_count.max(0) as u32))
    }

    pub async fn list_members(
        &self,
        org_id: &str,
        limit: u16,
        offset: u32,
    ) -> worker::Result<Vec<MembershipRecord>> {
        let result = self
            .database
            .prepare(
                MEMBERS_BY_ORG_SQL,
                &[
                    BindValue::Text(org_id),
                    BindValue::Integer(i32::from(limit)),
                    BindValue::Integer(offset as i32),
                ],
            )?
            .all()
            .await?;
        result
            .results::<MembershipRow>()?
            .into_iter()
            .map(TryInto::try_into)
            .collect()
    }

    pub async fn update_organization(
        &self,
        org_id: &str,
        display_name: &str,
        slug: &str,
        expected_version: i64,
        now: &Timestamp,
    ) -> worker::Result<bool> {
        let result = self
            .database
            .prepare(
                UPDATE_ORG_SQL,
                &[
                    BindValue::Text(org_id),
                    BindValue::Text(display_name),
                    BindValue::Text(slug),
                    BindValue::Text(now.as_str()),
                    BindValue::Integer(expected_version as i32),
                ],
            )?
            .run()
            .await?;
        Ok(D1Adapter::changes(&result)? == 1)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn update_state(
        &self,
        org_id: &str,
        expected_state: &str,
        next_state: &str,
        expected_version: i64,
        now: &Timestamp,
    ) -> worker::Result<bool> {
        let result = self
            .database
            .prepare(
                UPDATE_ORG_STATE_SQL,
                &[
                    BindValue::Text(org_id),
                    BindValue::Text(next_state),
                    BindValue::Text(now.as_str()),
                    BindValue::Text(expected_state),
                    BindValue::Integer(expected_version as i32),
                ],
            )?
            .run()
            .await?;
        Ok(D1Adapter::changes(&result)? == 1)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn insert_invitation_statement(
        &self,
        invitation_id: &str,
        org_id: &str,
        email: &str,
        role: &str,
        invited_by: &str,
        token_hash: &str,
        expires_at: &Timestamp,
        now: &Timestamp,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            INSERT_INVITATION_SQL,
            &[
                BindValue::Text(invitation_id),
                BindValue::Text(org_id),
                BindValue::Text(email),
                BindValue::Text(role),
                BindValue::Text(invited_by),
                BindValue::Text(token_hash),
                BindValue::Text(expires_at.as_str()),
                BindValue::Text(now.as_str()),
            ],
        )
    }

    pub async fn find_pending_invitation(
        &self,
        org_id: &str,
        email: &str,
    ) -> worker::Result<Option<InvitationRecord>> {
        let row = self
            .database
            .prepare(
                PENDING_INVITATION_SQL,
                &[BindValue::Text(org_id), BindValue::Text(email)],
            )?
            .first::<InvitationRow>(None)
            .await?;
        row.map(TryInto::try_into).transpose()
    }

    pub async fn find_invitation(
        &self,
        invitation_id: &str,
    ) -> worker::Result<Option<InvitationRecord>> {
        let row = self
            .database
            .prepare(INVITATION_BY_ID_SQL, &[BindValue::Text(invitation_id)])?
            .first::<InvitationRow>(None)
            .await?;
        row.map(TryInto::try_into).transpose()
    }

    pub async fn list_invitations(
        &self,
        org_id: &str,
        limit: u16,
        offset: u32,
    ) -> worker::Result<Vec<InvitationRecord>> {
        let result = self
            .database
            .prepare(
                INVITATIONS_BY_ORG_SQL,
                &[
                    BindValue::Text(org_id),
                    BindValue::Integer(i32::from(limit)),
                    BindValue::Integer(offset as i32),
                ],
            )?
            .all()
            .await?;
        result
            .results::<InvitationRow>()?
            .into_iter()
            .map(TryInto::try_into)
            .collect()
    }

    pub async fn revoke_invitation(
        &self,
        invitation_id: &str,
        org_id: &str,
        now: &Timestamp,
    ) -> worker::Result<bool> {
        let result = self
            .database
            .prepare(
                REVOKE_INVITATION_SQL,
                &[
                    BindValue::Text(invitation_id),
                    BindValue::Text(org_id),
                    BindValue::Text(now.as_str()),
                ],
            )?
            .run()
            .await?;
        Ok(D1Adapter::changes(&result)? == 1)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn rotate_invitation_statement(
        &self,
        invitation_id: &str,
        org_id: &str,
        token_hash: &str,
        expires_at: &Timestamp,
        now: &Timestamp,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            ROTATE_INVITATION_SQL,
            &[
                BindValue::Text(invitation_id),
                BindValue::Text(org_id),
                BindValue::Text(token_hash),
                BindValue::Text(expires_at.as_str()),
                BindValue::Text(now.as_str()),
            ],
        )
    }

    pub fn accept_invitation_statement(
        &self,
        invitation_id: &str,
        user_id: &str,
        token_hash: &str,
        now: &Timestamp,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            ACCEPT_INVITATION_SQL,
            &[
                BindValue::Text(invitation_id),
                BindValue::Text(user_id),
                BindValue::Text(now.as_str()),
                BindValue::Text(token_hash),
            ],
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn insert_invited_membership_statement(
        &self,
        membership_id: &str,
        org_id: &str,
        user_id: &str,
        role: &str,
        inviter: &str,
        invitation_id: &str,
        token_hash: &str,
        now: &Timestamp,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            INSERT_INVITED_MEMBERSHIP_SQL,
            &[
                BindValue::Text(membership_id),
                BindValue::Text(org_id),
                BindValue::Text(user_id),
                BindValue::Text(role),
                BindValue::Text(inviter),
                BindValue::Text(now.as_str()),
                BindValue::Text(invitation_id),
                BindValue::Text(token_hash),
            ],
        )
    }

    pub async fn change_role(
        &self,
        membership_id: &str,
        org_id: &str,
        role: &str,
        expected_version: i64,
        now: &Timestamp,
    ) -> worker::Result<bool> {
        let result = self
            .database
            .prepare(
                CHANGE_ROLE_SQL,
                &[
                    BindValue::Text(membership_id),
                    BindValue::Text(org_id),
                    BindValue::Text(role),
                    BindValue::Text(now.as_str()),
                    BindValue::Integer(expected_version as i32),
                ],
            )?
            .run()
            .await?;
        Ok(D1Adapter::changes(&result)? == 1)
    }

    pub async fn remove_member(
        &self,
        membership_id: &str,
        org_id: &str,
        expected_version: i64,
        now: &Timestamp,
    ) -> worker::Result<bool> {
        let result = self
            .database
            .prepare(
                REMOVE_MEMBERSHIP_SQL,
                &[
                    BindValue::Text(membership_id),
                    BindValue::Text(now.as_str()),
                    BindValue::Text(org_id),
                    BindValue::Integer(expected_version as i32),
                ],
            )?
            .run()
            .await?;
        Ok(D1Adapter::changes(&result)? == 1)
    }

    pub async fn transfer_ownership(
        &self,
        target_membership_id: &str,
        org_id: &str,
        now: &Timestamp,
    ) -> worker::Result<bool> {
        let result = self
            .database
            .prepare(
                TRANSFER_OWNERSHIP_SQL,
                &[
                    BindValue::Text(target_membership_id),
                    BindValue::Text(org_id),
                    BindValue::Text(target_membership_id),
                    BindValue::Text(now.as_str()),
                ],
            )?
            .run()
            .await?;
        Ok(D1Adapter::changes(&result)? >= 2)
    }

    pub fn insert_team_statement(
        &self,
        team_id: &str,
        org_id: &str,
        display_name: &str,
        slug: &str,
        created_by: &str,
        now: &Timestamp,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            INSERT_TEAM_SQL,
            &[
                BindValue::Text(team_id),
                BindValue::Text(org_id),
                BindValue::Text(display_name),
                BindValue::Text(slug),
                BindValue::Text(created_by),
                BindValue::Text(now.as_str()),
            ],
        )
    }

    pub async fn list_teams(
        &self,
        org_id: &str,
        limit: u16,
        offset: u32,
    ) -> worker::Result<Vec<TeamRecord>> {
        let result = self
            .database
            .prepare(
                TEAMS_BY_ORG_SQL,
                &[
                    BindValue::Text(org_id),
                    BindValue::Integer(i32::from(limit)),
                    BindValue::Integer(offset as i32),
                ],
            )?
            .all()
            .await?;
        result
            .results::<TeamRow>()?
            .into_iter()
            .map(TryInto::try_into)
            .collect()
    }

    pub async fn add_team_member(
        &self,
        team_member_id: &str,
        org_id: &str,
        team_id: &str,
        membership_id: &str,
        now: &Timestamp,
    ) -> worker::Result<bool> {
        let result = self
            .database
            .prepare(
                INSERT_TEAM_MEMBER_SQL,
                &[
                    BindValue::Text(team_member_id),
                    BindValue::Text(org_id),
                    BindValue::Text(team_id),
                    BindValue::Text(membership_id),
                    BindValue::Text(now.as_str()),
                ],
            )?
            .run()
            .await?;
        Ok(D1Adapter::changes(&result)? == 1)
    }

    pub async fn remove_team_member(
        &self,
        org_id: &str,
        team_id: &str,
        membership_id: &str,
    ) -> worker::Result<bool> {
        let result = self
            .database
            .prepare(
                DELETE_TEAM_MEMBER_SQL,
                &[
                    BindValue::Text(org_id),
                    BindValue::Text(team_id),
                    BindValue::Text(membership_id),
                ],
            )?
            .run()
            .await?;
        Ok(D1Adapter::changes(&result)? == 1)
    }
}

impl TryFrom<OrgRow> for OrganizationRecord {
    type Error = worker::Error;
    fn try_from(row: OrgRow) -> Result<Self, Self::Error> {
        Ok(Self {
            org_id: row.org_id,
            display_name: row.display_name,
            slug: row.slug,
            state: row.state,
            version: row.version,
            created_by_user_id: row.created_by_user_id,
            created_at: row.created_at,
            updated_at: row.updated_at,
        })
    }
}

impl TryFrom<OrgSummaryRow> for OrganizationSummary {
    type Error = worker::Error;
    fn try_from(row: OrgSummaryRow) -> Result<Self, Self::Error> {
        Ok(Self {
            organization: OrganizationRecord {
                org_id: row.org_id,
                display_name: row.display_name,
                slug: row.slug,
                state: row.state,
                version: row.version,
                created_by_user_id: row.created_by_user_id,
                created_at: row.created_at,
                updated_at: row.updated_at,
            },
            membership_id: row.membership_id,
            role: row.role,
            status: row.status,
            membership_version: row.membership_version,
        })
    }
}

impl TryFrom<MembershipRow> for MembershipRecord {
    type Error = worker::Error;
    fn try_from(row: MembershipRow) -> Result<Self, Self::Error> {
        Ok(Self {
            membership_id: row.membership_id,
            org_id: row.org_id,
            user_id: row.user_id,
            role: row.role,
            status: row.status,
            version: row.version,
            invited_by_user_id: row.invited_by_user_id,
            joined_at: row.joined_at,
            created_at: row.created_at,
            updated_at: row.updated_at,
        })
    }
}

impl TryFrom<InvitationRow> for InvitationRecord {
    type Error = worker::Error;
    fn try_from(row: InvitationRow) -> Result<Self, Self::Error> {
        Ok(Self {
            invitation_id: row.invitation_id,
            org_id: row.org_id,
            email: row.email,
            role: row.role,
            invited_by_user_id: row.invited_by_user_id,
            token_hash: row.token_hash,
            status: row.status,
            expires_at: row.expires_at,
            accepted_by_user_id: row.accepted_by_user_id,
            accepted_at: row.accepted_at,
            created_at: row.created_at,
            updated_at: row.updated_at,
        })
    }
}

impl TryFrom<TeamRow> for TeamRecord {
    type Error = worker::Error;
    fn try_from(row: TeamRow) -> Result<Self, Self::Error> {
        Ok(Self {
            team_id: row.team_id,
            org_id: row.org_id,
            display_name: row.display_name,
            slug: row.slug,
            created_by_user_id: row.created_by_user_id,
            version: row.version,
            created_at: row.created_at,
            updated_at: row.updated_at,
        })
    }
}
