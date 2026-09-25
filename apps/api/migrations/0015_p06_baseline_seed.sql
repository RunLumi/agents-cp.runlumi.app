-- 0015_p06_baseline_seed.sql — static P06 platform data.
--
-- Apply after 0014_p06_data_governance.sql.
--
-- WHY a migration and not a request path: the baseline entitlement registry and
-- the default plan are PLATFORM data. They are not tenant state, they change
-- only through a contract-governed migration, and every organization resolves
-- against exactly the same set. Computing them per request would let two
-- requests disagree, and seeding them on org creation would let a partially
-- applied org exist without them.
--
-- The per-organization `license_states` row is NOT seeded here: that is tenant
-- state and it is created in the same D1 batch that creates the organization,
-- so an organization can never exist without a license projection.

--------------------------------------------------------------------------------
-- Baseline entitlement definitions (the stable Lumi key registry)
--------------------------------------------------------------------------------
-- The public identity of an entitlement is its stable dotted Lumi key. These
-- are deliberately NOT payment-provider product or price IDs; the same trigger
-- that rejects `price_…` in 0013 also applies here.
--
-- `default_value_json` is the PLATFORM DEFAULT, the lowest precedence tier. It
-- is not a grant: a value here is what an organization with no plan, no
-- subscription, and no override resolves to.
INSERT INTO entitlement_definitions
    (entitlement_definition_id, entitlement_key, value_type, scope, default_value_json, unit, description, version, created_at, updated_at)
VALUES
    ('ent_000000000000000000000000000000a1', 'org.max_members', 'integer', 'organization', '5', 'members',
     'Maximum active organization members.', 1, '2026-09-25T00:00:00.000Z', '2026-09-25T00:00:00.000Z'),
    ('ent_000000000000000000000000000000a2', 'projects.max_active', 'integer', 'organization', '3', 'projects',
     'Maximum active projects in an organization.', 1, '2026-09-25T00:00:00.000Z', '2026-09-25T00:00:00.000Z'),
    ('ent_000000000000000000000000000000a3', 'inference.platform_managed', 'boolean', 'organization', 'true', NULL,
     'Platform-managed inference routes may be used.', 1, '2026-09-25T00:00:00.000Z', '2026-09-25T00:00:00.000Z'),
    ('ent_000000000000000000000000000000a4', 'inference.byok', 'boolean', 'organization', 'false', NULL,
     'Organization-supplied provider credentials may be used.', 1, '2026-09-25T00:00:00.000Z', '2026-09-25T00:00:00.000Z'),
    ('ent_000000000000000000000000000000a5', 'audit.retention_days', 'integer', 'organization', '90', 'days',
     'Audit and security event retention window.', 1, '2026-09-25T00:00:00.000Z', '2026-09-25T00:00:00.000Z'),
    ('ent_000000000000000000000000000000a6', 'automations.max_active', 'integer', 'organization', '5', 'automations',
     'Maximum active automations. A downgrade blocks new automations and never deletes existing ones.', 1, '2026-09-25T00:00:00.000Z', '2026-09-25T00:00:00.000Z'),
    ('ent_000000000000000000000000000000a7', 'automations.max_concurrent', 'integer', 'organization', '2', 'automations',
     'Maximum automations executing concurrently for one organization.', 1, '2026-09-25T00:00:00.000Z', '2026-09-25T00:00:00.000Z'),
    ('ent_000000000000000000000000000000a8', 'automations.off_peak_enabled', 'boolean', 'organization', 'false', NULL,
     'Off-peak execution is available. Off-peak is a distinct execution class, not a schedule window.', 1, '2026-09-25T00:00:00.000Z', '2026-09-25T00:00:00.000Z'),
    ('ent_000000000000000000000000000000a9', 'devices.max_enrolled', 'integer', 'organization', '3', 'devices',
     'Maximum enrolled managed devices.', 1, '2026-09-25T00:00:00.000Z', '2026-09-25T00:00:00.000Z'),
    ('ent_000000000000000000000000000000aa', 'webhooks.enabled', 'boolean', 'organization', 'false', NULL,
     'Outbound webhook delivery is available.', 1, '2026-09-25T00:00:00.000Z', '2026-09-25T00:00:00.000Z'),
    ('ent_000000000000000000000000000000ab', 'webhooks.max_endpoints', 'integer', 'organization', '0', 'endpoints',
     'Maximum webhook endpoints. Zero while webhooks are disabled.', 1, '2026-09-25T00:00:00.000Z', '2026-09-25T00:00:00.000Z'),
    ('ent_000000000000000000000000000000ac', 'notifications.in_app_enabled', 'boolean', 'organization', 'true', NULL,
     'In-app notifications are available.', 1, '2026-09-25T00:00:00.000Z', '2026-09-25T00:00:00.000Z'),
    ('ent_000000000000000000000000000000ad', 'notifications.email_enabled', 'boolean', 'organization', 'false', NULL,
     'Email notification delivery is available. Mandatory security events are unaffected.', 1, '2026-09-25T00:00:00.000Z', '2026-09-25T00:00:00.000Z'),
    ('ent_000000000000000000000000000000ae', 'exports.enabled', 'boolean', 'organization', 'true', NULL,
     'Self-service data export is available.', 1, '2026-09-25T00:00:00.000Z', '2026-09-25T00:00:00.000Z'),
    ('ent_000000000000000000000000000000af', 'deletion.self_service', 'boolean', 'organization', 'true', NULL,
     'Self-service account deletion is available.', 1, '2026-09-25T00:00:00.000Z', '2026-09-25T00:00:00.000Z'),
    ('ent_000000000000000000000000000000b0', 'sso.enabled', 'boolean', 'organization', 'false', NULL,
     'Organization SSO/SAML is available.', 1, '2026-09-25T00:00:00.000Z', '2026-09-25T00:00:00.000Z'),
    ('ent_000000000000000000000000000000b1', 'scim.enabled', 'boolean', 'organization', 'false', NULL,
     'SCIM user provisioning is available.', 1, '2026-09-25T00:00:00.000Z', '2026-09-25T00:00:00.000Z'),
    ('ent_000000000000000000000000000000b2', 'data.export.enabled', 'boolean', 'organization', 'true', NULL,
     'Data export jobs may be requested. Distinct from the product-level exports.enabled capability.', 1, '2026-09-25T00:00:00.000Z', '2026-09-25T00:00:00.000Z'),
    ('ent_000000000000000000000000000000b3', 'data.deletion.self_service', 'boolean', 'organization', 'true', NULL,
     'Data deletion jobs may be requested. Distinct from the product-level deletion.self_service capability.', 1, '2026-09-25T00:00:00.000Z', '2026-09-25T00:00:00.000Z');

--------------------------------------------------------------------------------
-- Default plan (the platform tier every new organization starts on)
--------------------------------------------------------------------------------
-- `plan_key` is a stable Lumi key, not a provider product/price ID. A payment
-- provider is mapped to this plan by the billing adapter; product logic never
-- sees the provider identifier.
INSERT INTO plans (plan_id, plan_key, version, name, description, seat_based, is_active, created_at)
VALUES (
    'plan_00000000000000000000000000000001',
    'lumi-platform',
    1,
    'Lumi Platform',
    'The default self-service tier. Commercial upgrades are applied through the billing adapter.',
    0,
    1,
    '2026-09-25T00:00:00.000Z'
);

-- The default plan carries no entitlement overrides: the platform defaults in
-- `entitlement_definitions` are the whole grant set, so a downgrade or a
-- disabled plan can never be bypassed by a plan row.
