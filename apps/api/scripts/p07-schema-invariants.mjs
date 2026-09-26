// P07 storage-invariant verification.
//
// Every security property in `0016`, `0017` and `0018` is proven REJECTED by the
// database itself, not merely asserted in Rust. That distinction matters: an
// invariant enforced only in application code is one code path away from being
// bypassed by a migration, a script, or a future packet.
//
// The harness is deliberately dependency-free. It uses `node:sqlite`, which is
// built into the Node version this repository already requires (engines:
// >=24 <25), and applies the migrations to a throwaway file so the checks run
// against the same DDL D1 executes.
//
// FOUR THINGS THIS SCRIPT EXISTS TO PREVENT, three of which were got wrong while
// probing by hand:
//
//   1. False positives. A probe that inserts a row violating an FK fails for the
//      FK, not the trigger under test, and still reports "rejected". Every
//      probe here therefore runs against a fixture known to be valid, and each
//      case declares whether it expects accept or reject.
//   2. Order dependence. Re-running probes against a dirty database makes
//      previously-passing cases fail on a PRIMARY KEY or on a column a previous
//      case already set. Every case here runs inside a SAVEPOINT that is rolled
//      back, so the suite is idempotent and order-independent.
//   3. Fixture ordering. The first version of the 0017/0018 cases seeded the
//      plugin and platform rows BEFORE the user and organization rows they
//      reference, and every probe failed on the FOREIGN KEY rather than on the
//      constraint under test — which is failure mode 1 wearing a new hat. The
//      seed below is one `db.exec` in dependency order for that reason.
//   4. A single-trigger miss. The terminal-state invariants are about what
//      happens *after* a revoke, so they need a sequence. Probing them one
//      statement at a time reports "accepted" for a row that was never revoked,
//      which is a passing test that proves nothing.
//
// Usage:
//   node apps/api/scripts/p07-schema-invariants.mjs
//
// Exits non-zero if any case does not behave as declared.

import { DatabaseSync } from "node:sqlite";
import { mkdtempSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const migrationsDir = fileURLToPath(new URL("../migrations/", import.meta.url));

const NOW = "2026-09-26T12:00:00.000Z";
const FUTURE = "2026-10-26T12:00:00.000Z";
const ORG = "org_0123456789abcdef0123456789abcdef";
const ORG_OTHER = "org_ffffffffffffffffffffffffffffffff";
const USER = "usr_0123456789abcdef0123456789abcdef";
const PRINCIPAL = USER;
const ACCOUNT = "svc_0123456789abcdef0123456789abcdef";
const HASH = "a".repeat(64);
const DIGEST = "b".repeat(64);
const DIGEST_TWO = "c".repeat(64);
const SIGNATURE = "s".repeat(64);

// --- 0016 machine identity -------------------------------------------------
const KEY_PREFIX = "000000000001";

// --- 0017 plugin governance ------------------------------------------------
const PUBLISHER = "pub_0123456789abcdef0123456789abcdef";
const PUBLISHER_OTHER = "pub_ffffffffffffffffffffffffffffffff";
const PACKAGE = "pkg_0123456789abcdef0123456789abcdef";
const PACKAGE_OTHER = "pkg_ffffffffffffffffffffffffffffffff";
const VERSION_ONE = "1.0.0";
const VERSION_TWO = "1.1.0";
const MANIFEST = JSON.stringify({
  tools: ["pkg_read"],
  mcp_servers: [],
  network_destinations: ["https://api.example.com"],
  filesystem_scopes: [],
  process_spawn: false,
  secret_handles: [],
  browser_capability: "none",
  external_data_handling: "none",
});
const MANIFEST_WILDCARD = MANIFEST.replace('"pkg_read"', '"*"');
const MANIFEST_INCOMPLETE = JSON.stringify({ tools: ["pkg_read"] });

// --- 0018 platform operations ----------------------------------------------
const STAFF = "stf_0123456789abcdef0123456789abcdef";
const STAFF_OTHER = "stf_ffffffffffffffffffffffffffffffff";
const GRANT = "sgr_0123456789abcdef0123456789abcdef";
const FLAG = "plugins.v2";
const SWITCH = "ksw_0123456789abcdef0123456789abcdef";
const SWITCH_OTHER = "ksw_ffffffffffffffffffffffffffffffff";

/** 32 hex characters, so `<prefix>_<32 hex>` is the frozen 36-character form. */
function id(prefix, n) {
  return prefix + String(n).padStart(32, "0");
}

const workdir = mkdtempSync(path.join(tmpdir(), "p07-invariants-"));
const dbPath = path.join(workdir, "p07.db");
const db = new DatabaseSync(dbPath);

try {
  const applied = readdirSync(migrationsDir)
    .filter((name) => name.endsWith(".sql"))
    .sort();
  for (const name of applied) {
    const sql = readFileSync(path.join(migrationsDir, name), "utf8");
    try {
      db.exec(sql);
    } catch (error) {
      console.error(`FAIL  migration ${name}: ${error.message}`);
      process.exit(1);
    }
  }
  console.log(`applied ${applied.length} migrations (last: ${applied.at(-1)})\n`);

  // One valid fixture per table, in dependency order. Every probe is layered on
  // top of this, so a rejection can only come from the constraint under test.
  seed();

  const cases = [];
  const expect = (label, want, sql) =>
    cases.push({ label, want, statements: Array.isArray(sql) ? sql : [sql] });

  // ------------------------------------------------------------- writers ----
  const account = (sid, name, caps) =>
    `INSERT INTO service_accounts (service_account_id, org_id, name, capabilities_json,
       created_by_principal, status, version, created_at, updated_at)
     VALUES ('${sid}', '${ORG}', '${name}', ${caps}, '${PRINCIPAL}', 'active', 1, '${NOW}', '${NOW}')`;
  const key = (kid, prefix, name, caps) =>
    `INSERT INTO api_keys (api_key_id, service_account_id, org_id, name, key_prefix,
       secret_hash, fingerprint, capabilities_json, status, version, created_at, updated_at)
     VALUES ('${kid}', '${ACCOUNT}', '${ORG}', '${name}', '${prefix}', '${HASH}', '${HASH}',
       ${caps}, 'active', 1, '${NOW}', '${NOW}')`;
  const publisher = (pid, name, official) =>
    `INSERT INTO plugin_publishers (publisher_id, display_name, official, status, created_at, updated_at)
     VALUES ('${pid}', '${name}', ${official}, 'active', '${NOW}', '${NOW}')`;
  const pluginPackage = (pkg, name, pub) =>
    `INSERT INTO plugin_packages (package_id, publisher_id, display_name, status, created_at, updated_at)
     VALUES ('${pkg}', '${pub}', '${name}', 'active', '${NOW}', '${NOW}')`;
  const pluginVersion = (pvr, pkg, version, digest, manifest) =>
    `INSERT INTO plugin_versions (plugin_version_id, package_id, version, runtime_min, runtime_max,
       content_digest, signature, manifest_json, published_at, created_at)
     VALUES ('${pvr}', '${pkg}', '${version}', '1.0.0', '3.0.0', '${digest}', '${SIGNATURE}',
       '${manifest}', '${NOW}', '${NOW}')`;
  const pluginPolicy = (overrides) =>
    `INSERT INTO plugin_policies (org_id, publisher_mode, approved_publishers_json,
       allowed_packages_json, blocked_packages_json, pinned_versions_json, auto_update, update_mode,
       version, created_at, updated_at)
     VALUES ('${ORG}', ${overrides.publisherMode ?? "'official_only'"},
       ${overrides.approved ?? "'[]'"}, ${overrides.allowed ?? "'[]'"},
       ${overrides.blocked ?? "'[]'"}, ${overrides.pinned ?? "'{}'"},
       ${overrides.autoUpdate ?? "'off'"}, ${overrides.updateMode ?? "'managed'"},
       ${overrides.version ?? 1}, '${NOW}', '${NOW}')`;
  const pluginInstall = (iid, pkg, version, state, reason, pending) =>
    `INSERT INTO plugin_installs (install_id, org_id, package_id, version, pending_review_version,
       review_state, review_reason, version_counter, created_at, updated_at)
     VALUES ('${iid}', '${ORG}', '${pkg}', '${version}', ${pending ?? "NULL"}, '${state}',
       ${reason ?? "NULL"}, 1, '${NOW}', '${NOW}')`;
  const registration = (rid, pkg, version, tool) =>
    `INSERT INTO plugin_tool_registrations (registration_id, org_id, package_id, version, tool_id,
       approved_by, approved_at, created_at)
     VALUES ('${rid}', '${ORG}', '${pkg}', '${version}', '${tool}', '${PRINCIPAL}', '${NOW}', '${NOW}')`;
  const quarantine = (qid, version, liftedAt) =>
    `INSERT INTO plugin_quarantines (quarantine_id, package_id, version, reason,
       engaged_by_staff_principal_id, engaged_at, lifted_at)
     VALUES ('${qid}', '${PACKAGE}', '${version}', 'CVE-2026-0001', '${STAFF}', '${NOW}', ${liftedAt ?? "NULL"})`;
  const staff = (sid, email, role, prefix, hash) =>
    `INSERT INTO staff_principals (staff_principal_id, email, display_name, staff_role, status,
       credential_prefix, credential_hash, credential_fingerprint, version, created_at, updated_at)
     VALUES ('${sid}', '${email}', 'Someone', '${role}', 'active', '${prefix}', '${hash}',
       '${prefix}', 1, '${NOW}', '${NOW}')`;
  const supportGrant = (gid, reason, expiresAt, caps) =>
    `INSERT INTO support_grants (grant_id, staff_principal_id, organization_id, reason,
       ticket_reference, capabilities_json, issued_at, expires_at, version, created_at, updated_at)
     VALUES ('${gid}', '${STAFF}', '${ORG}', ${reason}, 'TICKET-1', ${caps ?? "'[]'"},
       '${NOW}', ${expiresAt ?? `'${FUTURE}'`}, 1, '${NOW}', '${NOW}')`;
  const featureFlag = (key, enabled, percentage, allowlist, cohort, expiresAt) =>
    `INSERT INTO feature_flags (flag_key, enabled, rollout_percentage, org_allowlist_json, cohort,
       expires_at, owner_staff_principal_id, updated_by, version, created_at, updated_at)
     VALUES (${key ?? `'${FLAG}'`}, ${enabled ?? 1}, ${percentage ?? 0}, ${allowlist ?? "'[]'"},
       ${cohort ?? "'none'"}, ${expiresAt ?? `'${FUTURE}'`},
       '${STAFF}', '${STAFF}', 1, '${NOW}', '${NOW}')`;
  const killSwitch = (sid, klass, ref, scope, orgId, expiresAt, state) =>
    `INSERT INTO kill_switches (kill_switch_id, target_class, target_ref, scope, organization_id,
       reason, engaged_by_staff_principal_id, engaged_at, expires_at, state, version, created_at, updated_at)
     VALUES ('${sid}', '${klass}', '${ref}', '${scope}', ${orgId ?? "NULL"}, 'incident 42',
       '${STAFF}', '${NOW}', ${expiresAt ?? "NULL"}, ${state ?? "'engaged'"}, 1, '${NOW}', '${NOW}')`;

  // ============================ 0016 — machine identity ====================

  // Without a case that MUST succeed, every "rejected" below would be
  // indistinguishable from a broken fixture.
  expect(
    "control: a plain readable capability is accepted",
    "accepted",
    account(id("svc_", 900), "ctl", `'["runs.read"]'`),
  );
  expect(
    "control: a second key with a fresh prefix is accepted",
    "accepted",
    key(id("key_", 901), "000000000901", "ctl", `'["runs.read"]'`),
  );

  // -- FR-F14-001: no implicit owner inheritance -----------------------------
  expect(
    "wildcard capability is refused on a service account",
    "rejected",
    account(id("svc_", 1), "w1", `'["*"]'`),
  );
  expect(
    "wildcard capability is refused on a key",
    "rejected",
    key(id("key_", 2), "000000000002", "w2", `'["*"]'`),
  );
  expect(
    "duplicate service account name in one org is refused",
    "rejected",
    account(id("svc_", 3), "ci", `'["runs.read"]'`),
  );

  // -- FR-F14-007: human-only actions are structurally unavailable ------------
  for (const [n, capability] of [
    [10, "org.ownership_transfer"],
    [11, "org.lifecycle"],
    [12, "org.leave"],
    [13, "billing.manage"],
    [14, "data.delete"],
  ]) {
    expect(
      `human-only "${capability}" is refused on a service account`,
      "rejected",
      account(id("svc_", n), `h${n}`, `'["${capability}"]'`),
    );
    expect(
      `human-only "${capability}" is refused on a key`,
      "rejected",
      key(id("key_", n + 100), `000000000${n + 100}`, `h${n}`, `'["${capability}"]'`),
    );
  }

  // -- well-formed capability sets ------------------------------------------
  expect("a non-string capability is refused", "rejected", account(id("svc_", 20), "n1", `'[42]'`));
  expect(
    "a nested object capability is refused",
    "rejected",
    account(id("svc_", 21), "n2", `'[{"perm":"runs.read"}]'`),
  );
  expect(
    "a non-array capabilities value is refused",
    "rejected",
    account(id("svc_", 22), "n3", `'{"perm":"runs.read"}'`),
  );
  expect("invalid JSON is refused", "rejected", account(id("svc_", 23), "n4", `'not json'`));

  // -- FR-F14-002: the raw key is never storable -----------------------------
  expect(
    "a raw lumik_ key in secret_hash is refused",
    "rejected",
    `INSERT INTO api_keys (api_key_id, service_account_id, org_id, name, key_prefix,
       secret_hash, fingerprint, capabilities_json, status, version, created_at, updated_at)
     VALUES ('${id("key_", 30)}', '${ACCOUNT}', '${ORG}', 'raw', '000000000030',
       'lumik_000000000030_SeCrEtVaLuE', '${HASH}', '["runs.read"]', 'active', 1, '${NOW}', '${NOW}')`,
  );
  expect(
    "a short secret_hash is refused",
    "rejected",
    key(id("key_", 31), "000000000031", "short", `'["runs.read"]'`).replace(HASH, "abc"),
  );
  expect(
    "a non-hex key_prefix is refused",
    "rejected",
    key(id("key_", 32), "zzzzzzzzzzzz", "nz", `'["runs.read"]'`),
  );
  expect(
    "a non-hex fingerprint is refused",
    "rejected",
    `INSERT INTO api_keys (api_key_id, service_account_id, org_id, name, key_prefix,
       secret_hash, fingerprint, capabilities_json, status, version, created_at, updated_at)
     VALUES ('${id("key_", 33)}', '${ACCOUNT}', '${ORG}', 'nf', '000000000033',
       '${HASH}', 'not-hex-at-all', '["runs.read"]', 'active', 1, '${NOW}', '${NOW}')`,
  );

  // -- key identity ----------------------------------------------------------
  expect(
    "a duplicate key_prefix is refused",
    "rejected",
    key(id("key_", 40), KEY_PREFIX, "dup", `'["runs.read"]'`),
  );
  expect(
    "a key whose org differs from its account's org is refused",
    "rejected",
    `INSERT INTO api_keys (api_key_id, service_account_id, org_id, name, key_prefix,
       secret_hash, fingerprint, capabilities_json, status, version, created_at, updated_at)
     VALUES ('${id("key_", 41)}', '${ACCOUNT}', '${ORG_OTHER}', 'cross', '000000000041',
       '${HASH}', '${HASH}', '["runs.read"]', 'active', 1, '${NOW}', '${NOW}')`,
  );
  expect(
    "a self-referencing rotation is refused",
    "rejected",
    `INSERT INTO api_keys (api_key_id, service_account_id, org_id, name, key_prefix,
       secret_hash, fingerprint, capabilities_json, status, rotated_from_key_id,
       version, created_at, updated_at)
     VALUES ('${id("key_", 42)}', '${ACCOUNT}', '${ORG}', 'self', '000000000042',
       '${HASH}', '${HASH}', '["runs.read"]', 'active', '${id("key_", 42)}', 1, '${NOW}', '${NOW}')`,
  );

  // -- FR-F14-004: rotation and revocation are explained and terminal ---------
  expect(
    "revoking a key without a reason is refused",
    "rejected",
    `UPDATE api_keys SET status = 'revoked' WHERE api_key_id = '${id("key_", 1)}'`,
  );
  expect(
    "revoking a key WITH a reason is accepted",
    "accepted",
    `UPDATE api_keys SET status = 'revoked', revoke_reason = 'rotated to a new key' WHERE api_key_id = '${id("key_", 1)}'`,
  );
  const revoke = (kid) =>
    `UPDATE api_keys SET status = 'revoked', revoke_reason = 'superseded' WHERE api_key_id = '${kid}'`;
  expect("reactivating a revoked key is refused", "rejected", [
    revoke(id("key_", 1)),
    `UPDATE api_keys SET status = 'active' WHERE api_key_id = '${id("key_", 1)}'`,
  ]);
  expect("a revoked key's reason cannot be blanked afterwards", "rejected", [
    revoke(id("key_", 1)),
    `UPDATE api_keys SET revoke_reason = NULL WHERE api_key_id = '${id("key_", 1)}'`,
  ]);
  expect("rotating a key without a reason is refused", "rejected", [
    key(id("key_", 34), "000000000034", "torotate", `'["runs.read"]'`),
    `UPDATE api_keys SET status = 'rotated' WHERE api_key_id = '${id("key_", 34)}'`,
  ]);
  expect("a key may still be revoked while its account is suspended", "accepted", [
    `UPDATE service_accounts SET status = 'suspended' WHERE service_account_id = '${ACCOUNT}'`,
    revoke(id("key_", 1)),
  ]);

  // -- cross-tenant isolation ------------------------------------------------
  expect(
    "a service account cannot be created in an organization that does not exist",
    "rejected",
    account(id("svc_", 50), "ghost", `'["runs.read"]'`).replace(
      `'${ORG}'`,
      "'org_deadbeefdeadbeefdeadbeefdeadbeef'",
    ),
  );

  // ============================ 0017 — plugin governance ====================

  // The seed already holds one valid row of every table, so a "control" case
  // here must use a DIFFERENT identity or it fails on the primary key and proves
  // nothing about the constraint. That collision is why the first version of
  // these cases reported false failures.
  expect("control: a second valid publisher is accepted", "accepted", [
    publisher("pub_cccccccccccccccccccccccccccccccc", "Lumi Labs", 0),
  ]);
  expect("control: a second publisher name is refused", "rejected", [
    publisher("pub_dddddddddddddddddddddddddddddddd", "Lumi", 0),
  ]);

  // -- F25-001 stable identity, and an immutable published version ------------
  expect("a published version cannot be re-pointed at another package", "rejected", [
    pluginVersion(id("pvr_", 901), PACKAGE, VERSION_ONE, DIGEST, MANIFEST),
    `UPDATE plugin_versions SET package_id = '${PACKAGE_OTHER}' WHERE version = '${VERSION_ONE}'`,
  ]);
  expect("a published version's manifest cannot be edited in place", "rejected", [
    pluginVersion(id("pvr_", 902), PACKAGE, VERSION_ONE, DIGEST, MANIFEST),
    `UPDATE plugin_versions SET manifest_json = '${MANIFEST.replace('"none"', '"computer_use"')}' WHERE version = '${VERSION_ONE}'`,
  ]);
  expect("a published version's digest cannot be swapped", "rejected", [
    pluginVersion(id("pvr_", 903), PACKAGE, VERSION_ONE, DIGEST, MANIFEST),
    `UPDATE plugin_versions SET content_digest = '${DIGEST_TWO}' WHERE version = '${VERSION_ONE}'`,
  ]);
  expect("a duplicate package/version is refused", "rejected", [
    pluginVersion(id("pvr_", 904), PACKAGE, VERSION_ONE, DIGEST, MANIFEST),
    pluginVersion(id("pvr_", 905), PACKAGE, VERSION_ONE, DIGEST_TWO, MANIFEST),
  ]);
  expect("a wildcard in a manifest is refused", "rejected", [
    publisher(PUBLISHER, "Lumi", 1),
    pluginPackage(PACKAGE, "Pack Reader", PUBLISHER),
    pluginVersion(id("pvr_", 906), PACKAGE, VERSION_ONE, DIGEST, MANIFEST_WILDCARD),
  ]);
  expect("an incomplete manifest is refused", "rejected", [
    publisher(PUBLISHER, "Lumi", 1),
    pluginPackage(PACKAGE, "Pack Reader", PUBLISHER),
    pluginVersion(id("pvr_", 907), PACKAGE, VERSION_ONE, DIGEST, MANIFEST_INCOMPLETE),
  ]);

  // -- F25-004 org policy ----------------------------------------------------
  expect(
    "a wildcard package in a policy is refused",
    "rejected",
    pluginPolicy({ allowed: `'["*"]'` }),
  );
  expect("a wildcard pin is refused", "rejected", pluginPolicy({ pinned: `'{"*": "1.0.0"}'` }));
  expect(
    "a pin list rather than a pin map is refused",
    "rejected",
    pluginPolicy({ pinned: `'[]'` }),
  );
  // The gate requires the conflicting state to be STORABLE and reported, so this
  // is a control rather than a probe: a policy that lists one package on both
  // lists must persist, and the conflict is surfaced by the read path.
  expect(
    "control: an allow/block conflict is storable, because the gate reports it",
    "accepted",
    `UPDATE plugin_policies
     SET allowed_packages_json = '[\"${PACKAGE_OTHER}\"]', blocked_packages_json = '[\"${PACKAGE_OTHER}\"]'
     WHERE org_id = '${ORG}'`,
  );

  // -- F25-003 and one review state per package ------------------------------
  expect("a pending_review install without a reason is refused", "rejected", [
    pluginVersion(id("pvr_", 910), PACKAGE, VERSION_ONE, DIGEST, MANIFEST),
    pluginInstall(id("pil_", 910), PACKAGE, VERSION_ONE, "pending_review", "NULL"),
  ]);
  expect("a blocked install without a reason is refused", "rejected", [
    pluginVersion(id("pvr_", 911), PACKAGE, VERSION_ONE, DIGEST, MANIFEST),
    pluginInstall(id("pil_", 911), PACKAGE, VERSION_ONE, "approved", "NULL"),
    `UPDATE plugin_installs SET review_state = 'blocked' WHERE install_id = '${id("pil_", 911)}'`,
  ]);
  // The seeded install is the row to move: the UNIQUE `(org_id, package_id)` index
  // means there is exactly one review state per package per org, so a second row
  // is the invariant under test rather than a way to reach this one.
  expect("control: a blocked install WITH a reason is accepted", "accepted", [
    `UPDATE plugin_installs SET review_state = 'blocked', blocked_reason = 'untrusted publisher' WHERE install_id = '${id("pil_", 1)}'`,
  ]);
  expect("a second install row for one package in one org is refused", "rejected", [
    pluginVersion(id("pvr_", 913), PACKAGE, VERSION_ONE, DIGEST, MANIFEST),
    pluginVersion(id("pvr_", 914), PACKAGE, VERSION_TWO, DIGEST_TWO, MANIFEST),
    pluginInstall(id("pil_", 913), PACKAGE, VERSION_ONE, "approved"),
    pluginInstall(id("pil_", 914), PACKAGE, VERSION_TWO, "approved"),
  ]);
  expect("an install of a version nobody published is refused", "rejected", [
    publisher(PUBLISHER, "Lumi", 1),
    pluginPackage(PACKAGE, "Pack Reader", PUBLISHER),
    pluginInstall(id("pil_", 915), PACKAGE, "9.9.9", "approved"),
  ]);

  // -- F25-007 and F13 default deny ------------------------------------------
  expect("registering a tool the manifest does not declare is refused", "rejected", [
    pluginVersion(id("pvr_", 920), PACKAGE, VERSION_ONE, DIGEST, MANIFEST),
    registration(id("ptr_", 920), PACKAGE, VERSION_ONE, "not_declared"),
  ]);
  expect("control: registering a declared tool is accepted", "accepted", [
    registration(id("ptr_", 921), PACKAGE, VERSION_TWO, "pkg_read"),
  ]);
  expect("the same tool cannot be registered twice for one org", "rejected", [
    pluginVersion(id("pvr_", 922), PACKAGE, VERSION_ONE, DIGEST, MANIFEST),
    registration(id("ptr_", 922), PACKAGE, VERSION_ONE, "pkg_read"),
    registration(id("ptr_", 923), PACKAGE, VERSION_ONE, "pkg_read"),
  ]);

  // -- F25-008 quarantine ----------------------------------------------------
  expect("a quarantine cannot be deleted", "rejected", [
    pluginVersion(id("pvr_", 930), PACKAGE, VERSION_ONE, DIGEST, MANIFEST),
    quarantine(id("pqr_", 930), VERSION_ONE),
    `DELETE FROM plugin_quarantines WHERE quarantine_id = '${id("pqr_", 930)}'`,
  ]);
  expect("two active quarantines for one version are refused", "rejected", [
    pluginVersion(id("pvr_", 931), PACKAGE, VERSION_ONE, DIGEST, MANIFEST),
    quarantine(id("pqr_", 931), VERSION_ONE),
    quarantine(id("pqr_", 932), VERSION_ONE),
  ]);
  expect("lifting a quarantine without a reason is refused", "rejected", [
    pluginVersion(id("pvr_", 933), PACKAGE, VERSION_ONE, DIGEST, MANIFEST),
    quarantine(id("pqr_", 933), VERSION_ONE),
    `UPDATE plugin_quarantines SET lifted_at = '${NOW}' WHERE quarantine_id = '${id("pqr_", 933)}'`,
  ]);
  expect("a lifted quarantine cannot be re-engaged in place", "rejected", [
    pluginVersion(id("pvr_", 934), PACKAGE, VERSION_ONE, DIGEST, MANIFEST),
    quarantine(id("pqr_", 934), VERSION_ONE, `'${NOW}'`),
    `UPDATE plugin_quarantines SET lifted_at = NULL WHERE quarantine_id = '${id("pqr_", 934)}'`,
  ]);
  expect("a version may be quarantined again after the first was lifted", "accepted", [
    quarantine(id("pqr_", 935), VERSION_TWO, `'${NOW}'`),
    quarantine(id("pqr_", 936), VERSION_TWO),
  ]);
  expect("a lift WITH a reason is accepted", "accepted", [
    quarantine(id("pqr_", 937), VERSION_TWO),
    `UPDATE plugin_quarantines SET lifted_at = '${NOW}', lift_reason = 'fixed upstream' WHERE quarantine_id = '${id("pqr_", 937)}'`,
  ]);

  // ======================== 0018 — platform operations ======================

  expect(
    "control: a valid staff principal is accepted",
    "accepted",
    staff(
      "stf_eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
      "a@internal.example",
      "support",
      "eeeeeeeeeeeeeeee",
      HASH,
    ),
  );
  expect(
    "control: a valid support grant is accepted",
    "accepted",
    supportGrant("sgr_eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", "'looking into a report'"),
  );

  // -- F24-001 a named identity, not a shared account ------------------------
  expect("two staff principals cannot share a credential prefix", "rejected", [
    staff(
      "stf_eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
      "a@internal.example",
      "support",
      "0123456789abcdef",
      HASH,
    ),
    staff(STAFF_OTHER, "b@internal.example", "security", "0123456789abcdef", HASH),
  ]);
  expect("two staff principals cannot share an email", "rejected", [
    staff(
      "stf_eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
      "a@internal.example",
      "support",
      "0123456789abcdef",
      HASH,
    ),
    staff(STAFF_OTHER, "a@internal.example", "security", "ffffffffffffffff", HASH),
  ]);
  expect(
    "a staff credential hash must be 64 lowercase hex",
    "rejected",
    staff(STAFF_OTHER, "c@internal.example", "support", "ffffffffffffffff", "not-a-hash"),
  );
  expect(
    "an unknown staff role is refused",
    "rejected",
    staff(STAFF_OTHER, "d@internal.example", "superuser", "ffffffffffffffff", HASH),
  );
  expect(
    "a staff principal for an organization that does not exist is impossible",
    "rejected",
    `UPDATE support_grants SET organization_id = 'org_deadbeefdeadbeefdeadbeefdeadbeef' WHERE grant_id = '${GRANT}'`,
  );

  // -- F24-003 and F24-008 support grants ------------------------------------
  expect(
    "a grant with no reason is refused",
    "rejected",
    supportGrant("sgr_eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", "''"),
  );
  // The column CHECK is `length(reason) BETWEEN 1 AND 500`, so a whitespace-only
  // reason IS storable. That is the correct layering rather than a gap: the
  // schema owns "not empty" and `staff::validate_grant_input` owns "not blank",
  // and the Rust test `a_grant_needs_a_reason_a_ticket_and_a_bounded_ttl` pins
  // the trim. Asserting a rejection here would claim a guarantee the database
  // does not make, which is the failure mode this harness exists to prevent.
  expect(
    "control: a whitespace-only grant reason is storable; the domain layer trims it",
    "accepted",
    supportGrant("sgr_eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", "'   '"),
  );
  expect(
    "a grant that expires before it was issued is refused",
    "rejected",
    supportGrant(
      "sgr_eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
      "'looking into a report'",
      "'2026-09-01T00:00:00.000Z'",
    ),
  );
  expect(
    "a grant with no expiry is refused",
    "rejected",
    supportGrant("sgr_eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", "'looking into a report'", "NULL"),
  );
  expect(
    "a grant capability wildcard is refused",
    "rejected",
    supportGrant(
      "sgr_eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
      "'looking into a report'",
      null,
      `'["*"]'`,
    ),
  );
  expect(
    "a non-string grant capability is refused",
    "rejected",
    supportGrant("sgr_eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", "'looking into a report'", null, `'[42]'`),
  );
  expect("revoking a grant without a reason is refused", "rejected", [
    `UPDATE support_grants SET revoked_at = '${NOW}' WHERE grant_id = '${GRANT}'`,
  ]);
  expect("a revoked grant's reason cannot be blanked afterwards", "rejected", [
    `UPDATE support_grants SET revoked_at = '${NOW}', revoke_reason = 'done' WHERE grant_id = '${GRANT}'`,
    `UPDATE support_grants SET revoke_reason = NULL WHERE grant_id = '${GRANT}'`,
  ]);
  expect("a revoked grant cannot be restored in place", "rejected", [
    `UPDATE support_grants SET revoked_at = '${NOW}', revoke_reason = 'done' WHERE grant_id = '${GRANT}'`,
    `UPDATE support_grants SET revoked_at = NULL WHERE grant_id = '${GRANT}'`,
  ]);

  // -- F24-006 feature flags -------------------------------------------------
  expect(
    "a flag with no expiry is refused",
    "rejected",
    featureFlag("'no.expiry'", 1, 0, "'[]'", "'none'", "NULL"),
  );
  expect(
    "a flag with a negative percentage is refused",
    "rejected",
    featureFlag("'neg.pct'", 1, -1),
  );
  expect(
    "a flag with a percentage over 100 is refused",
    "rejected",
    featureFlag("'big.pct'", 1, 101),
  );
  expect(
    "a wildcard org allowlist is refused",
    "rejected",
    featureFlag("'wild.flag'", 1, 0, `'["*"]'`),
  );
  expect(
    "a flag combining an org allowlist with a partial rollout is refused",
    "rejected",
    featureFlag("'ambiguous.flag'", 1, 30, `'["${ORG}"]'`),
  );
  expect(
    "control: an allowlist with a FULL rollout is accepted",
    "accepted",
    featureFlag("'both.flag'", 1, 100, `'["${ORG}"]'`),
  );
  expect(
    "an unknown cohort is refused",
    "rejected",
    featureFlag("'bad.cohort'", 1, 0, "'[]'", "'vibes'"),
  );

  // -- F24-007 kill switches -------------------------------------------------
  expect(
    "control: a valid global kill switch is accepted",
    "accepted",
    killSwitch(
      "ksw_eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
      "plugin_version",
      `${PACKAGE}@${VERSION_ONE}`,
      "global",
    ),
  );
  expect(
    "control: a valid organization-scoped kill switch is accepted",
    "accepted",
    killSwitch(
      "ksw_dddddddddddddddddddddddddddddddd",
      "model_route",
      "rte_1",
      "organization",
      `'${ORG}'`,
    ),
  );
  expect(
    "an organization-scoped switch with no organization is refused",
    "rejected",
    killSwitch(
      "ksw_eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
      "model_route",
      "rte_1",
      "organization",
      "NULL",
    ),
  );
  expect(
    "a global switch carrying an organization is refused",
    "rejected",
    killSwitch(
      "ksw_eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
      "model_route",
      "rte_1",
      "global",
      `'${ORG}'`,
    ),
  );
  expect(
    "an unknown target class is refused",
    "rejected",
    killSwitch("ksw_eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", "everything", "rte_1", "global"),
  );
  expect(
    "a switch born already expired is refused",
    "rejected",
    killSwitch(
      "ksw_eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
      "model_route",
      "rte_1",
      "global",
      "NULL",
      "'2026-09-01T00:00:00.000Z'",
    ),
  );
  expect("lifting a switch without a reason is refused", "rejected", [
    `UPDATE kill_switches SET state = 'lifted' WHERE kill_switch_id = '${SWITCH}'`,
  ]);
  expect("a lifted switch cannot be re-engaged in place", "rejected", [
    `UPDATE kill_switches SET state = 'lifted', lift_reason = 'resolved' WHERE kill_switch_id = '${SWITCH}'`,
    `UPDATE kill_switches SET state = 'engaged' WHERE kill_switch_id = '${SWITCH}'`,
  ]);
  expect("control: lifting a switch WITH a reason is accepted", "accepted", [
    `UPDATE kill_switches SET state = 'lifted', lift_reason = 'resolved' WHERE kill_switch_id = '${SWITCH}'`,
  ]);

  // --------------------------------------------------------------- runner ----
  let passed = 0;
  const failures = [];
  for (const testCase of cases) {
    db.exec("SAVEPOINT probe");
    let actual = "accepted";
    let detail = "";
    try {
      for (const statement of testCase.statements) {
        db.prepare(statement).run();
      }
    } catch (error) {
      actual = "rejected";
      detail = error.message;
    }
    db.exec("ROLLBACK TO probe");
    db.exec("RELEASE probe");
    if (actual === testCase.want) {
      passed += 1;
      console.log(`  PASS  ${testCase.label}`);
    } else {
      failures.push(testCase.label);
      console.log(`  FAIL  ${testCase.label}`);
      console.log(`        wanted ${testCase.want}, got ${actual}${detail ? ` (${detail})` : ""}`);
    }
  }

  console.log(`\n${passed}/${cases.length} invariants behave as declared`);
  if (failures.length > 0) {
    console.error(`\n${failures.length} case(s) failed:`);
    for (const label of failures) console.error(`  - ${label}`);
    process.exitCode = 1;
  }
} finally {
  db.close();
  rmSync(workdir, { recursive: true, force: true });
}

function seed() {
  // ONE exec, in dependency order. The plugin and platform rows reference the
  // user and the organization, and SQLite resolves foreign keys immediately, so
  // a second exec seeded first fails every probe for the wrong reason.
  db.exec(`
    INSERT INTO users (user_id, email, display_name, email_verified, version, created_at, updated_at)
    VALUES ('${USER}', 'owner@example.com', 'Owner', 1, 1, '${NOW}', '${NOW}');
    INSERT INTO organizations (org_id, display_name, slug, state, version, created_by_user_id, created_at, updated_at)
    VALUES ('${ORG}', 'Acme', 'acme', 'active', 1, '${USER}', '${NOW}', '${NOW}');
    INSERT INTO service_accounts (service_account_id, org_id, name, capabilities_json,
      created_by_principal, status, version, created_at, updated_at)
    VALUES ('${ACCOUNT}', '${ORG}', 'ci', '["runs.start","runs.read"]', '${PRINCIPAL}', 'active', 1, '${NOW}', '${NOW}');
    INSERT INTO api_keys (api_key_id, service_account_id, org_id, name, key_prefix,
      secret_hash, fingerprint, capabilities_json, status, version, created_at, updated_at)
    VALUES ('${id("key_", 1)}', '${ACCOUNT}', '${ORG}', 'ci-deploy', '${KEY_PREFIX}',
      '${HASH}', '${HASH}', '["runs.start"]', 'active', 1, '${NOW}', '${NOW}');

    INSERT INTO plugin_publishers (publisher_id, display_name, official, status, created_at, updated_at)
    VALUES ('${PUBLISHER}', 'Lumi', 1, 'active', '${NOW}', '${NOW}'),
           ('${PUBLISHER_OTHER}', 'Community', 0, 'active', '${NOW}', '${NOW}');
    INSERT INTO plugin_packages (package_id, publisher_id, display_name, status, created_at, updated_at)
    VALUES ('${PACKAGE}', '${PUBLISHER}', 'Pack Reader', 'active', '${NOW}', '${NOW}'),
           ('${PACKAGE_OTHER}', '${PUBLISHER_OTHER}', 'Other Pack', 'active', '${NOW}', '${NOW}');
    INSERT INTO plugin_versions (plugin_version_id, package_id, version, runtime_min, runtime_max,
      content_digest, signature, manifest_json, published_at, created_at)
    VALUES ('${id("pvr_", 1)}', '${PACKAGE}', '${VERSION_ONE}', '1.0.0', '3.0.0',
      '${DIGEST}', '${SIGNATURE}', '${MANIFEST}', '${NOW}', '${NOW}'),
      ('${id("pvr_", 2)}', '${PACKAGE}', '${VERSION_TWO}', '1.0.0', '3.0.0',
      '${DIGEST_TWO}', '${SIGNATURE}', '${MANIFEST}', '${NOW}', '${NOW}');
    INSERT INTO plugin_policies (org_id, publisher_mode, approved_publishers_json, allowed_packages_json,
      blocked_packages_json, pinned_versions_json, auto_update, update_mode, version, created_at, updated_at)
    VALUES ('${ORG}', 'official_only', '[]', '[]', '[]', '{}', 'off', 'managed', 1, '${NOW}', '${NOW}');
    INSERT INTO plugin_installs (install_id, org_id, package_id, version, review_state,
      version_counter, created_at, updated_at)
    VALUES ('${id("pil_", 1)}', '${ORG}', '${PACKAGE}', '${VERSION_ONE}', 'approved', 1, '${NOW}', '${NOW}');

    INSERT INTO staff_principals (staff_principal_id, email, display_name, staff_role, status,
      credential_prefix, credential_hash, credential_fingerprint, version, created_at, updated_at)
    VALUES ('${STAFF}', 'support@internal.example', 'Support', 'support', 'active',
      '0123456789abcdef', '${HASH}', '0123456789abcdef', 1, '${NOW}', '${NOW}');
    INSERT INTO support_grants (grant_id, staff_principal_id, organization_id, reason, ticket_reference,
      capabilities_json, issued_at, expires_at, version, created_at, updated_at)
    VALUES ('${GRANT}', '${STAFF}', '${ORG}', 'looking into a report', 'TICKET-1',
      '["org.lookup"]', '${NOW}', '${FUTURE}', 1, '${NOW}', '${NOW}');
    INSERT INTO feature_flags (flag_key, enabled, rollout_percentage, org_allowlist_json, cohort,
      expires_at, owner_staff_principal_id, updated_by, version, created_at, updated_at)
    VALUES ('${FLAG}', 1, 25, '[]', 'none', '${FUTURE}', '${STAFF}', '${STAFF}', 1, '${NOW}', '${NOW}');
    INSERT INTO kill_switches (kill_switch_id, target_class, target_ref, scope, organization_id, reason,
      engaged_by_staff_principal_id, engaged_at, state, version, created_at, updated_at)
    VALUES ('${SWITCH}', 'plugin_version', '${PACKAGE}@${VERSION_ONE}', 'global', NULL, 'incident 42',
      '${STAFF}', '${NOW}', 'engaged', 1, '${NOW}', '${NOW}');
  `);
}
