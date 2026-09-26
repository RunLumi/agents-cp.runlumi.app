// P07 storage-invariant verification.
//
// Every security property in `0016_p07_machine_identity.sql` is proven REJECTED
// by the database itself, not merely asserted in Rust. That distinction matters:
// an invariant enforced only in application code is one code path away from
// being bypassed by a migration, a script, or a future packet.
//
// The harness is deliberately dependency-free. It uses `node:sqlite`, which is
// built into the Node version this repository already requires (engines:
// >=24 <25), and applies the migrations to a throwaway file so the checks run
// against the same DDL D1 executes.
//
// TWO THINGS THIS SCRIPT EXISTS TO PREVENT, both of which I got wrong while
// probing by hand:
//
//   1. False positives. A probe that inserts a row violating an FK fails for
//      the FK, not the trigger under test, and still reports "rejected". Every
//      probe here therefore runs against a fixture known to be valid, and each
//      case declares whether it expects accept or reject.
//   2. Order dependence. Re-running probes against a dirty database makes
//      previously-passing cases fail on a PRIMARY KEY or on a column a previous
//      case already set. Every case here runs inside a SAVEPOINT that is rolled
//      back, so the suite is idempotent and order-independent.
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
const ORG = "org_0123456789abcdef0123456789abcdef";
const ORG_OTHER = "org_ffffffffffffffffffffffffffffffff";
const USER = "usr_0123456789abcdef0123456789abcdef";
const PRINCIPAL = USER;
const ACCOUNT = "svc_0123456789abcdef0123456789abcdef";
const HASH = "a".repeat(64);

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

  // One valid fixture. Every probe is layered on top of this, so a rejection
  // can only come from the constraint under test.
  seed();

  const cases = [];
  // A case may be one statement or several run in order. The terminal-state
  // invariants are about what happens *after* a revoke, so they need a sequence;
  // probing them one statement at a time reports "accepted" for a row that was
  // never revoked, which is a passing test that proves nothing.
  const expect = (label, want, sql) =>
    cases.push({ label, want, statements: Array.isArray(sql) ? sql : [sql] });
  const account = (sid, name, caps) =>
    `INSERT INTO service_accounts (service_account_id, org_id, name, capabilities_json,
       created_by_principal, status, version, created_at, updated_at)
     VALUES ('${sid}', '${ORG}', '${name}', ${caps}, '${PRINCIPAL}', 'active', 1, '${NOW}', '${NOW}')`;
  const key = (kid, prefix, name, caps) =>
    `INSERT INTO api_keys (api_key_id, service_account_id, org_id, name, key_prefix,
       secret_hash, fingerprint, capabilities_json, status, version, created_at, updated_at)
     VALUES ('${kid}', '${ACCOUNT}', '${ORG}', '${name}', '${prefix}', '${HASH}', '${HASH}',
       ${caps}, 'active', 1, '${NOW}', '${NOW}')`;

  // -- control ---------------------------------------------------------------
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
    key(id("key_", 40), "000000000001", "dup", `'["runs.read"]'`),
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
  const keyOne = id("key_", 1);
  expect(
    "revoking a key without a reason is refused",
    "rejected",
    `UPDATE api_keys SET status = 'revoked' WHERE api_key_id = '${keyOne}'`,
  );
  expect(
    "revoking a key WITH a reason is accepted",
    "accepted",
    `UPDATE api_keys SET status = 'revoked', revoke_reason = 'rotated to a new key' WHERE api_key_id = '${keyOne}'`,
  );
  const revoke = (kid) =>
    `UPDATE api_keys SET status = 'revoked', revoke_reason = 'superseded' WHERE api_key_id = '${kid}'`;
  expect("reactivating a revoked key is refused", "rejected", [
    revoke(keyOne),
    `UPDATE api_keys SET status = 'active' WHERE api_key_id = '${keyOne}'`,
  ]);
  expect("a revoked key's reason cannot be blanked afterwards", "rejected", [
    revoke(keyOne),
    `UPDATE api_keys SET revoke_reason = NULL WHERE api_key_id = '${keyOne}'`,
  ]);
  expect("rotating a key without a reason is refused", "rejected", [
    `INSERT INTO api_keys (api_key_id, service_account_id, org_id, name, key_prefix,
         secret_hash, fingerprint, capabilities_json, status, version, created_at, updated_at)
       VALUES ('${id("key_", 34)}', '${ACCOUNT}', '${ORG}', 'torotate', '000000000034',
         '${HASH}', '${HASH}', '["runs.read"]', 'active', 1, '${NOW}', '${NOW}')`,
    `UPDATE api_keys SET status = 'rotated' WHERE api_key_id = '${id("key_", 34)}'`,
  ]);
  expect("a key may still be revoked while its account is suspended", "accepted", [
    `UPDATE service_accounts SET status = 'suspended' WHERE service_account_id = '${ACCOUNT}'`,
    revoke(keyOne),
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
    VALUES ('${id("key_", 1)}', '${ACCOUNT}', '${ORG}', 'ci-deploy', '000000000001',
      '${HASH}', '${HASH}', '["runs.start"]', 'active', 1, '${NOW}', '${NOW}');
  `);
}
