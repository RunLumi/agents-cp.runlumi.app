import { spawn } from "node:child_process";
import { setTimeout as delay } from "node:timers/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const apiDir = path.resolve(scriptDir, "..");
const repoRoot = path.resolve(apiDir, "../..");
const webDir = path.join(repoRoot, "apps/web");
const wranglerBin = path.join(apiDir, "node_modules/.bin/wrangler");
const viteBin = path.join(webDir, "node_modules/.bin/vite");
const apiUrl = "http://127.0.0.1:8787";
const webUrl = "http://127.0.0.1:5173";
const productionApiUrl = "http://127.0.0.1:8788";
const foundationChecksPath = "/api/v1/_internal/foundation-checks";
const services = [];

function start(executable, args, cwd, label) {
  const child = spawn(executable, args, {
    cwd,
    env: process.env,
    stdio: ["ignore", "pipe", "pipe"],
    detached: process.platform !== "win32",
  });
  let output = "";
  const capture = (chunk) => {
    output = `${output}${chunk.toString()}`.slice(-12_000);
  };
  child.stdout.on("data", capture);
  child.stderr.on("data", capture);
  child.on("error", (error) => {
    output = `${output}\n${error.message}`.slice(-12_000);
  });
  services.push({
    child,
    label,
    get output() {
      return output;
    },
  });
  return child;
}

async function run(executable, args, cwd, label) {
  const child = spawn(executable, args, {
    cwd,
    env: process.env,
    stdio: ["ignore", "pipe", "pipe"],
  });
  let output = "";
  child.stdout.on("data", (chunk) => {
    output += chunk.toString();
  });
  child.stderr.on("data", (chunk) => {
    output += chunk.toString();
  });
  const exitCode = await new Promise((resolve, reject) => {
    child.once("error", reject);
    child.once("close", resolve);
  });
  if (exitCode !== 0) {
    throw new Error(`${label} failed (${exitCode}).\n${output.slice(-12_000)}`);
  }
  return output;
}

async function runD1Json(sql, label) {
  const output = await run(
    wranglerBin,
    ["d1", "execute", "DB", "--local", "--env", "development", "--json", "--command", sql],
    apiDir,
    label,
  );
  try {
    return JSON.parse(output);
  } catch {
    throw new Error(`${label} returned an invalid Wrangler JSON result.`);
  }
}

async function verifyIdempotencyScopeIsolation() {
  const suffix = crypto.randomUUID().replaceAll("-", "");
  const principalA = `smoke-a-${suffix}`;
  const principalB = `smoke-b-${suffix}`;
  const organizationA = `org-smoke-a-${suffix}`;
  const organizationB = `org-smoke-b-${suffix}`;
  const keyDigest = `sha256:${suffix}`;
  const fingerprint = `sha256:${suffix}`;
  const expiresAt = new Date(Date.now() + 86_400_000).toISOString();
  const claimToken = `smoke-${suffix}`;
  const method = "POST";
  const endpoint = "/api/v1/_internal/foundation-checks";
  const quote = (value) => `'${value.replaceAll("'", "''")}'`;
  const row = (principal, organization) =>
    `(${quote(principal)}, ${quote(organization)}, ${quote(method)}, ${quote(endpoint)}, ${quote(keyDigest)}, ${quote(fingerprint)}, 'pending', NULL, NULL, ${quote(expiresAt)}, ${quote(claimToken)})`;
  const insertColumns =
    "principal_id, organization_id, method, path, key_digest, request_fingerprint, state, response_status, response_body, expires_at, claim_token";
  const insert = `INSERT INTO idempotency_records (${insertColumns}) VALUES ${row(principalA, organizationA)}, ${row(principalA, organizationB)}, ${row(principalB, organizationA)};`;
  const ignoreDuplicate = `INSERT OR IGNORE INTO idempotency_records (${insertColumns}) VALUES ${row(principalA, organizationA)};`;
  const count = `SELECT COUNT(*) AS scope_count FROM idempotency_records WHERE (principal_id = ${quote(principalA)} OR principal_id = ${quote(principalB)}) AND key_digest = ${quote(keyDigest)};`;
  const cleanup = `DELETE FROM idempotency_records WHERE principal_id IN (${quote(principalA)}, ${quote(principalB)}) AND key_digest = ${quote(keyDigest)};`;

  try {
    const statements = await runD1Json(
      `${insert} ${ignoreDuplicate} ${count}`,
      "Local D1 idempotency-scope verification",
    );
    if (
      statements.length !== 3 ||
      statements[0]?.success !== true ||
      statements[1]?.success !== true ||
      statements[2]?.results?.[0]?.scope_count !== 3
    ) {
      const summary = JSON.stringify(
        statements.map((statement) => ({
          success: statement?.success,
          changes: statement?.meta?.changes,
          results: statement?.results,
        })),
      );
      throw new Error(
        `D1 did not preserve principal/organization idempotency scope uniqueness: ${summary}`,
      );
    }
  } finally {
    await runD1Json(cleanup, "Local D1 smoke-fixture cleanup");
  }
}

async function verifyStaleClaimRollback() {
  const suffix = crypto.randomUUID().replaceAll("-", "");
  const principal = `smoke-rollback-${suffix}`;
  const organization = `org-smoke-rollback-${suffix}`;
  const keyDigest = `sha256:${suffix}`;
  const fingerprint = `sha256:${suffix}`;
  const claimToken = `current-${suffix}`;
  const staleToken = `stale-${suffix}`;
  const expiresAt = new Date(Date.now() + 86_400_000).toISOString();
  const occurredAt = new Date().toISOString();
  const eventId = `evt_${suffix}`;
  const requestId = `req_${suffix}`;
  const quote = (value) => `'${value.replaceAll("'", "''")}'`;
  const setup = `INSERT INTO idempotency_records (principal_id, organization_id, method, path, key_digest, request_fingerprint, state, response_status, response_body, expires_at, claim_token) VALUES (${quote(principal)}, ${quote(organization)}, 'POST', '/api/v1/smoke', ${quote(keyDigest)}, ${quote(fingerprint)}, 'pending', NULL, NULL, ${quote(expiresAt)}, ${quote(claimToken)});`;
  const guard = `INSERT INTO idempotency_records (principal_id, organization_id, method, path, key_digest, request_fingerprint, state, response_status, response_body, expires_at, claim_token) SELECT NULL, '', '', '', '', '', 'pending', NULL, NULL, '', '' WHERE NOT EXISTS (SELECT 1 FROM idempotency_records WHERE principal_id = ${quote(principal)} AND organization_id = ${quote(organization)} AND method = 'POST' AND path = '/api/v1/smoke' AND key_digest = ${quote(keyDigest)} AND request_fingerprint = ${quote(fingerprint)} AND state = 'pending' AND claim_token = ${quote(staleToken)});`;
  const eventEnvelope = JSON.stringify({
    event_id: eventId,
    event_type: "foundation.check.requested.v1",
    occurred_at: occurredAt,
    request_id: requestId,
    correlation_id: requestId,
    actor: { type: "anonymous", id: null, effective_user_id: null },
    organization_id: null,
    payload: {},
  });
  const businessOutboxInsert = `INSERT INTO outbox_events (event_id, event_type, occurred_at, request_id, correlation_id, organization_id, envelope_json, delivery_status, attempt_count, next_attempt_at) VALUES (${quote(eventId)}, 'foundation.check.requested.v1', ${quote(occurredAt)}, ${quote(requestId)}, ${quote(requestId)}, '', ${quote(eventEnvelope)}, 'pending', 0, ${quote(occurredAt)});`;
  const verify = `SELECT (SELECT COUNT(*) FROM outbox_events WHERE event_id = ${quote(eventId)}) AS outbox_count, (SELECT COUNT(*) FROM idempotency_records WHERE principal_id = ${quote(principal)} AND claim_token = ${quote(claimToken)}) AS claim_count;`;
  const cleanup = `DELETE FROM idempotency_records WHERE principal_id = ${quote(principal)} AND key_digest = ${quote(keyDigest)}; DELETE FROM outbox_events WHERE event_id = ${quote(eventId)};`;

  try {
    await runD1Json(setup, "Local D1 stale-claim setup");
    let failure = "";
    try {
      await runD1Json(`${guard} ${businessOutboxInsert}`, "Local D1 stale-claim transaction probe");
    } catch (error) {
      failure = error instanceof Error ? error.message : String(error);
    }
    if (!/NOT NULL constraint failed: idempotency_records\.principal_id/i.test(failure)) {
      throw new Error("The stale-claim probe did not fail at its transaction guard.");
    }
    const results = await runD1Json(verify, "Local D1 stale-claim rollback verification");
    if (
      results[0]?.results?.[0]?.outbox_count !== 0 ||
      results[0]?.results?.[0]?.claim_count !== 1
    ) {
      throw new Error(
        "The D1 batch committed business/outbox data after a stale-claim guard failure.",
      );
    }
  } finally {
    await runD1Json(cleanup, "Local D1 transaction-fixture cleanup");
  }
}

async function sha256Digest(value) {
  const digest = new Uint8Array(
    await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value)),
  );
  return `sha256:${Array.from(digest, (byte) => byte.toString(16).padStart(2, "0")).join("")}`;
}

async function prepareIdempotencyExpiryFixture() {
  const suffix = crypto.randomUUID().replaceAll("-", "");
  const principal = "anonymous-local";
  const expiredKey = `p01-expired-${suffix}`;
  const activeKey = `p01-active-${suffix}`;
  const expiredDigest = await sha256Digest(expiredKey);
  const activeDigest = await sha256Digest(activeKey);
  const fingerprint = await sha256Digest(`POST\n${foundationChecksPath}\n{}`);
  const expiredEventId = `evt_${suffix}`;
  const activeClaimToken = `active-${suffix}`;
  const quote = (value) => `'${value.replaceAll("'", "''")}'`;
  const columns =
    "principal_id, organization_id, method, path, key_digest, request_fingerprint, state, response_status, response_body, expires_at, claim_token";
  const expiredRow = `(${quote(principal)}, '', 'POST', ${quote(foundationChecksPath)}, ${quote(expiredDigest)}, ${quote(fingerprint)}, 'completed', 202, ${quote(JSON.stringify({ event_id: expiredEventId, delivery_status: "delivered" }))}, '2000-01-01T00:00:00.000Z', NULL)`;
  const activeRow = `(${quote(principal)}, '', 'POST', ${quote(foundationChecksPath)}, ${quote(activeDigest)}, ${quote(fingerprint)}, 'pending', NULL, NULL, '2099-01-01T00:00:00.000Z', ${quote(activeClaimToken)})`;
  const setup = `INSERT INTO idempotency_records (${columns}) VALUES ${expiredRow}, ${activeRow};`;

  await runD1Json(setup, "Local D1 idempotency-expiry fixture setup");
  return {
    principal,
    expiredKey,
    activeKey,
    expiredDigest,
    activeDigest,
    fingerprint,
    expiredEventId,
    activeClaimToken,
    cleanupFor: (eventId) =>
      `DELETE FROM idempotency_records WHERE principal_id = ${quote(principal)} AND key_digest IN (${quote(expiredDigest)}, ${quote(activeDigest)}); DELETE FROM outbox_events WHERE event_id = ${quote(eventId)};`,
  };
}

async function waitForDelivered(baseUrl, eventId, timeoutMs = 20_000) {
  const statusUrl = `${baseUrl}${foundationChecksPath}/${encodeURIComponent(eventId)}`;
  const deadline = Date.now() + timeoutMs;
  let deliveryStatus = "pending";
  while (deliveryStatus !== "delivered" && Date.now() < deadline) {
    await delay(250);
    const status = await requestJson(statusUrl);
    if (!status.response.ok || status.body.event_id !== eventId) {
      throw new Error("The local D1 status endpoint did not return the created event.");
    }
    deliveryStatus = status.body.delivery_status;
  }
  if (deliveryStatus !== "delivered") {
    throw new Error(
      `The local outbox consumer did not persist delivery; state is ${deliveryStatus}.`,
    );
  }
}

async function verifyIdempotencyExpiryBehavior(fixture) {
  const create = (key) =>
    requestJson(`${webUrl}${foundationChecksPath}`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "Idempotency-Key": key },
      body: "{}",
    });
  let reclaimedEventId;
  let delivered = false;

  try {
    const reclaimed = await create(fixture.expiredKey);
    if (
      reclaimed.response.status !== 202 ||
      typeof reclaimed.body.event_id !== "string" ||
      reclaimed.body.event_id === fixture.expiredEventId
    ) {
      throw new Error("An expired idempotency record was replayed instead of being reclaimed.");
    }
    reclaimedEventId = reclaimed.body.event_id;

    const active = await create(fixture.activeKey);
    if (active.response.status !== 409 || active.body?.error?.code !== "idempotency_in_progress") {
      throw new Error("An active pending idempotency claim was overwritten or misclassified.");
    }

    const persisted = await runD1Json(
      `SELECT (SELECT state FROM idempotency_records WHERE principal_id = '${fixture.principal}' AND key_digest = '${fixture.expiredDigest}') AS expired_state, (SELECT json_extract(response_body, '$.event_id') FROM idempotency_records WHERE principal_id = '${fixture.principal}' AND key_digest = '${fixture.expiredDigest}') AS reclaimed_event_id, (SELECT request_fingerprint FROM idempotency_records WHERE principal_id = '${fixture.principal}' AND key_digest = '${fixture.activeDigest}') AS active_fingerprint, (SELECT claim_token FROM idempotency_records WHERE principal_id = '${fixture.principal}' AND key_digest = '${fixture.activeDigest}') AS active_claim_token;`,
      "Local D1 idempotency-expiry verification",
    );
    const row = persisted[0]?.results?.[0];
    if (
      row?.expired_state !== "completed" ||
      row?.reclaimed_event_id !== reclaimedEventId ||
      row?.active_fingerprint !== fixture.fingerprint ||
      row?.active_claim_token !== fixture.activeClaimToken
    ) {
      throw new Error("Reclaiming an expired key changed the wrong idempotency scope.");
    }

    await waitForDelivered(webUrl, reclaimedEventId);
    delivered = true;
  } finally {
    if (delivered && reclaimedEventId) {
      await runD1Json(
        fixture.cleanupFor(reclaimedEventId),
        "Local D1 idempotency-expiry fixture cleanup",
      );
    }
  }
}

async function waitForHealth(baseUrl, child, timeoutMs = 180_000) {
  const deadline = Date.now() + timeoutMs;
  let lastError = "no response";
  while (Date.now() < deadline) {
    if (child.exitCode !== null) {
      const service = services.find((entry) => entry.child === child);
      throw new Error(`Worker exited during startup.\n${service?.output ?? ""}`);
    }
    try {
      const response = await fetch(`${baseUrl}/api/health`, { signal: AbortSignal.timeout(2_000) });
      if (response.ok) return response;
      lastError = `health status ${response.status}`;
    } catch (error) {
      lastError = error instanceof Error ? error.message : "unknown connection error";
    }
    await delay(250);
  }
  throw new Error(`Local web-to-Worker health did not become ready: ${lastError}`);
}

async function requestJson(url, init) {
  const response = await fetch(url, init);
  let body;
  try {
    body = await response.json();
  } catch {
    throw new Error(`Expected JSON from ${url}; received HTTP ${response.status}`);
  }
  return { response, body };
}

async function stop(service) {
  const { child } = service;
  if (child.exitCode !== null || child.signalCode !== null) return;
  try {
    if (process.platform === "win32") child.kill("SIGTERM");
    else process.kill(-child.pid, "SIGTERM");
  } catch {
    child.kill("SIGTERM");
  }
  await Promise.race([new Promise((resolve) => child.once("close", resolve)), delay(3_000)]);
  if (child.exitCode === null && child.signalCode === null) {
    try {
      if (process.platform === "win32") child.kill("SIGKILL");
      else process.kill(-child.pid, "SIGKILL");
    } catch {
      child.kill("SIGKILL");
    }
  }
}

try {
  await run(
    wranglerBin,
    ["d1", "migrations", "apply", "DB", "--local", "--env", "development"],
    apiDir,
    "Local D1 migration",
  );
  await verifyIdempotencyScopeIsolation();
  await verifyStaleClaimRollback();

  const worker = start(
    wranglerBin,
    ["dev", "--env", "development", "--local", "--port", "8787"],
    apiDir,
    "Worker",
  );
  await waitForHealth(apiUrl, worker);

  const productionWorker = start(
    wranglerBin,
    ["dev", "--env", "production", "--local", "--port", "8788"],
    apiDir,
    "Production-config Worker",
  );
  await waitForHealth(productionApiUrl, productionWorker);

  start(viteBin, ["--host", "127.0.0.1", "--port", "5173", "--strictPort"], webDir, "Web");

  const health = await waitForHealth(webUrl, worker, 20_000);
  const requestId = health.headers.get("X-Request-ID");
  if (!requestId?.startsWith("req_") || requestId.length > 160) {
    throw new Error("Health response did not carry the frozen X-Request-ID.");
  }

  const { response: metaResponse, body: meta } = await requestJson(`${webUrl}/api/v1/meta`);
  if (!metaResponse.ok || meta.api_version !== "v1" || meta.contract_version !== "p01-cg-v1") {
    throw new Error("The web proxy returned unexpected API metadata.");
  }

  const productionProbe = await requestJson(
    `${productionApiUrl}/api/v1/_internal/foundation-checks`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json", "Idempotency-Key": "production-route-check" },
      body: "{}",
    },
  );
  if (
    productionProbe.response.status !== 404 ||
    productionProbe.body?.error?.code !== "not_found"
  ) {
    throw new Error("The development-only foundation route was registered in production.");
  }

  const idempotencyKey = `p01-smoke-${crypto.randomUUID()}`;
  const createUrl = `${webUrl}/api/v1/_internal/foundation-checks`;
  const create = () =>
    requestJson(createUrl, {
      method: "POST",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json",
        "Idempotency-Key": idempotencyKey,
      },
      body: "{}",
    });

  const first = await create();
  if (
    first.response.status !== 202 ||
    typeof first.body.event_id !== "string" ||
    first.body.delivery_status !== "pending"
  ) {
    throw new Error("Foundation mutation did not return the frozen accepted response.");
  }
  const firstRequestId = first.response.headers.get("X-Request-ID");
  if (!firstRequestId?.startsWith("req_")) {
    throw new Error("Foundation mutation did not carry a request ID.");
  }
  if (!/^evt_[a-f0-9]{32}$/.test(first.body.event_id)) {
    throw new Error("Foundation mutation returned an invalid opaque event ID.");
  }

  const persistedContext = await runD1Json(
    `SELECT json_extract(envelope_json, '$.request_id') AS request_id, correlation_id FROM outbox_events WHERE event_id = '${first.body.event_id}';`,
    "Local D1 request-correlation propagation verification",
  );
  if (
    persistedContext[0]?.results?.[0]?.request_id !== firstRequestId ||
    persistedContext[0]?.results?.[0]?.correlation_id !== firstRequestId
  ) {
    throw new Error(
      "The HTTP request/correlation ID did not propagate through the D1 outbox envelope.",
    );
  }

  const replay = await create();
  if (
    replay.response.status !== 202 ||
    replay.body.event_id !== first.body.event_id ||
    replay.response.headers.get("X-Request-ID") === firstRequestId
  ) {
    throw new Error(
      "Duplicate idempotency request did not replay one mutation with a fresh request ID.",
    );
  }

  const persistedCount = await runD1Json(
    `SELECT COUNT(*) AS event_count FROM outbox_events WHERE event_id = '${first.body.event_id}';`,
    "Local D1 outbox deduplication verification",
  );
  if (persistedCount[0]?.results?.[0]?.event_count !== 1) {
    throw new Error("The duplicate request created more than one persisted outbox event.");
  }

  const conflict = await requestJson(createUrl, {
    method: "POST",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/json",
      "Idempotency-Key": idempotencyKey,
    },
    body: JSON.stringify({ changed: true }),
  });
  if (conflict.response.status !== 409 || conflict.body?.error?.code !== "idempotency_conflict") {
    throw new Error("Reusing an idempotency key with a different body did not conflict.");
  }

  let deliveryStatus = first.body.delivery_status;
  const statusUrl = `${webUrl}/api/v1/_internal/foundation-checks/${encodeURIComponent(first.body.event_id)}`;
  const deliveryDeadline = Date.now() + 20_000;
  while (deliveryStatus !== "delivered" && Date.now() < deliveryDeadline) {
    await delay(250);
    const status = await requestJson(statusUrl);
    if (!status.response.ok || status.body.event_id !== first.body.event_id) {
      throw new Error("The local D1 status endpoint did not return the created event.");
    }
    deliveryStatus = status.body.delivery_status;
  }
  if (deliveryStatus !== "delivered") {
    throw new Error(
      `The local outbox consumer did not persist delivery; state is ${deliveryStatus}.`,
    );
  }

  const expiryFixture = await prepareIdempotencyExpiryFixture();
  await verifyIdempotencyExpiryBehavior(expiryFixture);

  console.log(
    "P01 local smoke passed: Vite proxy → Rust Worker → D1 → outbox → Queue consumer → D1 status.",
  );
  console.log(
    `Request ID: ${firstRequestId}; event ID: ${first.body.event_id}; ID propagation, duplicate replay, and body-mismatch conflict verified.`,
  );
  console.log(
    "Local D1 preserved distinct principal/org scopes and ignored an exact duplicate scope insert.",
  );
  console.log("Local D1 rolled back the outbox insert when the idempotency claim guard failed.");
  console.log("Local Worker reclaimed an expired idempotency key and preserved an active claim.");
  console.log(
    "Production-config Worker returned a stable 404 for the development-only foundation route.",
  );
} catch (error) {
  const message = error instanceof Error ? error.message : "unknown smoke failure";
  console.error(message);
  for (const service of services) {
    if (service.output)
      console.error(`${service.label} log tail:\n${service.output.slice(-4_000)}`);
  }
  process.exitCode = 1;
} finally {
  await Promise.all(services.map(stop));
}
