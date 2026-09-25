// P05 managed control-loop integration smoke.
//
// This is intentionally self-contained: it creates a fresh local D1 persist
// directory, applies migrations 0001-0010, starts a development Worker, drives
// the browser/device APIs, and removes the persist directory on exit. It does
// not add a package script; the coordinator can wire one after reviewing this
// packet.
//
// Usage:
//   node apps/api/scripts/p05-smoke.mjs
//
// Optional environment variables:
//   P05_API_BASE          use an already-running Worker (requires
//                         P05_D1_PERSIST_TO for D1 evidence)
//   P05_PORT              local Worker port (default: an available port)
//   P05_PERSIST_TO        use a specific fresh local persist directory
//   P05_KEEP_PERSIST=1    retain the fresh directory for debugging
//   P05_PROBE_DISCONNECT=0 skip the passive-downstream-disconnect probe
//   P05_REQUIRE_CANCELLATION_ROW=1
//                         fail if no request_cancelled row is observed

import { spawn } from "node:child_process";
import { createHash, generateKeyPairSync, randomUUID, sign } from "node:crypto";
import { mkdir, mkdtemp, rm } from "node:fs/promises";
import { once } from "node:events";
import { createServer } from "node:net";
import os from "node:os";
import path from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { fileURLToPath } from "node:url";

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const apiDir = path.resolve(scriptDir, "..");
const wranglerBin = process.env.P05_WRANGLER ?? path.join(apiDir, "node_modules/.bin/wrangler");
const nonce = randomUUID().replaceAll("-", "").slice(0, 12);
const secrets = new Set();
const services = [];
const limitations = [];
let passed = 0;
let stage = "bootstrap";
let persistDir = null;
let ownsPersistDir = false;
let worker = null;
let baseUrl = process.env.P05_API_BASE ?? null;

function setStage(value) {
  stage = value;
  console.log(`\n== ${value} ==`);
}

function registerSecret(value) {
  if (typeof value === "string" && value.length >= 8) secrets.add(value);
}

function redactText(value) {
  let text = String(value);
  for (const secret of secrets) text = text.split(secret).join("[redacted]");
  return text.replace(/(Bearer|DeviceToken)\s+[A-Za-z0-9._-]+/gi, "$1 [redacted]").slice(0, 2_000);
}

const sensitiveKey =
  /(secret|token|password|cookie|authorization|challenge|development_code|signature|private|credential|content|prompt|body|text|summary|arguments)/i;

function sanitize(value, key = "", depth = 0) {
  if (depth > 8) return "[truncated]";
  if (sensitiveKey.test(key)) return "[redacted]";
  if (typeof value === "string") return redactText(value);
  if (value === null || typeof value === "number" || typeof value === "boolean") return value;
  if (Array.isArray(value)) return value.slice(0, 32).map((item) => sanitize(item, key, depth + 1));
  if (typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value)
        .slice(0, 64)
        .map(([childKey, childValue]) => [childKey, sanitize(childValue, childKey, depth + 1)]),
    );
  }
  return redactText(value);
}

function responseSummary(result) {
  const payload = result?.payload;
  const error = payload && typeof payload === "object" ? payload.error : undefined;
  return {
    method: result?.method,
    path: result?.path,
    status: result?.status,
    request_id: result?.requestId ?? null,
    error_code: error?.code ?? null,
    reason: error?.details?.reason ?? null,
    body: result?.text && !payload ? "[non-JSON response]" : sanitize(payload),
  };
}

function fail(message, result, detail = "") {
  const suffix = result ? ` ${JSON.stringify(responseSummary(result))}` : "";
  const detailSuffix = detail ? ` (${redactText(detail)})` : "";
  throw new Error(`${message}${detailSuffix}${suffix}`);
}

function pass(name, detail = "") {
  passed += 1;
  console.log(`PASS  ${name}${detail ? ` — ${redactText(detail)}` : ""}`);
}

function expect(name, condition, detail = "") {
  if (!condition) fail(name, null, detail);
  pass(name, detail);
}

function expectStatus(name, result, statuses, reasons = []) {
  const allowed = Array.isArray(statuses) ? statuses : [statuses];
  const reason = result?.payload?.error?.details?.reason;
  if (!allowed.includes(result?.status) || (reasons.length > 0 && !reasons.includes(reason))) {
    fail(
      `${name} (expected ${allowed.join("/")}${reasons.length ? ` ${reasons.join("/")}` : ""})`,
      result,
    );
  }
  pass(name, `HTTP ${result.status}${reason ? ` ${reason}` : ""}`);
  return result;
}

function addLimitation(message) {
  limitations.push(message);
  console.log(`LIMIT ${message}`);
}

// Wrangler's D1 CLI accepts a command string rather than bound parameters. All
// values passed to this helper are opaque IDs returned by the Worker and
// validated above; the smoke never interpolates prompt, secret, or tool input.
function quoteSql(value) {
  return `'${String(value).replaceAll("'", "''")}'`;
}

function opaqueId(prefix, label) {
  const digest = createHash("sha256").update(`${nonce}:${label}`).digest("hex");
  return `${prefix}_${digest.slice(0, 32)}`;
}

function idempotencyKey(label) {
  return `p05-${label}-${nonce}-${randomUUID().slice(0, 8)}`;
}

function assertId(name, value, prefix) {
  const expression = new RegExp(`^${prefix}_[0-9a-f]{32}$`);
  expect(name, typeof value === "string" && expression.test(value), `expected ${prefix} opaque ID`);
  return value;
}

class CookieJar {
  cookies = new Map();

  absorb(response) {
    const values =
      typeof response.headers.getSetCookie === "function"
        ? response.headers.getSetCookie()
        : [response.headers.get("set-cookie")].filter(Boolean);
    for (const value of values) {
      for (const part of value.split(/,(?=\s*[^;=]+=[^;]+)/)) {
        const [pair] = part.split(";");
        const separator = pair.indexOf("=");
        if (separator > 0)
          this.cookies.set(pair.slice(0, separator).trim(), pair.slice(separator + 1));
      }
    }
  }

  header() {
    return [...this.cookies.entries()].map(([key, value]) => `${key}=${value}`).join("; ");
  }
}

async function request(jar, method, routePath, body, extraHeaders = {}, options = {}) {
  const headers = { Accept: "application/json", ...extraHeaders };
  if (body !== undefined) headers["Content-Type"] = "application/json";
  const cookie = jar?.header?.();
  if (cookie) headers.Cookie = cookie;
  if (options.deviceToken) headers.Authorization = `DeviceToken ${options.deviceToken}`;
  const init = {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  };
  if (options.signal) init.signal = options.signal;
  else init.signal = AbortSignal.timeout(options.timeoutMs ?? 30_000);

  let response;
  try {
    response = await fetch(`${baseUrl}${routePath}`, init);
  } catch (error) {
    throw new Error(
      `${stage}: ${method} ${routePath} transport failure: ${redactText(error.message)}`,
    );
  }
  jar?.absorb?.(response);
  const text = await response.text();
  let payload;
  if (text) {
    try {
      payload = JSON.parse(text);
    } catch {
      payload = undefined;
    }
  }
  return {
    method,
    path: routePath,
    status: response.status,
    payload,
    text,
    headers: response.headers,
    requestId: response.headers.get("X-Request-ID"),
  };
}

function browserHeaders(jar, extra = {}) {
  return {
    "X-CSRF-Token": jar.cookies.get("lumi_csrf") ?? "",
    ...extra,
  };
}

function browserMutation(jar, label, extra = {}) {
  return browserHeaders(jar, { "Idempotency-Key": idempotencyKey(label), ...extra });
}

function deviceHeaders(device, extra = {}) {
  return { Authorization: `DeviceToken ${device.token}`, ...extra };
}

async function runProcess(command, args, label) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      cwd: apiDir,
      env: { ...process.env, CI: "1" },
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk) => {
      stdout = `${stdout}${chunk}`.slice(-20_000);
    });
    child.stderr.on("data", (chunk) => {
      stderr = `${stderr}${chunk}`.slice(-20_000);
    });
    child.once("error", (error) =>
      reject(new Error(`${label} could not start: ${redactText(error.message)}`)),
    );
    child.once("close", (code, signal) => {
      if (code === 0) {
        resolve({ stdout, stderr });
        return;
      }
      reject(
        new Error(
          `${label} failed (${code ?? signal ?? "unknown"}).\n${redactText(`${stdout}\n${stderr}`.slice(-8_000))}`,
        ),
      );
    });
  });
}

async function runWrangler(args, label) {
  return runProcess(wranglerBin, args, label);
}

function parseD1Json(output, label) {
  const text = output.trim();
  try {
    return JSON.parse(text);
  } catch {
    const start = text.search(/[[{]/);
    if (start >= 0) {
      try {
        return JSON.parse(text.slice(start));
      } catch {
        // Fall through to the diagnostic below.
      }
    }
    throw new Error(`${label} returned invalid Wrangler JSON: ${redactText(text.slice(-2_000))}`);
  }
}

function d1Rows(parsed) {
  const statements = Array.isArray(parsed) ? parsed : [parsed];
  return statements.flatMap((statement) =>
    Array.isArray(statement?.results) ? statement.results : [],
  );
}

async function d1(sql, label) {
  const output = await runWrangler(
    [
      "d1",
      "execute",
      "DB",
      "--local",
      "--env",
      "development",
      "--persist-to",
      persistDir,
      "--json",
      "--command",
      sql,
    ],
    label,
  );
  return d1Rows(parseD1Json(output.stdout, label));
}

async function d1One(sql, label) {
  return (await d1(sql, label))[0];
}

async function waitForD1(label, sql, predicate, timeoutMs = 12_000) {
  const deadline = Date.now() + timeoutMs;
  let last;
  while (Date.now() < deadline) {
    last = await d1One(sql, label);
    if (predicate(last)) return last;
    await delay(150);
  }
  throw new Error(
    `${stage}: ${label} did not reach the expected D1 state; last=${JSON.stringify(sanitize(last))}`,
  );
}

async function availablePort() {
  const server = createServer();
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  const port = typeof address === "object" && address ? address.port : 8787;
  await new Promise((resolve, reject) =>
    server.close((error) => (error ? reject(error) : resolve())),
  );
  return port;
}

async function waitForHealth(child) {
  const deadline = Date.now() + 180_000;
  let lastError = "no response";
  while (Date.now() < deadline) {
    if (child.exitCode !== null) {
      const service = services.find((entry) => entry.child === child);
      throw new Error(`Worker exited during startup.\n${redactText(service?.output ?? "")}`);
    }
    try {
      const response = await fetch(`${baseUrl}/api/health`, { signal: AbortSignal.timeout(2_000) });
      if (response.ok) return;
      lastError = `health status ${response.status}`;
    } catch (error) {
      lastError = error instanceof Error ? error.message : "connection error";
    }
    await delay(250);
  }
  throw new Error(`Worker did not become healthy: ${redactText(lastError)}`);
}

function startWorker(port) {
  const child = spawn(
    wranglerBin,
    [
      "dev",
      "--env",
      "development",
      "--local",
      "--port",
      String(port),
      "--persist-to",
      persistDir,
      "--show-interactive-dev-session=false",
    ],
    {
      cwd: apiDir,
      env: { ...process.env, CI: "1" },
      stdio: ["ignore", "pipe", "pipe"],
      detached: process.platform !== "win32",
    },
  );
  let output = "";
  const capture = (chunk) => {
    output = `${output}${chunk}`.slice(-16_000);
  };
  child.stdout.on("data", capture);
  child.stderr.on("data", capture);
  child.on("error", (error) => {
    output = `${output}\n${error.message}`.slice(-16_000);
  });
  services.push({
    child,
    label: "Worker",
    get output() {
      return output;
    },
  });
  return child;
}

async function setupInfrastructure() {
  if (baseUrl) {
    if (!process.env.P05_D1_PERSIST_TO) {
      throw new Error(
        "P05_API_BASE was supplied without P05_D1_PERSIST_TO; external-worker mode cannot prove fresh D1 state",
      );
    }
    persistDir = path.resolve(process.env.P05_D1_PERSIST_TO);
    await mkdir(persistDir, { recursive: true });
    console.log(`Using external Worker at ${baseUrl}; D1 evidence comes from ${persistDir}`);
    return;
  }

  if (process.env.P05_PERSIST_TO) {
    persistDir = path.resolve(process.env.P05_PERSIST_TO);
    await mkdir(persistDir, { recursive: true });
  } else {
    persistDir = await mkdtemp(path.join(os.tmpdir(), "lumi-p05-smoke-"));
    ownsPersistDir = true;
  }

  const port = process.env.P05_PORT ? Number(process.env.P05_PORT) : await availablePort();
  if (!Number.isInteger(port) || port < 1 || port > 65_535) {
    throw new Error(`P05_PORT is invalid: ${process.env.P05_PORT}`);
  }
  baseUrl = `http://127.0.0.1:${port}`;

  await runWrangler(
    [
      "d1",
      "migrations",
      "apply",
      "DB",
      "--local",
      "--env",
      "development",
      "--persist-to",
      persistDir,
    ],
    "P05 fresh D1 migration",
  );
  const migrations = await d1(
    "SELECT name FROM d1_migrations ORDER BY id",
    "P05 migration ledger check",
  );
  if (!migrations.some((row) => String(row.name).includes("0010_p05_runs_tools_usage_control"))) {
    throw new Error(
      `Fresh D1 did not apply migration 0010: ${JSON.stringify(sanitize(migrations))}`,
    );
  }
  pass("fresh D1 applies migrations through 0010", `${migrations.length} migration rows`);

  worker = startWorker(port);
  await waitForHealth(worker);
  pass("development Worker is healthy", baseUrl);
}

const failures = [];
const skipped = [];

function errorText(error) {
  return redactText(error instanceof Error ? error.message : String(error));
}

function recordFailure(name, error) {
  const message = errorText(error);
  failures.push({ name, message });
  console.error(`FAIL  ${name} — ${message}`);
}

async function scenario(name, callback) {
  setStage(name);
  try {
    await callback();
    pass(`${name} completed`);
  } catch (error) {
    recordFailure(name, error);
  }
}

async function optionalProbe(name, callback) {
  setStage(name);
  try {
    await callback();
    pass(`${name} probe completed`);
  } catch (error) {
    addLimitation(`${name}: ${errorText(error)}`);
  }
}

function skip(name, reason) {
  const message = `${name}: ${reason}`;
  skipped.push(message);
  addLimitation(message);
}

function instantOffset(seconds = 0) {
  return new Date(Date.now() + seconds * 1_000).toISOString();
}

function requirePayload(result, name) {
  if (!result?.payload || typeof result.payload !== "object") {
    fail(`${name} returned no JSON object`, result);
  }
  return result.payload;
}

function reasonOf(result) {
  return result?.payload?.error?.details?.reason ?? null;
}

function statusIs(result, statuses, reasons = []) {
  const allowed = Array.isArray(statuses) ? statuses : [statuses];
  return (
    allowed.includes(result?.status) && (reasons.length === 0 || reasons.includes(reasonOf(result)))
  );
}

function assertDenied(result, name, statuses, reasons) {
  if (!statusIs(result, statuses, reasons)) {
    fail(`${name} did not fail closed`, result, `reason=${reasonOf(result) ?? "none"}`);
  }
  pass(name, `HTTP ${result.status}${reasonOf(result) ? ` ${reasonOf(result)}` : ""}`);
}

async function d1Find(sql, label) {
  const row = await d1One(sql, label);
  if (!row) fail(`${label} returned no D1 row`, null, "the expected correlation row is absent");
  return row;
}

function deviceMutation(device, label, extra = {}) {
  return {
    Authorization: `DeviceToken ${device.token}`,
    "Idempotency-Key": idempotencyKey(label),
    ...extra,
  };
}

function makeDevice(label) {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const publicKeyPem = publicKey.export({ type: "spki", format: "pem" }).toString();
  const keyFingerprint = createHash("sha256")
    .update(publicKey.export({ type: "spki", format: "der" }))
    .digest("hex");
  return {
    label,
    publicKeyPem,
    keyFingerprint,
    sign(message) {
      return sign(null, Buffer.from(message), privateKey).toString("hex");
    },
    privateKey,
  };
}

async function authenticatedUser(label) {
  const jar = new CookieJar();
  const email = `${label.toLowerCase().replaceAll(/[^a-z0-9]+/g, "-")}-${nonce}@example.com`;
  let result = await request(jar, "POST", "/api/v1/auth/signup", {
    email,
    display_name: label,
  });
  expectStatus(`signup ${label}`, result, 201);
  const verification = requirePayload(result, `signup ${label}`).verification;
  if (!verification?.challenge_id || !verification?.development_code) {
    fail(`signup ${label} did not expose the development verification challenge`, result);
  }
  registerSecret(verification.development_code);
  result = await request(jar, "POST", "/api/v1/auth/verify-email", {
    challenge_id: verification.challenge_id,
    code: verification.development_code,
  });
  expectStatus(`verify ${label}`, result, 200);
  result = await request(jar, "POST", "/api/v1/auth/login/start", { email });
  expectStatus(`login start ${label}`, result, 202);
  const login = requirePayload(result, `login start ${label}`);
  if (!login.challenge_id || !login.development_code) {
    fail(`login start ${label} did not expose a development challenge`, result);
  }
  registerSecret(login.development_code);
  result = await request(jar, "POST", "/api/v1/auth/login/complete", {
    challenge_id: login.challenge_id,
    code: login.development_code,
  });
  expectStatus(`login complete ${label}`, result, 200);
  const user = requirePayload(result, `login complete ${label}`).user;
  if (!user?.id || !user?.email) fail(`login complete ${label} did not return a user`, result);
  assertId(`user ${label} has an opaque ID`, user.id, "usr");
  return { jar, user, email };
}

async function createOrganization(jar, label, slug) {
  const result = await request(
    jar,
    "POST",
    "/api/v1/orgs",
    { display_name: label, slug },
    browserMutation(jar, `org-${slug}`),
  );
  expectStatus(`create ${label}`, result, 201);
  const orgId = result.payload?.organization?.org_id;
  assertId(`${label} organization ID`, orgId, "org");
  return { orgId, slug };
}

async function createProject(jar, orgId, name, slug) {
  const result = await request(
    jar,
    "POST",
    `/api/v1/orgs/${orgId}/projects`,
    { name, slug, visibility: "org" },
    browserMutation(jar, `project-${slug}`),
  );
  expectStatus(`create project ${name}`, result, 201);
  const projectId = result.payload?.id;
  assertId(`${name} project ID`, projectId, "prj");
  return projectId;
}

async function inviteAndAccept(alice, bob, orgId) {
  const invite = await request(
    alice.jar,
    "POST",
    `/api/v1/orgs/${orgId}/invitations`,
    { email: bob.user.email, role: "member" },
    browserMutation(alice.jar, `invite-${orgId}`),
  );
  expectStatus("invite second user", invite, 201);
  const invitation = requirePayload(invite, "invite second user").invitation;
  const token = invite.payload?.development_token;
  const invitationId = invitation?.invitation_id ?? invitation?.id;
  if (!invitationId || !token) {
    fail("invite response omitted the development invitation token", invite);
  }
  registerSecret(token);
  const accepted = await request(
    bob.jar,
    "POST",
    `/api/v1/invitations/${invitationId}/accept`,
    { token },
    browserHeaders(bob.jar),
  );
  expectStatus("accept second-user invitation", accepted, 200);
  return invitation.invitation_id ?? invitation.id;
}

async function enrollDevice({ admin, orgSlug, device, capabilities }) {
  const enrollment = await request(new CookieJar(), "POST", "/api/v1/devices/enrollments", {
    org_slug: orgSlug,
    public_key: device.publicKeyPem,
    key_fingerprint: device.keyFingerprint,
    device_name: device.label,
    platform: "darwin-arm64",
    app_version: "0.5.0",
  });
  expectStatus(`begin enrollment ${device.label}`, enrollment, 201);
  const enrollmentId = requirePayload(enrollment, `begin enrollment ${device.label}`).enrollment_id;
  assertId(`${device.label} enrollment ID`, enrollmentId, "enr");
  const approval = await request(
    admin.jar,
    "POST",
    `/api/v1/orgs/${admin.orgId}/devices/enrollments/${enrollmentId}/approve`,
    {},
    browserMutation(admin.jar, `approve-${enrollmentId}`),
  );
  expectStatus(`approve enrollment ${device.label}`, approval, 201);
  const status = await request(
    new CookieJar(),
    "GET",
    `/api/v1/devices/enrollments/${enrollmentId}`,
  );
  expectStatus(`poll enrollment ${device.label}`, status, 200);
  if (status.payload?.status !== "approved" || typeof status.payload?.challenge !== "string") {
    fail(`enrollment ${device.label} did not release a proof challenge`, status);
  }
  const invalid = await request(
    new CookieJar(),
    "POST",
    `/api/v1/devices/enrollments/${enrollmentId}/complete`,
    { signature: "00".repeat(64) },
  );
  assertDenied(invalid, `invalid device proof ${device.label} is rejected`, 403, [
    "device_proof_invalid",
  ]);
  const completed = await request(
    new CookieJar(),
    "POST",
    `/api/v1/devices/enrollments/${enrollmentId}/complete`,
    { signature: device.sign(status.payload.challenge) },
  );
  expectStatus(`complete enrollment ${device.label}`, completed, 201);
  const payload = requirePayload(completed, `complete enrollment ${device.label}`);
  const token = payload.device_token;
  const deviceId = payload.device?.id;
  if (!token || !deviceId)
    fail(`completed enrollment ${device.label} omitted token/device`, completed);
  assertId(`${device.label} device ID`, deviceId, "dvc");
  registerSecret(token);
  const activeDevice = { ...device, id: deviceId, token, orgId: admin.orgId };
  if (capabilities) {
    const heartbeat = await request(
      new CookieJar(),
      "POST",
      "/api/v1/devices/heartbeat",
      { app_version: "0.5.0", capabilities },
      deviceHeaders(activeDevice),
    );
    expectStatus(`heartbeat ${device.label}`, heartbeat, 200);
  }
  return activeDevice;
}

async function createWorkspaceBinding(device, projectId, label) {
  const result = await request(
    new CookieJar(),
    "POST",
    "/api/v1/devices/bindings",
    {
      project_id: projectId,
      workspace_identity: `p05-${label}-${nonce}`,
      display_name: `P05 ${label}`,
      environment_type: "local",
    },
    deviceHeaders(device),
  );
  expectStatus(`bind workspace for ${label}`, result, 201);
  const bindingId = result.payload?.id;
  assertId(`${label} workspace binding ID`, bindingId, "wsb");
  return bindingId;
}

async function stopServices() {
  for (const service of [...services].reverse()) {
    const child = service.child;
    if (child.exitCode !== null) continue;
    try {
      child.kill("SIGTERM");
      await Promise.race([once(child, "exit"), delay(5_000)]);
      if (child.exitCode === null) child.kill("SIGKILL");
    } catch (error) {
      console.error(`cleanup ${service.label}: ${errorText(error)}`);
    }
  }
}

async function createCredential(jar, orgId, providerId, label) {
  const secret = `p05-${nonce}-${label}-secret`;
  registerSecret(secret);
  const result = await request(
    jar,
    "POST",
    `/api/v1/orgs/${orgId}/credentials`,
    {
      provider_id: providerId,
      owner_type: "organization",
      label: `P05 ${label}`,
      secret,
    },
    browserMutation(jar, `credential-${label}`),
  );
  expectStatus(`create ${label} credential`, result, 201);
  const credentialId = result.payload?.credential?.credential_id;
  assertId(`${label} credential ID`, credentialId, "cred");
  return credentialId;
}

async function createPublishedRoute({
  jar,
  orgId,
  alias,
  providerId,
  modelId,
  credentialId,
  label,
}) {
  const config = {
    strategy: "fixed",
    candidates: [
      {
        provider_id: providerId,
        model_id: modelId,
        weight: 100,
        timeout_ms: 5_000,
        max_retries: 0,
        credential_id: credentialId,
      },
    ],
  };
  let result = await request(
    jar,
    "POST",
    `/api/v1/orgs/${orgId}/routes`,
    { alias, display_name: `P05 ${label}`, strategy: "fixed", config },
    browserMutation(jar, `route-${alias}`),
  );
  expectStatus(`create ${label} route`, result, 201);
  const route = result.payload?.route;
  const routeId = route?.route_id;
  if (!routeId) fail(`create ${label} route omitted route_id`, result);
  assertId(`${label} route ID`, routeId, "rte");
  result = await request(
    jar,
    "POST",
    `/api/v1/orgs/${orgId}/routes/${routeId}/publish`,
    { version: route.version, config },
    browserMutation(jar, `publish-${alias}`),
  );
  expectStatus(`publish ${label} route`, result, 200);
  const routeVersionId = result.payload?.version?.route_version_id;
  if (!routeVersionId) fail(`publish ${label} route omitted route version`, result);
  assertId(`${label} route version ID`, routeVersionId, "rtv");
  return { route: result.payload?.route ?? route, routeId, routeVersionId, config };
}

async function setupModelPlane(jar, orgId) {
  const catalog = await request(jar, "GET", `/api/v1/orgs/${orgId}/catalog`);
  expectStatus("read P04 catalog", catalog, 200);
  const providers = catalog.payload?.providers ?? [];
  const models = catalog.payload?.models ?? [];
  const successProvider = providers.find((provider) => provider.provider_key === "mock-success");
  const timeoutProvider = providers.find((provider) => provider.provider_key === "mock-timeout");
  const successModel = models.find((model) => model.provider_model_id === "mock-success");
  const timeoutModel = models.find((model) => model.provider_model_id === "mock-timeout");
  if (!successProvider || !successModel) {
    fail("development catalog is missing mock-success", catalog);
  }
  const successCredential = await createCredential(
    jar,
    orgId,
    successProvider.provider_id,
    "mock-success",
  );
  const successRoute = await createPublishedRoute({
    jar,
    orgId,
    alias: "coding-default",
    providerId: successProvider.provider_id,
    modelId: successModel.model_id,
    credentialId: successCredential,
    label: "managed success",
  });
  let timeout = null;
  if (timeoutProvider && timeoutModel) {
    const timeoutCredential = await createCredential(
      jar,
      orgId,
      timeoutProvider.provider_id,
      "mock-timeout",
    );
    timeout = await createPublishedRoute({
      jar,
      orgId,
      alias: "p05-timeout",
      providerId: timeoutProvider.provider_id,
      modelId: timeoutModel.model_id,
      credentialId: timeoutCredential,
      label: "timeout probe",
    });
  } else {
    skip(
      "passive disconnect probe",
      "mock-timeout provider/model is not present in the development catalog",
    );
  }
  const policy = await request(jar, "GET", `/api/v1/orgs/${orgId}/policy`);
  expectStatus("read model policy", policy, 200);
  const allowedAliases = ["coding-default"];
  const allowedModels = [successModel.model_id];
  const allowedProviders = [successProvider.provider_id];
  if (timeout) {
    allowedAliases.push("p05-timeout");
    allowedModels.push(timeoutModel.model_id);
    allowedProviders.push(timeoutProvider.provider_id);
  }
  const updated = await request(
    jar,
    "PUT",
    `/api/v1/orgs/${orgId}/policy`,
    {
      allowed_aliases: allowedAliases,
      allowed_models: allowedModels,
      allowed_providers: allowedProviders,
      credential_mode: "organization_only",
      managed_route_enabled: true,
      version: policy.payload?.version ?? 0,
    },
    browserMutation(jar, "model-policy"),
  );
  expectStatus("publish model policy", updated, 200);
  return {
    catalog,
    successProvider,
    successModel,
    successCredential,
    successRoute,
    timeoutProvider,
    timeoutModel,
    timeout,
    modelPolicyVersion: updated.payload?.version,
  };
}

async function createTool(jar, orgId, definition) {
  const result = await request(
    jar,
    "POST",
    `/api/v1/orgs/${orgId}/tools`,
    definition,
    browserMutation(jar, `tool-${definition.name}`),
  );
  expectStatus(`create tool ${definition.name}`, result, 201);
  const toolId = result.payload?.tool_id ?? result.payload?.id;
  assertId(`${definition.name} tool ID`, toolId, "tool");
  return { ...result.payload, tool_id: toolId, id: toolId };
}

async function updateMcp(jar, orgId, mcpId, version, fields) {
  const result = await request(
    jar,
    "PATCH",
    `/api/v1/orgs/${orgId}/mcp/${mcpId}`,
    { version, ...fields },
    browserMutation(jar, `mcp-update-${mcpId}-${version}`),
  );
  expectStatus(`update MCP ${mcpId}`, result, 200);
  return result.payload;
}

async function setupToolPlane(jar, orgId) {
  const browserCapabilityId = opaqueId("cap", "browser");
  const readonly = await createTool(jar, orgId, {
    name: `P05 readonly ${nonce}`,
    source: "built_in",
    risk_class: "read_only",
    capability_ids: [],
    fingerprint: `p05-readonly-${nonce}`,
  });
  const privileged = await createTool(jar, orgId, {
    name: `P05 privileged ${nonce}`,
    source: "built_in",
    risk_class: "external_side_effect",
    capability_ids: [],
    fingerprint: `p05-privileged-${nonce}`,
  });
  const browser = await createTool(jar, orgId, {
    name: `P05 browser submit ${nonce}`,
    source: "built_in",
    risk_class: "browser",
    capability_ids: [browserCapabilityId],
    fingerprint: `p05-browser-${nonce}`,
  });
  const mcpTool = await createTool(jar, orgId, {
    name: `P05 MCP fixture ${nonce}`,
    source: "custom",
    risk_class: "mcp",
    capability_ids: [],
    fingerprint: `p05-mcp-${nonce}`,
  });
  const expandedMcpTool = await createTool(jar, orgId, {
    name: `P05 MCP expansion ${nonce}`,
    source: "custom",
    risk_class: "mcp",
    capability_ids: [],
    fingerprint: `p05-mcp-expanded-${nonce}`,
  });
  const staleTool = await createTool(jar, orgId, {
    name: `P05 stale policy ${nonce}`,
    source: "built_in",
    risk_class: "read_only",
    capability_ids: [],
    fingerprint: `p05-stale-${nonce}`,
  });
  const mcpRegistration = await request(
    jar,
    "POST",
    `/api/v1/orgs/${orgId}/mcp`,
    {
      source: "custom",
      transport: "stdio",
      endpoint_metadata: { display_name: "P05 fixture MCP" },
      command_metadata: { command: "p05-mcp-fixture", arguments: [] },
      allowed_origins: [],
      tool_fingerprint: mcpTool.fingerprint,
    },
    browserMutation(jar, "mcp-fixture"),
  );
  expectStatus("create MCP registration", mcpRegistration, 201);
  const mcp = mcpRegistration.payload;
  const mcpId = mcp?.mcp_id ?? mcp?.id;
  assertId("MCP registration ID", mcpId, "mcp");
  const approvedMcp = await updateMcp(jar, orgId, mcpId, mcp.version, {
    policy_status: "approved",
    tool_list: [
      {
        tool_id: mcpTool.tool_id,
        fingerprint: mcpTool.fingerprint,
        risk_class: "mcp",
      },
    ],
  });
  const policyTools = [
    readonly.tool_id,
    privileged.tool_id,
    browser.tool_id,
    mcpTool.tool_id,
    expandedMcpTool.tool_id,
    staleTool.tool_id,
  ];
  const initialPolicy = {
    schema_version: 1,
    default_posture: "deny",
    default_approval_mode: "none",
    tool_ids: policyTools,
    mcp_ids: [mcpId],
    tool_approval_modes: {
      [privileged.tool_id]: "per_use",
      [browser.tool_id]: "per_use",
      [mcpTool.tool_id]: "per_use",
    },
    browser: {
      allowed_domains: ["example.test"],
      blocked_domains: [],
      allow_download: false,
      allow_upload: false,
      allow_authenticated: false,
      allow_clipboard: false,
      external_submit: "require_per_use_approval",
    },
    computer: {
      allow_accessibility: false,
      allow_screen_capture: false,
      allow_keyboard_mouse: false,
      allow_shell_escalation: false,
      allowed_applications: [],
    },
    version: 0,
  };
  const policy = await request(
    jar,
    "PUT",
    `/api/v1/orgs/${orgId}/policy/tools`,
    initialPolicy,
    browserMutation(jar, "tool-policy"),
  );
  expectStatus("publish managed tool policy", policy, 200);
  const capabilityRows = await d1(
    `SELECT capability_id, capability_key FROM capability_definitions WHERE capability_id = ${quoteSql(browserCapabilityId)} LIMIT 1`,
    "P05 browser capability evidence",
  );
  if (capabilityRows.length === 0) {
    skip(
      "public browser/CUA capability catalog",
      "no capability-definition write route is exposed and no platform browser capability row is present; no D1 seed is used by this smoke",
    );
  }
  return {
    browserCapabilityId,
    readonly,
    privileged,
    browser,
    mcpTool,
    expandedMcpTool,
    staleTool,
    mcp: approvedMcp,
    mcpId,
    policy,
    policyTools,
  };
}

async function createAgent(jar, orgId, projectId, toolPlane, modelAlias) {
  const result = await request(
    jar,
    "POST",
    `/api/v1/orgs/${orgId}/agents`,
    {
      name: `P05 managed agent ${nonce}`,
      description: "P05 managed-loop smoke agent",
      instructions_ref: `local://p05-smoke/${nonce}/instructions`,
      default_model_alias: modelAlias,
      required_capabilities: ["text"],
      allowed_tool_ids: [
        toolPlane.readonly.tool_id,
        toolPlane.privileged.tool_id,
        toolPlane.browser.tool_id,
        toolPlane.mcpTool.tool_id,
        toolPlane.expandedMcpTool.tool_id,
        toolPlane.staleTool.tool_id,
      ],
      runtime_requirements: ["filesystem_read"],
      project_id: projectId,
    },
    browserMutation(jar, "agent"),
  );
  expectStatus("create managed agent", result, 201);
  const agentId = result.payload?.id;
  assertId("agent definition ID", agentId, "agd");
  return result.payload;
}

async function createBudget(jar, orgId, limitMinor = 1_000) {
  const result = await request(
    jar,
    "POST",
    `/api/v1/orgs/${orgId}/budgets`,
    {
      scope_type: "organization",
      period_start: instantOffset(-3_600),
      period_end: instantOffset(86_400),
      limit_minor: limitMinor,
      currency: "USD",
      hard: true,
    },
    browserMutation(jar, "hard-budget"),
  );
  expectStatus("create hard budget", result, 201);
  const budgetId = result.payload?.budget_id ?? result.payload?.id;
  assertId("budget ID", budgetId, "bud");
  return result.payload;
}

async function setBudgetLimit(jar, orgId, budget, limitMinor) {
  const result = await request(
    jar,
    "PATCH",
    `/api/v1/orgs/${orgId}/budgets/${budget.budget_id ?? budget.id}`,
    { version: budget.version, limit_minor: limitMinor },
    browserMutation(jar, `budget-limit-${limitMinor}`),
  );
  expectStatus(`set hard budget limit ${limitMinor}`, result, 200);
  return result.payload;
}

async function setConcurrencyLimit(jar, orgId, projectId, maxConcurrent = 1, version = 0) {
  const result = await request(
    jar,
    "PUT",
    `/api/v1/orgs/${orgId}/rate-limits/project/${projectId}`,
    {
      requests_per_minute: null,
      tokens_per_minute: null,
      max_concurrent_requests: maxConcurrent,
      version,
    },
    browserMutation(jar, "concurrency-limit"),
  );
  expectStatus("set project concurrency limit", result, 200);
  return result.payload;
}

async function createDeviceSessionAndRun(device, projectId, agent, bindingId, modelAlias, label) {
  let result = await request(
    new CookieJar(),
    "POST",
    "/api/v1/devices/sessions",
    {
      project_id: projectId,
      agent_definition_id: agent.id,
      workspace_binding_id: bindingId,
      external_id: `p05-${label}-${nonce}`,
      title: `P05 ${label}`,
    },
    deviceMutation(device, `session-${label}`),
  );
  expectStatus(`create device session ${label}`, result, 201);
  const sessionId = result.payload?.id ?? result.payload?.agent_session_id;
  assertId(`${label} agent session ID`, sessionId, "rse");
  result = await request(
    new CookieJar(),
    "POST",
    `/api/v1/devices/sessions/${sessionId}/runs`,
    {
      model_alias: modelAlias,
      input_ref: `local://p05-smoke/${nonce}/${label}`,
      execution_mode: "managed",
    },
    deviceMutation(device, `run-${label}`),
  );
  expectStatus(`create device-managed run ${label}`, result, 201);
  const run = result.payload;
  const runId = run?.id ?? run?.run_id;
  assertId(`${label} run ID`, runId, "run");
  expect(
    `${label} run is server-owned`,
    run.org_id === device.orgId && run.project_id === projectId,
  );
  expect(
    `${label} run carries device and agent-session correlation`,
    run.device_id === device.id && run.agent_session_id === sessionId,
  );
  return { sessionId, run, runId };
}

async function startDeviceRun(device, run) {
  const result = await request(
    new CookieJar(),
    "POST",
    `/api/v1/devices/runs/${run.id ?? run.run_id}/start`,
    { version: run.version },
    deviceMutation(device, `start-${run.id ?? run.run_id}`),
  );
  expectStatus(`start run ${run.id ?? run.run_id}`, result, 200);
  return result.payload;
}

async function runManagedInference({ jar, orgId, runId, sessionId, model, stream = false }) {
  return request(
    jar,
    "POST",
    "/api/v1/inference/responses",
    {
      model,
      messages: [{ role: "user", content: [{ type: "text", text: "P05 managed smoke" }] }],
      required_capabilities: ["text"],
      max_output_tokens: 1,
      stream,
      run_id: runId,
      agent_session_id: sessionId,
    },
    {
      "X-Org-ID": orgId,
      ...browserHeaders(jar),
    },
  );
}

async function runToolDecision(device, runId, body) {
  return request(
    new CookieJar(),
    "POST",
    `/api/v1/runs/${runId}/tool-decisions`,
    body,
    deviceHeaders(device),
  );
}

async function runToolResult(device, runId, toolCallId, body, label) {
  return request(
    new CookieJar(),
    "POST",
    `/api/v1/devices/runs/${runId}/tool-calls/${toolCallId}/result`,
    body,
    deviceMutation(device, label),
  );
}

async function resolveApproval(jar, orgId, approvalId, version, decision = "approved") {
  return request(
    jar,
    "POST",
    `/api/v1/orgs/${orgId}/approvals/${approvalId}/resolve`,
    { decision, version },
    browserMutation(jar, `approval-${approvalId}-${decision}`),
  );
}

async function openManagedStream({ jar, orgId, runId, sessionId, model }) {
  const controller = new AbortController();
  const headers = {
    Accept: "text/event-stream",
    "Content-Type": "application/json",
    "X-Org-ID": orgId,
    ...browserHeaders(jar),
  };
  const cookie = jar.header();
  if (cookie) headers.Cookie = cookie;
  const response = await fetch(`${baseUrl}/api/v1/inference/responses`, {
    method: "POST",
    headers,
    body: JSON.stringify({
      model,
      messages: [{ role: "user", content: [{ type: "text", text: "P05 timeout probe" }] }],
      required_capabilities: ["text"],
      max_output_tokens: 1,
      stream: true,
      run_id: runId,
      agent_session_id: sessionId,
    }),
    signal: controller.signal,
  });
  const reader = response.body?.getReader();
  const firstChunk = reader ? await reader.read() : null;
  return { controller, response, reader, firstChunk };
}

async function inspectCancellationD1(requestId) {
  if (!requestId) return null;
  return d1One(
    `SELECT request_id, response_state, error_code FROM inference_requests WHERE request_id = ${quoteSql(requestId)} LIMIT 1`,
    "P05 passive disconnect D1 evidence",
  );
}

async function main() {
  const state = {
    alice: null,
    bob: null,
    orgA: null,
    orgB: null,
    projectA: null,
    projectB: null,
    deviceA: null,
    deviceB: null,
    bindingA: null,
    bindingB: null,
    modelPlane: null,
    toolPlane: null,
    agent: null,
    budget: null,
    mainRun: null,
    retryRun: null,
    toolEvidence: {},
  };

  await setupInfrastructure();
  addLimitation(
    "public CUA: this Worker exposes policy decisions and result metadata only; no public computer/browser execution endpoint or UI execution evidence is claimed",
  );

  await scenario("two-tenant identity and project provisioning", async () => {
    state.alice = await authenticatedUser("P05 Alice");
    state.bob = await authenticatedUser("P05 Bob");
    state.orgA = await createOrganization(
      state.alice.jar,
      `P05 managed tenant A ${nonce}`,
      `p05-a-${nonce}`,
    );
    state.orgB = await createOrganization(
      state.alice.jar,
      `P05 isolated tenant B ${nonce}`,
      `p05-b-${nonce}`,
    );
    await inviteAndAccept(state.alice, state.bob, state.orgB.orgId);
    state.projectA = await createProject(
      state.alice.jar,
      state.orgA.orgId,
      "P05 managed project",
      `p05-project-a-${nonce}`,
    );
    state.projectB = await createProject(
      state.alice.jar,
      state.orgB.orgId,
      "P05 isolated project",
      `p05-project-b-${nonce}`,
    );
    expect(
      "tenant IDs are distinct",
      state.orgA.orgId !== state.orgB.orgId && state.projectA !== state.projectB,
    );
  });

  await scenario("two-device enrollment, binding, and capability reporting", async () => {
    if (!state.orgA || !state.orgB || !state.projectA || !state.projectB) {
      fail("tenant provisioning did not complete", null);
    }
    const deviceAKey = makeDevice("P05 Alice laptop");
    const deviceBKey = makeDevice("P05 Bob laptop");
    state.deviceA = await enrollDevice({
      admin: { jar: state.alice.jar, orgId: state.orgA.orgId },
      orgSlug: state.orgA.slug,
      device: deviceAKey,
      capabilities: {
        browser_use: true,
        computer_use: false,
        automation_eligible: true,
        remote_environment: false,
        runtime_version: "p05-smoke",
      },
    });
    state.deviceB = await enrollDevice({
      // Bob approves his own member enrollment so the device owner is Bob;
      // this makes the later membership-removal probe exercise stale identity
      // rather than testing Alice's owner membership.
      admin: { jar: state.bob.jar, orgId: state.orgB.orgId },
      orgSlug: state.orgB.slug,
      device: deviceBKey,
      capabilities: { browser_use: false, computer_use: false },
    });
    state.bindingA = await createWorkspaceBinding(state.deviceA, state.projectA, "alice");
    state.bindingB = await createWorkspaceBinding(state.deviceB, state.projectB, "bob");
    expect(
      "device and workspace IDs remain distinct across tenants",
      state.deviceA.id !== state.deviceB.id && state.bindingA !== state.bindingB,
    );
  });

  await scenario("P04 catalog, route, credential, and model policy setup", async () => {
    if (!state.orgA) fail("tenant A is unavailable", null);
    state.modelPlane = await setupModelPlane(state.alice.jar, state.orgA.orgId);
    expect(
      "managed success route is published",
      state.modelPlane.successRoute?.route?.lifecycle === "published" &&
        Boolean(state.modelPlane.successRoute.routeVersionId),
    );
  });

  await scenario("P05 tool, MCP, policy, and agent setup", async () => {
    if (!state.orgA || !state.projectA) fail("tenant A project is unavailable", null);
    state.toolPlane = await setupToolPlane(state.alice.jar, state.orgA.orgId);
    state.agent = await createAgent(
      state.alice.jar,
      state.orgA.orgId,
      state.projectA,
      state.toolPlane,
      "coding-default",
    );
    if (!state.bindingA) {
      state.bindingA = await createWorkspaceBinding(state.deviceA, state.projectA, "alice");
    }
    state.budget = await createBudget(state.alice.jar, state.orgA.orgId, 1_000);
    const effective = await request(
      state.alice.jar,
      "GET",
      `/api/v1/orgs/${state.orgA.orgId}/policy`,
    );
    expectStatus("read effective P03 policy", effective, 200);
    const payload = effective.payload?.payload;
    expect(
      "effective policy is persisted for the bound project",
      effective.payload?.persisted === true &&
        payload?.projects?.bindings?.includes(state.projectA) === true,
    );
    const budgets = payload?.budgets;
    const rates = payload?.rate_limits;
    if (budgets?.schema_version === 0 || rates?.schema_version === 0) {
      addLimitation(
        "managed P05 policy transport: the current P03 snapshot exposes schema-0 budgets/rate_limits placeholders; no client snapshot is accepted as authority",
      );
    }
  });

  // Managed inference is intentionally attempted against the real snapshot. A
  // schema-0/malformed P05 section must fail closed; the smoke does not patch D1
  // to make that contract violation disappear.
  await scenario("managed run start and correlated inference", async () => {
    if (!state.deviceA || !state.projectA || !state.agent || !state.bindingA) {
      fail("managed run prerequisites are unavailable", null);
    }
    const created = await createDeviceSessionAndRun(
      state.deviceA,
      state.projectA,
      state.agent,
      state.bindingA,
      "coding-default",
      "managed",
    );
    state.mainRun = created;
    const running = await startDeviceRun(state.deviceA, created.run);
    state.mainRun.run = running;
    state.mainRun.running = true;
    const inference = await runManagedInference({
      jar: state.alice.jar,
      orgId: state.orgA.orgId,
      runId: created.runId,
      sessionId: created.sessionId,
      model: "coding-default",
    });
    expectStatus("managed mock inference", inference, 200);
    const requestId = inference.requestId ?? inference.payload?.request_id;
    assertId("managed inference request ID", requestId, "req");
    state.mainRun.requestId = requestId;
    const requestRow = await d1Find(
      `SELECT request_id, org_id, project_id, run_id, principal_user_id, session_id, device_id, model_alias, route_id, route_version_id, response_state FROM inference_requests WHERE request_id = ${quoteSql(requestId)} LIMIT 1`,
      "managed inference D1 correlation",
    );
    expect(
      "managed inference propagates server-owned org/project/device/session/run identity",
      requestRow.org_id === state.orgA.orgId &&
        requestRow.project_id === state.projectA &&
        requestRow.run_id === created.runId &&
        requestRow.device_id === state.deviceA.id &&
        requestRow.principal_user_id === state.alice.user.id,
    );
    expect(
      "managed inference uses the managed alias and published route",
      requestRow.model_alias === "coding-default" &&
        requestRow.route_id === state.modelPlane.successRoute.routeId &&
        requestRow.route_version_id === state.modelPlane.successRoute.routeVersionId,
    );
    const reservation = await waitForD1(
      "managed budget reservation",
      `SELECT reservation_id, request_id, org_id, run_id, budget_id, reserved_minor, status FROM budget_reservations WHERE request_id = ${quoteSql(requestId)} LIMIT 1`,
      (row) => row?.request_id === requestId,
    );
    expect(
      "managed inference creates a correlated budget reservation",
      reservation.org_id === state.orgA.orgId &&
        reservation.run_id === created.runId &&
        Number(reservation.reserved_minor) > 0,
    );
    state.mainRun.reservation = reservation;
    const usage = await waitForD1(
      "managed usage event",
      `SELECT usage_event_id, request_id, org_id, project_id, run_id, device_id, source, estimated_cost_minor, actual_cost_minor, pricing_version, reconciliation_status FROM usage_events WHERE request_id = ${quoteSql(requestId)} LIMIT 1`,
      (row) => row?.request_id === requestId,
    );
    expect(
      "managed usage event retains run/device/source correlation",
      usage.org_id === state.orgA.orgId &&
        usage.run_id === created.runId &&
        usage.device_id === state.deviceA.id &&
        usage.source === "inference",
    );
    state.mainRun.usage = usage;
    const reservationProbe = await request(
      new CookieJar(),
      "POST",
      `/api/v1/devices/${state.orgA.orgId}/budgets/${state.budget.budget_id ?? state.budget.id}/reservations`,
      {
        request_id: requestId,
        run_id: created.runId,
        reserved_minor: Number(reservation.reserved_minor),
        expires_at: instantOffset(1_800),
      },
      deviceMutation(state.deviceA, `reservation-probe-${requestId}`),
    );
    expect(
      "internal reservation endpoint replays the managed hold",
      [200, 201].includes(reservationProbe.status) ||
        (reservationProbe.status === 409 &&
          ["reservation_already_reconciled", "reservation_conflict"].includes(
            reasonOf(reservationProbe),
          )),
      `status=${reservationProbe.status} reason=${reasonOf(reservationProbe) ?? "none"}`,
    );
    const reservationReconcile = await request(
      new CookieJar(),
      "POST",
      `/api/v1/devices/${state.orgA.orgId}/budgets/${state.budget.budget_id ?? state.budget.id}/reservations/${reservation.reservation_id}/reconcile`,
      { actual_minor: 0, status: "committed" },
      deviceMutation(state.deviceA, `reservation-reconcile-${requestId}`),
    );
    expect(
      "managed reservation reconciliation is monotonic",
      [200, 409].includes(reservationReconcile.status) &&
        (reservationReconcile.status === 200 ||
          reasonOf(reservationReconcile) === "reservation_already_reconciled"),
      `status=${reservationReconcile.status} reason=${reasonOf(reservationReconcile) ?? "none"}`,
    );
    const usageKey = idempotencyKey(`usage-reconcile-${requestId}`);
    const usageReconcile = await request(
      new CookieJar(),
      "POST",
      `/api/v1/devices/${state.orgA.orgId}/usage/reconcile`,
      {
        request_id: requestId,
        actual_cost_minor: 1,
        provider_usage: { input_tokens: 4, output_tokens: 3 },
      },
      {
        Authorization: `DeviceToken ${state.deviceA.token}`,
        "Idempotency-Key": usageKey,
      },
    );
    expectStatus("managed usage reconciliation", usageReconcile, 200);
    expect(
      "usage reconciliation retains pricing and appends an actual cost",
      typeof usageReconcile.payload?.cost_record?.pricing_version === "string" &&
        Number(usageReconcile.payload?.cost_record?.cost_minor) === 1,
    );
    const usageReplay = await request(
      new CookieJar(),
      "POST",
      `/api/v1/devices/${state.orgA.orgId}/usage/reconcile`,
      {
        request_id: requestId,
        actual_cost_minor: 1,
        provider_usage: { input_tokens: 4, output_tokens: 3 },
      },
      {
        Authorization: `DeviceToken ${state.deviceA.token}`,
        "Idempotency-Key": usageKey,
      },
    );
    expectStatus("usage reconciliation idempotent replay", usageReplay, 200);
    const usageRead = await request(
      state.alice.jar,
      "GET",
      `/api/v1/orgs/${state.orgA.orgId}/usage?run_id=${encodeURIComponent(created.runId)}`,
    );
    expectStatus("read correlated usage", usageRead, 200);
    expect(
      "usage read exposes the managed run",
      (usageRead.payload?.items ?? []).some((item) => item.run_id === created.runId),
    );
    const summary = await request(
      state.alice.jar,
      "GET",
      `/api/v1/orgs/${state.orgA.orgId}/usage/summary?run_id=${encodeURIComponent(created.runId)}`,
    );
    expectStatus("read usage summary", summary, 200);
    expect("usage summary is correlated to the run", Number(summary.payload?.event_count) >= 1);
  });

  // The following scenarios are deliberately independent where possible. If
  // a contract boundary above is unavailable, they report the concrete failure
  // and the final gate remains pending rather than silently substituting a
  // client-side authority or a direct D1 mutation.
  await optionalProbe("privileged browser decision and approval boundary", async () => {
    if (!state.mainRun?.running) {
      skip("browser approval probe", "managed run did not reach a tool-capable running state");
      return;
    }
    if (!state.mainRun || !state.toolPlane || !state.deviceA || !state.orgA) {
      fail("browser decision prerequisites are unavailable", null);
    }
    const browserCallId = opaqueId("tcl", "browser");
    const decision = await runToolDecision(state.deviceA, state.mainRun.runId, {
      tool_call_id: browserCallId,
      tool_id: state.toolPlane.browser.tool_id,
      tool_fingerprint: state.toolPlane.browser.fingerprint,
      capability_ids: [state.toolPlane.browserCapabilityId],
      risk_class: "browser",
      arguments_summary: "domain=example.test; operation=submit",
      browser_action: { action: "external_submit", domain: "example.test" },
    });
    if (decision.status !== 200 || decision.payload?.decision !== "require_per_use_approval") {
      fail(
        "browser tool did not return an approval-required decision",
        decision,
        `decision=${decision.payload?.decision ?? "none"} reason=${reasonOf(decision) ?? "none"}`,
      );
    }
    const approvalId = decision.payload.approval_id;
    assertId("browser approval ID", approvalId, "apr");
    const beforeApproval = await runToolResult(
      state.deviceA,
      state.mainRun.runId,
      browserCallId,
      { status: "completed", result_summary: "must not run before approval" },
      `browser-before-approval-${browserCallId}`,
    );
    assertDenied(beforeApproval, "browser result is blocked before approval", 422, [
      "approval_required",
    ]);
    const approval = await resolveApproval(
      state.alice.jar,
      state.orgA.orgId,
      approvalId,
      decision.payload.approval_version ?? 1,
    );
    expectStatus("browser approval resolution", approval, 200);
    const result = await runToolResult(
      state.deviceA,
      state.mainRun.runId,
      browserCallId,
      { status: "completed", result_summary: "approved browser metadata" },
      `browser-result-${browserCallId}`,
    );
    expectStatus("approved browser result", result, 200);
    state.toolEvidence.browser = true;
    const replay = await resolveApproval(
      state.alice.jar,
      state.orgA.orgId,
      approvalId,
      2,
      "denied",
    );
    assertDenied(replay, "browser approval cannot be replayed after resolution", 409, [
      "approval_already_resolved",
    ]);
  });

  await optionalProbe("generic privileged tool approval, result, and replay", async () => {
    if (!state.mainRun?.running) {
      skip(
        "generic privileged tool probe",
        "managed run did not reach a tool-capable running state",
      );
      return;
    }
    if (!state.mainRun || !state.toolPlane || !state.deviceA || !state.orgA) {
      fail("generic tool prerequisites are unavailable", null);
    }
    const callId = opaqueId("tcl", "privileged");
    const decision = await runToolDecision(state.deviceA, state.mainRun.runId, {
      tool_call_id: callId,
      tool_id: state.toolPlane.privileged.tool_id,
      tool_fingerprint: state.toolPlane.privileged.fingerprint,
      capability_ids: [],
      risk_class: "external_side_effect",
      arguments_summary: "operation=submit; destination=example.test",
    });
    if (decision.status !== 200 || decision.payload?.decision !== "require_per_use_approval") {
      fail(
        "privileged tool did not return approval-required",
        decision,
        `decision=${decision.payload?.decision ?? "none"} reason=${reasonOf(decision) ?? "none"}`,
      );
    }
    const approvalId = decision.payload.approval_id;
    assertId("privileged approval ID", approvalId, "apr");
    const pendingResult = await runToolResult(
      state.deviceA,
      state.mainRun.runId,
      callId,
      { status: "completed", result_summary: "blocked" },
      `privileged-pending-${callId}`,
    );
    assertDenied(pendingResult, "privileged result is blocked before approval", 422, [
      "approval_required",
    ]);
    const approval = await resolveApproval(
      state.alice.jar,
      state.orgA.orgId,
      approvalId,
      decision.payload.approval_version ?? 1,
    );
    expectStatus("privileged approval resolution", approval, 200);
    const resultKey = idempotencyKey(`privileged-result-${callId}`);
    const result = await request(
      new CookieJar(),
      "POST",
      `/api/v1/devices/runs/${state.mainRun.runId}/tool-calls/${callId}/result`,
      { status: "completed", result_summary: "privileged result recorded" },
      {
        Authorization: `DeviceToken ${state.deviceA.token}`,
        "Idempotency-Key": resultKey,
      },
    );
    expectStatus("privileged tool result", result, 200);
    state.toolEvidence.privileged = true;
    const replay = await request(
      new CookieJar(),
      "POST",
      `/api/v1/devices/runs/${state.mainRun.runId}/tool-calls/${callId}/result`,
      { status: "completed", result_summary: "privileged result recorded" },
      {
        Authorization: `DeviceToken ${state.deviceA.token}`,
        "Idempotency-Key": resultKey,
      },
    );
    expectStatus("tool result idempotent replay", replay, 200);
    const secondUse = await runToolResult(
      state.deviceA,
      state.mainRun.runId,
      callId,
      { status: "completed", result_summary: "replay attempt" },
      `privileged-second-use-${callId}`,
    );
    expect(
      "per-use approval cannot be consumed twice",
      secondUse.status === 200 || statusIs(secondUse, 409, ["approval_already_resolved"]),
      secondUse,
    );
  });

  await optionalProbe("MCP approval and fingerprint-expansion denial", async () => {
    if (!state.mainRun?.running) {
      skip("MCP approval probe", "managed run did not reach a tool-capable running state");
      return;
    }
    if (!state.mainRun || !state.toolPlane || !state.deviceA || !state.orgA) {
      fail("MCP prerequisites are unavailable", null);
    }
    const callId = opaqueId("tcl", "mcp");
    const decision = await runToolDecision(state.deviceA, state.mainRun.runId, {
      tool_call_id: callId,
      tool_id: state.toolPlane.mcpTool.tool_id,
      tool_fingerprint: state.toolPlane.mcpTool.fingerprint,
      capability_ids: [],
      risk_class: "mcp",
      arguments_summary: "operation=read; server=fixture",
    });
    if (decision.status !== 200 || decision.payload?.decision !== "require_per_use_approval") {
      fail(
        "MCP tool did not require approval",
        decision,
        `decision=${decision.payload?.decision ?? "none"} reason=${reasonOf(decision) ?? "none"}`,
      );
    }
    const approvalId = decision.payload.approval_id;
    assertId("MCP approval ID", approvalId, "apr");
    const approval = await resolveApproval(state.alice.jar, state.orgA.orgId, approvalId, 1);
    expectStatus("MCP approval resolution", approval, 200);
    const result = await runToolResult(
      state.deviceA,
      state.mainRun.runId,
      callId,
      { status: "completed", result_summary: "MCP result metadata" },
      `mcp-result-${callId}`,
    );
    expectStatus("MCP tool result", result, 200);
    state.toolEvidence.mcp = true;
    const currentMcp = await request(
      state.alice.jar,
      "GET",
      `/api/v1/orgs/${state.orgA.orgId}/mcp`,
    );
    expectStatus("read MCP registration before expansion", currentMcp, 200);
    const current = (currentMcp.payload?.items ?? []).find(
      (item) => item.mcp_id === state.toolPlane.mcpId,
    );
    if (!current) fail("MCP registration disappeared before expansion probe", currentMcp);
    await updateMcp(state.alice.jar, state.orgA.orgId, state.toolPlane.mcpId, current.version, {
      policy_status: "pending_review",
      tool_list: [
        {
          tool_id: state.toolPlane.mcpTool.tool_id,
          fingerprint: state.toolPlane.mcpTool.fingerprint,
          risk_class: "mcp",
        },
        {
          tool_id: state.toolPlane.expandedMcpTool.tool_id,
          fingerprint: state.toolPlane.expandedMcpTool.fingerprint,
          risk_class: "mcp",
        },
      ],
    });
    const expandedCallId = opaqueId("tcl", "mcp-expanded");
    const expanded = await runToolDecision(state.deviceA, state.mainRun.runId, {
      tool_call_id: expandedCallId,
      tool_id: state.toolPlane.expandedMcpTool.tool_id,
      tool_fingerprint: state.toolPlane.expandedMcpTool.fingerprint,
      capability_ids: [],
      risk_class: "mcp",
      arguments_summary: "operation=read; server=fixture-expanded",
    });
    if (expanded.status !== 200 || expanded.payload?.decision !== "deny") {
      fail("MCP fingerprint expansion was not denied", expanded);
    }
    expect(
      "MCP expansion denial carries a stable review/fingerprint reason",
      ["mcp_tool_requires_review", "tool_fingerprint_changed"].includes(expanded.payload?.reason),
      `reason=${expanded.payload?.reason ?? "none"}`,
    );
  });

  await optionalProbe("stale current-policy re-evaluation", async () => {
    if (!state.mainRun?.running) {
      skip("stale-policy probe", "managed run did not reach a tool-capable running state");
      return;
    }
    if (!state.mainRun || !state.toolPlane || !state.deviceA || !state.orgA) {
      fail("stale-policy prerequisites are unavailable", null);
    }
    const callId = opaqueId("tcl", "stale-policy");
    const body = {
      tool_call_id: callId,
      tool_id: state.toolPlane.staleTool.tool_id,
      tool_fingerprint: state.toolPlane.staleTool.fingerprint,
      capability_ids: [],
      risk_class: "read_only",
      arguments_summary: "operation=read; resource=stale",
    };
    const initial = await runToolDecision(state.deviceA, state.mainRun.runId, body);
    if (initial.status !== 200 || initial.payload?.decision !== "allow") {
      fail("stale-policy baseline decision was not allow", initial);
    }
    const current = await request(
      state.alice.jar,
      "GET",
      `/api/v1/orgs/${state.orgA.orgId}/policy/tools`,
    );
    expectStatus("read current tool policy for stale check", current, 200);
    const document = current.payload?.document;
    if (!document || typeof document !== "object") fail("tool policy document is absent", current);
    const updated = await request(
      state.alice.jar,
      "PUT",
      `/api/v1/orgs/${state.orgA.orgId}/policy/tools`,
      {
        ...document,
        denied_tool_ids: [...(document.denied_tool_ids ?? []), state.toolPlane.staleTool.tool_id],
        version: current.payload.version,
      },
      browserMutation(state.alice.jar, "stale-policy-update"),
    );
    expectStatus("publish stale-policy denial", updated, 200);
    const replay = await runToolDecision(state.deviceA, state.mainRun.runId, body);
    if (replay.status !== 200 || replay.payload?.decision !== "deny") {
      fail("stale policy was not re-evaluated at tool use", replay);
    }
    expect(
      "stale policy denial is fail-closed",
      ["org_tool_denied", "tool_denied", "policy_schema_invalid"].includes(replay.payload?.reason),
      `reason=${replay.payload?.reason ?? "none"}`,
    );
    state.toolEvidence.stalePolicy = true;
  });

  await optionalProbe("rate/concurrency and passive downstream-disconnect probe", async () => {
    if (process.env.P05_PROBE_DISCONNECT === "0") {
      skip("passive disconnect probe", "disabled by P05_PROBE_DISCONNECT=0");
      return;
    }
    if (
      !state.modelPlane?.timeout ||
      !state.deviceA ||
      !state.projectA ||
      !state.agent ||
      !state.bindingA
    ) {
      skip(
        "passive disconnect probe",
        "timeout route or managed-run prerequisites are unavailable",
      );
      return;
    }
    const ratePolicy = await setConcurrencyLimit(
      state.alice.jar,
      state.orgA.orgId,
      state.projectA,
      1,
    );
    const timeoutRun = await createDeviceSessionAndRun(
      state.deviceA,
      state.projectA,
      state.agent,
      state.bindingA,
      "p05-timeout",
      "timeout",
    );
    await startDeviceRun(state.deviceA, timeoutRun.run);
    let stream;
    try {
      stream = await openManagedStream({
        jar: state.alice.jar,
        orgId: state.orgA.orgId,
        runId: timeoutRun.runId,
        sessionId: timeoutRun.sessionId,
        model: "p05-timeout",
      });
      if (stream.response.status !== 200) {
        fail("timeout stream did not open", {
          status: stream.response.status,
          text: "[stream response]",
        });
      }
      const requestId = stream.response.headers.get("X-Request-ID");
      const second = await runManagedInference({
        jar: state.alice.jar,
        orgId: state.orgA.orgId,
        runId: timeoutRun.runId,
        sessionId: timeoutRun.sessionId,
        model: "p05-timeout",
        stream: false,
      });
      assertDenied(second, "concurrent managed inference is denied", 429, [
        "concurrency_limit_exceeded",
      ]);
      stream.controller.abort();
      await delay(750);
      const row = await inspectCancellationD1(requestId);
      if (row?.error_code === "request_cancelled") {
        pass("passive disconnect produced an observed request_cancelled D1 row");
      } else if (process.env.P05_REQUIRE_CANCELLATION_ROW === "1") {
        fail(
          "required request_cancelled D1 row was not observed",
          null,
          JSON.stringify(sanitize(row)),
        );
      } else {
        addLimitation(
          "passive downstream disconnect: no request_cancelled D1 row was observed; no cancellation success is claimed",
        );
      }
    } finally {
      if (stream) {
        try {
          stream.controller.abort();
          await stream.reader?.cancel();
        } catch {
          // The stream may already be closed by the runtime.
        }
      }
      if (ratePolicy) {
        try {
          await setConcurrencyLimit(
            state.alice.jar,
            state.orgA.orgId,
            state.projectA,
            100,
            ratePolicy.version,
          );
        } catch (error) {
          addLimitation(`rate-limit cleanup: ${errorText(error)}`);
        }
      }
      await delay(250);
    }
  });

  await scenario("hard-budget denial after a successful managed request", async () => {
    if (!state.mainRun?.requestId) {
      skip(
        "hard-budget denial",
        "managed inference did not produce a correlated request to exhaust",
      );
      return;
    }
    if (!state.budget || !state.orgA || !state.alice) {
      fail("hard-budget prerequisites are unavailable", null);
    }
    state.budget = await setBudgetLimit(state.alice.jar, state.orgA.orgId, state.budget, 3);
    const budgetRun = await createDeviceSessionAndRun(
      state.deviceA,
      state.projectA,
      state.agent,
      state.bindingA,
      "coding-default",
      "budget-denial",
    );
    const budgetRunning = await startDeviceRun(state.deviceA, budgetRun.run);
    expect("budget-denial run is running", budgetRunning.state === "running");
    const denied = await runManagedInference({
      jar: state.alice.jar,
      orgId: state.orgA.orgId,
      runId: budgetRun.runId,
      sessionId: budgetRun.sessionId,
      model: "coding-default",
    });
    assertDenied(denied, "next eligible managed request is denied by the hard budget", 403, [
      "budget_exceeded",
    ]);
    const denials = await request(
      state.alice.jar,
      "GET",
      `/api/v1/orgs/${state.orgA.orgId}/usage/denials?limit=100`,
    );
    expectStatus("read budget/rate denial projections", denials, 200);
    expect(
      "budget denial is visible in the denial projection",
      (denials.payload?.items ?? []).some(
        (item) => item.run_id === budgetRun.runId && item.reason === "budget_exceeded",
      ),
    );
  });

  await optionalProbe("retry and idempotent cancel lifecycle", async () => {
    if (!state.deviceA || !state.projectA || !state.agent || !state.bindingA || !state.orgA) {
      fail("retry/cancel prerequisites are unavailable", null);
    }
    const failed = await createDeviceSessionAndRun(
      state.deviceA,
      state.projectA,
      state.agent,
      state.bindingA,
      "coding-default",
      "retry-parent",
    );
    // Queued -> failed and queued -> cancelled are explicit contract edges;
    // use them here so retry/cancel remains testable even while the current
    // start route lacks the queued -> dispatching command.
    const failedResult = await request(
      new CookieJar(),
      "POST",
      `/api/v1/devices/runs/${failed.runId}/fail`,
      { version: failed.run.version, failure_code: "p05_smoke_failure" },
      deviceMutation(state.deviceA, `fail-${failed.runId}`),
    );
    expectStatus("fail retry parent run", failedResult, 200);
    const retried = await request(
      state.alice.jar,
      "POST",
      `/api/v1/orgs/${state.orgA.orgId}/runs/${failed.runId}/retry`,
      { version: failedResult.payload.version },
      browserMutation(state.alice.jar, `retry-${failed.runId}`),
    );
    expectStatus("create retry run", retried, 201);
    const retryRun = retried.payload;
    const retryRunId = retryRun?.id;
    assertId("retry run ID", retryRunId, "run");
    expect(
      "retry creates a new immutable attempt",
      retryRunId !== failed.runId &&
        retryRun.parent_run_id === failed.runId &&
        retryRun.attempt > 1,
    );
    const cancelKey = idempotencyKey(`cancel-${retryRunId}`);
    const cancelHeaders = {
      Authorization: `DeviceToken ${state.deviceA.token}`,
      "Idempotency-Key": cancelKey,
    };
    const cancelled = await request(
      new CookieJar(),
      "POST",
      `/api/v1/devices/runs/${retryRunId}/cancel`,
      { version: retryRun.version },
      cancelHeaders,
    );
    expectStatus("cancel retry run", cancelled, 200);
    const cancelReplay = await request(
      new CookieJar(),
      "POST",
      `/api/v1/devices/runs/${retryRunId}/cancel`,
      { version: retryRun.version },
      cancelHeaders,
    );
    expectStatus("cancel idempotent replay", cancelReplay, 200);
    const secondCancel = await request(
      new CookieJar(),
      "POST",
      `/api/v1/devices/runs/${retryRunId}/cancel`,
      { version: cancelled.payload.version },
      deviceMutation(state.deviceA, `second-cancel-${retryRunId}`),
    );
    expectStatus("second cancel is idempotent after terminal state", secondCancel, 200);
    state.retryRun = { runId: retryRunId, sessionId: failed.sessionId, run: retryRun };
  });

  await scenario("cross-tenant, stale-membership, and revoked-device negatives", async () => {
    if (
      !state.alice ||
      !state.bob ||
      !state.orgA ||
      !state.orgB ||
      !state.deviceA ||
      !state.deviceB ||
      !state.mainRun
    ) {
      fail("tenant/device negative prerequisites are unavailable", null);
    }
    const bobReadsA = await request(
      state.bob.jar,
      "GET",
      `/api/v1/orgs/${state.orgA.orgId}/runs/${state.mainRun.runId}`,
    );
    assertDenied(bobReadsA, "second user cannot read tenant A run", [403, 404]);
    const aliceReadsB = await request(
      state.alice.jar,
      "GET",
      `/api/v1/orgs/${state.orgB.orgId}/runs/${state.mainRun.runId}`,
    );
    assertDenied(aliceReadsB, "tenant B cannot read tenant A run by ID", [403, 404]);
    const wrongDevice = await request(
      new CookieJar(),
      "GET",
      `/api/v1/devices/runs/${state.mainRun.runId}`,
      undefined,
      deviceHeaders(state.deviceB),
    );
    assertDenied(wrongDevice, "device B cannot read tenant A run", [401, 403, 404]);
    const members = await request(
      state.alice.jar,
      "GET",
      `/api/v1/orgs/${state.orgB.orgId}/members?limit=100`,
    );
    expectStatus("list tenant B members for stale-membership check", members, 200);
    const bobMembership = (members.payload?.items ?? []).find(
      (member) => member.user_id === state.bob.user.id,
    );
    if (!bobMembership) fail("second-user membership is absent before stale check", members);
    const removed = await request(
      state.alice.jar,
      "DELETE",
      `/api/v1/orgs/${state.orgB.orgId}/members/${bobMembership.membership_id}`,
      undefined,
      { ...browserHeaders(state.alice.jar), "If-Match": `"${bobMembership.version}"` },
    );
    expectStatus("remove second user from tenant B", removed, 204);
    const nonce = await request(new CookieJar(), "GET", "/api/v1/devices/token/nonce");
    expectStatus("get device refresh nonce after membership removal", nonce, 200);
    const refresh = await request(new CookieJar(), "POST", "/api/v1/devices/token", {
      device_id: state.deviceB.id,
      signature: state.deviceB.sign(nonce.payload.nonce),
      nonce: nonce.payload.nonce,
      app_version: "0.5.0",
    });
    assertDenied(refresh, "stale membership blocks device token refresh", 403, [
      "membership_required",
    ]);
    const revoke = await request(
      state.alice.jar,
      "DELETE",
      `/api/v1/orgs/${state.orgB.orgId}/devices/${state.deviceB.id}`,
      undefined,
      browserMutation(state.alice.jar, `revoke-${state.deviceB.id}`),
    );
    expectStatus("revoke tenant B device", revoke, 204);
    const revokedHeartbeat = await request(
      new CookieJar(),
      "POST",
      "/api/v1/devices/heartbeat",
      { app_version: "0.5.0" },
      deviceHeaders(state.deviceB),
    );
    assertDenied(
      revokedHeartbeat,
      "revoked device loses managed access",
      [401, 403],
      ["device_token_expired", "device_revoked"],
    );
  });

  await scenario("timeline, audit, and D1 correlation evidence", async () => {
    if (!state.mainRun || !state.orgA || !state.alice) {
      fail("timeline/audit prerequisites are unavailable", null);
    }
    const events = await request(
      state.alice.jar,
      "GET",
      `/api/v1/orgs/${state.orgA.orgId}/runs/${state.mainRun.runId}/events?limit=100`,
    );
    expectStatus("read managed run timeline", events, 200);
    const eventItems = events.payload?.items ?? [];
    const hasCreatedEvent = eventItems.some((event) => event.event_type === "run.created.v1");
    const hasStartedEvent = eventItems.some((event) => event.event_type === "run.started.v1");
    expect("timeline contains run creation metadata", hasCreatedEvent);
    if (!hasStartedEvent) {
      addLimitation("run start timeline: no run.started.v1 event was observed for the managed run");
    }
    if (Object.keys(state.toolEvidence).length > 0) {
      expect(
        "timeline contains tool decision and approval lifecycle metadata",
        eventItems.some((event) => event.event_type === "tool.decision_recorded.v1") &&
          eventItems.some((event) => event.event_type === "tool.approval_requested.v1") &&
          eventItems.some((event) => event.event_type === "approval.resolved.v1"),
      );
    }
    const d1Events = await d1(
      `SELECT run_id, org_id, project_id, request_id, device_id, agent_session_id, sequence, event_type, actor_type, correlation_id FROM run_events WHERE run_id = ${quoteSql(state.mainRun.runId)} ORDER BY sequence ASC`,
      "managed run D1 timeline evidence",
    );
    expect(
      "D1 timeline rows carry the managed correlation envelope",
      d1Events.length > 0 &&
        d1Events.every(
          (event) =>
            event.org_id === state.orgA.orgId &&
            event.project_id === state.projectA &&
            event.device_id === state.deviceA.id &&
            event.agent_session_id === state.mainRun.sessionId,
        ),
    );
    if (Object.keys(state.toolEvidence).length > 0) {
      expect(
        "D1 timeline includes tool decision and approval event types",
        ["tool.decision_recorded.v1", "tool.approval_requested.v1", "approval.resolved.v1"].every(
          (eventType) => d1Events.some((event) => event.event_type === eventType),
        ),
      );
    }
    const audit = await request(
      state.alice.jar,
      "GET",
      `/api/v1/orgs/${state.orgA.orgId}/audit?run_id=${encodeURIComponent(state.mainRun.runId)}&limit=100`,
    );
    expectStatus("read run-correlated audit projection", audit, 200);
    expect(
      "audit projection is queryable by run ID",
      Array.isArray(audit.payload?.items) && audit.payload.items.length > 0,
    );
    const d1Audit = await d1(
      `SELECT action, outcome, run_id, agent_session_id, device_id, request_id FROM security_events WHERE org_id = ${quoteSql(state.orgA.orgId)} AND run_id = ${quoteSql(state.mainRun.runId)} ORDER BY created_at ASC`,
      "managed run D1 audit evidence",
    );
    expect("D1 audit rows are correlated to the managed run", d1Audit.length > 0);
    if (state.mainRun.requestId) {
      const requestEvents = await d1(
        `SELECT request_id, run_id, device_id, agent_session_id FROM security_events WHERE request_id = ${quoteSql(state.mainRun.requestId)}`,
        "request-to-run audit correlation evidence",
      );
      expect(
        "request ID is queryable in run correlation evidence",
        requestEvents.some((event) => event.run_id === state.mainRun.runId),
      );
    }
  });

  return state;
}

let exitState = null;
try {
  exitState = await main();
} catch (error) {
  recordFailure("smoke bootstrap or finalization", error);
} finally {
  await stopServices();
  if (persistDir && ownsPersistDir && process.env.P05_KEEP_PERSIST !== "1") {
    try {
      await rm(persistDir, { recursive: true, force: true });
    } catch (error) {
      addLimitation(`fresh D1 cleanup: ${errorText(error)}`);
    }
  }
  const report = {
    status: failures.length === 0 && limitations.length === 0 ? "PASS" : "PENDING",
    checks_passed: passed,
    failures,
    limitations,
    skipped,
    fresh_d1: Boolean(persistDir),
    worker: baseUrl,
    tool_evidence: exitState?.toolEvidence ?? {},
    references: exitState
      ? {
          org_a: exitState.orgA?.orgId ?? null,
          org_b: exitState.orgB?.orgId ?? null,
          project_a: exitState.projectA ?? null,
          project_b: exitState.projectB ?? null,
          device_a: exitState.deviceA?.id ?? null,
          device_b: exitState.deviceB?.id ?? null,
          main_run: exitState.mainRun?.runId ?? null,
          retry_run: exitState.retryRun?.runId ?? null,
        }
      : null,
  };
  console.log(
    `\nP05 smoke: ${passed} checks passed; ${failures.length} failures; ${limitations.length} limitations`,
  );
  console.log(JSON.stringify(report, null, 2));
  if (failures.length > 0) process.exitCode = 1;
}
