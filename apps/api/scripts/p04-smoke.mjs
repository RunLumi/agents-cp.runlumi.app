import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";

const baseUrl = process.env.P04_API_BASE ?? "http://127.0.0.1:8787";

class CookieJar {
  cookies = new Map();
  absorb(response) {
    const values =
      typeof response.headers.getSetCookie === "function"
        ? response.headers.getSetCookie()
        : [response.headers.get("set-cookie")].filter(Boolean);
    for (const value of values) {
      const [pair] = value.split(";");
      const separator = pair.indexOf("=");
      if (separator > 0) this.cookies.set(pair.slice(0, separator), pair.slice(separator + 1));
    }
  }
  header() {
    return [...this.cookies.entries()].map(([key, value]) => `${key}=${value}`).join("; ");
  }
}

async function request(jar, method, path, body, extraHeaders = {}) {
  const headers = { Accept: "application/json", ...extraHeaders };
  if (body !== undefined) headers["Content-Type"] = "application/json";
  const cookie = jar.header();
  if (cookie) headers.Cookie = cookie;
  const response = await fetch(`${baseUrl}${path}`, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  jar.absorb(response);
  const text = await response.text();
  let payload;
  try {
    payload = text ? JSON.parse(text) : undefined;
  } catch {
    payload = text;
  }
  return { status: response.status, payload, text };
}

async function abortRequest(jar, path, body, extraHeaders = {}) {
  const controller = new AbortController();
  const headers = { Accept: "text/event-stream", ...extraHeaders };
  if (body !== undefined) headers["Content-Type"] = "application/json";
  const cookie = jar.header();
  if (cookie) headers.Cookie = cookie;
  const pending = fetch(`${baseUrl}${path}`, {
    method: "POST",
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
    signal: controller.signal,
  });
  const fallback = setTimeout(() => controller.abort(), 3_000);
  let responseReceived = false;
  let firstChunk = false;
  try {
    const response = await pending;
    responseReceived = true;
    const reader = response.body?.getReader();
    if (reader) {
      firstChunk = Boolean(await reader.read());
    }
    controller.abort();
  } catch {
    // The downstream abort is expected; the server-side finalization is
    // checked in the D1 evidence query after this smoke completes.
  } finally {
    clearTimeout(fallback);
  }
  await new Promise((resolve) => setTimeout(resolve, 500));
  return { responseReceived, firstChunk };
}

async function authenticatedUser(label) {
  const jar = new CookieJar();
  const email = `${label}-${randomUUID().slice(0, 8)}@example.com`;
  let result = await request(jar, "POST", "/api/v1/auth/signup", { email, display_name: label });
  assert.equal(result.status, 201);
  result = await request(jar, "POST", "/api/v1/auth/verify-email", {
    challenge_id: result.payload.verification.challenge_id,
    code: result.payload.verification.development_code,
  });
  assert.equal(result.status, 200);
  result = await request(jar, "POST", "/api/v1/auth/login/start", { email });
  assert.equal(result.status, 202);
  result = await request(jar, "POST", "/api/v1/auth/login/complete", {
    challenge_id: result.payload.challenge_id,
    code: result.payload.development_code,
  });
  assert.equal(result.status, 200);
  return { jar, user: result.payload.user, email };
}

const csrf = (jar) => ({ "X-CSRF-Token": jar.cookies.get("lumi_csrf") });
const mutation = (jar) => ({ ...csrf(jar), "Idempotency-Key": randomUUID() });

const alice = await authenticatedUser("P04 Alice");
const bob = await authenticatedUser("P04 Bob");

let result = await request(
  alice.jar,
  "POST",
  "/api/v1/orgs",
  { display_name: "P04 Smoke Tenant", slug: `p04-smoke-${randomUUID().slice(0, 6)}` },
  mutation(alice.jar),
);
assert.equal(result.status, 201);
const orgId = result.payload.organization.org_id;
const orgHeaders = { "X-Org-ID": orgId };

const catalog = await request(alice.jar, "GET", `/api/v1/orgs/${orgId}/catalog`);
assert.equal(catalog.status, 200);
const failProvider = catalog.payload.providers.find(
  (provider) => provider.provider_key === "mock-fail",
);
const successProvider = catalog.payload.providers.find(
  (provider) => provider.provider_key === "mock-success",
);
const postOutputProvider = catalog.payload.providers.find(
  (provider) => provider.provider_key === "mock-post-output-failure",
);
const timeoutProvider = catalog.payload.providers.find(
  (provider) => provider.provider_key === "mock-timeout",
);
assert.ok(failProvider && successProvider && postOutputProvider && timeoutProvider);
const failModel = catalog.payload.models.find((model) => model.provider_model_id === "mock-fail");
const successModel = catalog.payload.models.find(
  (model) => model.provider_model_id === "mock-success",
);
const postOutputModel = catalog.payload.models.find(
  (model) => model.provider_model_id === "mock-post-output-failure",
);
const timeoutModel = catalog.payload.models.find(
  (model) => model.provider_model_id === "mock-timeout",
);
assert.ok(failModel && successModel && postOutputModel && timeoutModel);

const ssrf = await request(
  alice.jar,
  "POST",
  `/api/v1/orgs/${orgId}/catalog/providers`,
  {
    provider_key: "blocked-endpoint",
    display_name: "Blocked endpoint",
    adapter: "openai_compatible",
    endpoint_url: "https://127.0.0.1/v1",
  },
  mutation(alice.jar),
);
assert.ok([403, 422].includes(ssrf.status));
assert.equal(ssrf.payload.error.details.reason, "ssrf_blocked");

const lifecycleProviderKey = `p04-lifecycle-${randomUUID().slice(0, 8)}`;
const lifecycleCreateKey = mutation(alice.jar);
const lifecycleProvider = await request(
  alice.jar,
  "POST",
  `/api/v1/orgs/${orgId}/catalog/providers`,
  {
    provider_key: lifecycleProviderKey,
    display_name: "Lifecycle provider",
    adapter: "mock",
    endpoint_url: "mock://lumi-success",
  },
  lifecycleCreateKey,
);
assert.equal(lifecycleProvider.status, 201);
const lifecycleProviderReplay = await request(
  alice.jar,
  "POST",
  `/api/v1/orgs/${orgId}/catalog/providers`,
  {
    provider_key: lifecycleProviderKey,
    display_name: "Lifecycle provider",
    adapter: "mock",
    endpoint_url: "mock://lumi-success",
  },
  lifecycleCreateKey,
);
assert.equal(lifecycleProviderReplay.status, 201);
const lifecycleModel = await request(
  alice.jar,
  "POST",
  `/api/v1/orgs/${orgId}/catalog/models`,
  {
    provider_id: lifecycleProvider.payload.provider.provider_id,
    provider_model_id: "lifecycle-success",
    display_name: "Lifecycle model",
    capabilities: ["text"],
    max_input_tokens: 8_000,
    max_output_tokens: 2_000,
  },
  mutation(alice.jar),
);
assert.equal(lifecycleModel.status, 201);
const lifecycleKey = mutation(alice.jar);
const lifecycleUpdate = await request(
  alice.jar,
  "PATCH",
  `/api/v1/orgs/${orgId}/catalog/models/${lifecycleModel.payload.model.model_id}`,
  { lifecycle: "deprecated", version: 1 },
  lifecycleKey,
);
assert.equal(lifecycleUpdate.status, 200);
const lifecycleReplay = await request(
  alice.jar,
  "PATCH",
  `/api/v1/orgs/${orgId}/catalog/models/${lifecycleModel.payload.model.model_id}`,
  { lifecycle: "deprecated", version: 1 },
  lifecycleKey,
);
assert.equal(lifecycleReplay.status, 200);
const lifecycleConflict = await request(
  alice.jar,
  "PATCH",
  `/api/v1/orgs/${orgId}/catalog/models/${lifecycleModel.payload.model.model_id}`,
  { lifecycle: "active", version: 1 },
  lifecycleKey,
);
assert.equal(lifecycleConflict.status, 409);

const failSecret = `p04-fail-secret-${randomUUID()}`;
const successSecret = `p04-success-secret-${randomUUID()}`;
result = await request(
  alice.jar,
  "POST",
  `/api/v1/orgs/${orgId}/credentials`,
  {
    provider_id: failProvider.provider_id,
    owner_type: "organization",
    label: "Fail provider",
    secret: failSecret,
  },
  mutation(alice.jar),
);
assert.equal(result.status, 201);
const failCredential = result.payload.credential;
assert.ok(!result.text.includes(failSecret));
result = await request(
  alice.jar,
  "POST",
  `/api/v1/orgs/${orgId}/credentials`,
  {
    provider_id: successProvider.provider_id,
    owner_type: "organization",
    label: "Success provider",
    secret: successSecret,
  },
  mutation(alice.jar),
);
assert.equal(result.status, 201);
const successCredential = result.payload.credential;
assert.ok(!result.text.includes(successSecret));
const postOutputSecret = `p04-post-output-secret-${randomUUID()}`;
result = await request(
  alice.jar,
  "POST",
  `/api/v1/orgs/${orgId}/credentials`,
  {
    provider_id: postOutputProvider.provider_id,
    owner_type: "organization",
    label: "Post-output provider",
    secret: postOutputSecret,
  },
  mutation(alice.jar),
);
assert.equal(result.status, 201);
const postOutputCredential = result.payload.credential;
assert.ok(!result.text.includes(postOutputSecret));
const localCredential = await request(
  alice.jar,
  "POST",
  `/api/v1/orgs/${orgId}/credentials`,
  {
    provider_id: successProvider.provider_id,
    owner_type: "local_only",
    label: "Local BYOK registration",
  },
  mutation(alice.jar),
);
assert.equal(localCredential.status, 201);
assert.equal(localCredential.payload.credential.org_id, null);
assert.equal(localCredential.payload.credential.has_secret, false);
const credentialList = await request(alice.jar, "GET", `/api/v1/orgs/${orgId}/credentials`);
assert.equal(credentialList.status, 200);
assert.ok(
  !credentialList.payload.items.some(
    (item) => item.credential_id === localCredential.payload.credential.credential_id,
  ),
);

const timeoutSecret = `p04-timeout-secret-${randomUUID()}`;
result = await request(
  alice.jar,
  "POST",
  `/api/v1/orgs/${orgId}/credentials`,
  {
    provider_id: timeoutProvider.provider_id,
    owner_type: "organization",
    label: "Timeout provider",
    secret: timeoutSecret,
  },
  mutation(alice.jar),
);
assert.equal(result.status, 201);
const timeoutCredential = result.payload.credential;
assert.ok(!result.text.includes(timeoutSecret));

const routeConfig = {
  strategy: "ordered_fallback",
  candidates: [
    {
      provider_id: failProvider.provider_id,
      model_id: failModel.model_id,
      weight: 70,
      timeout_ms: 1000,
      max_retries: 1,
      credential_id: failCredential.credential_id,
    },
    {
      provider_id: successProvider.provider_id,
      model_id: successModel.model_id,
      weight: 30,
      timeout_ms: 1000,
      max_retries: 0,
      credential_id: successCredential.credential_id,
    },
  ],
};
const routeCreateKey = mutation(alice.jar);
result = await request(
  alice.jar,
  "POST",
  `/api/v1/orgs/${orgId}/routes`,
  {
    alias: "coding-default",
    display_name: "Coding default",
    strategy: "ordered_fallback",
    config: routeConfig,
  },
  routeCreateKey,
);
assert.equal(result.status, 201);
const route = result.payload.route;
const initialVersion = result.payload.version;
assert.ok(initialVersion);
const routeReplay = await request(
  alice.jar,
  "POST",
  `/api/v1/orgs/${orgId}/routes`,
  {
    alias: "coding-default",
    display_name: "Coding default",
    strategy: "ordered_fallback",
    config: routeConfig,
  },
  routeCreateKey,
);
assert.equal(routeReplay.status, 201);
assert.equal(routeReplay.payload.route.route_id, route.route_id);
const routeConflict = await request(
  alice.jar,
  "POST",
  `/api/v1/orgs/${orgId}/routes`,
  {
    alias: "coding-default",
    display_name: "Different request",
    strategy: "ordered_fallback",
    config: routeConfig,
  },
  routeCreateKey,
);
assert.equal(routeConflict.status, 409);

const publishKey = mutation(alice.jar);
result = await request(
  alice.jar,
  "POST",
  `/api/v1/orgs/${orgId}/routes/${route.route_id}/publish`,
  { version: route.version, config: routeConfig },
  publishKey,
);
assert.equal(result.status, 200);
const publishedVersion = result.payload.version;
const publishedRouteState = result.payload.route;
assert.equal(result.payload.route.active_version_id, publishedVersion.route_version_id);
const publishReplay = await request(
  alice.jar,
  "POST",
  `/api/v1/orgs/${orgId}/routes/${route.route_id}/publish`,
  { version: route.version, config: routeConfig },
  publishKey,
);
assert.equal(publishReplay.status, 200);
assert.equal(publishReplay.payload.version.route_version_id, publishedVersion.route_version_id);
const publishConflict = await request(
  alice.jar,
  "POST",
  `/api/v1/orgs/${orgId}/routes/${route.route_id}/publish`,
  {
    version: route.version,
    config: {
      ...routeConfig,
      candidates: routeConfig.candidates.map((candidate, index) => ({
        ...candidate,
        weight: index === 0 ? 71 : 29,
      })),
    },
  },
  publishKey,
);
assert.equal(publishConflict.status, 409);
const stalePublish = await request(
  alice.jar,
  "POST",
  `/api/v1/orgs/${orgId}/routes/${route.route_id}/publish`,
  { version: route.version, config: routeConfig },
  mutation(alice.jar),
);
assert.equal(stalePublish.status, 409);

const inference = await request(
  alice.jar,
  "POST",
  "/api/v1/inference/responses",
  {
    model: "coding-default",
    messages: [{ role: "user", content: [{ type: "text", text: "Say hello" }] }],
    required_capabilities: ["text"],
    stream: true,
  },
  { ...orgHeaders, ...csrf(alice.jar) },
);
assert.equal(inference.status, 200);
assert.match(inference.text, /response\.started/);
assert.match(inference.text, /Hello/);
assert.match(inference.text, /from Lumi/);
assert.match(inference.text, /response\.completed/);
assert.ok(!inference.text.includes(failSecret));
assert.ok(!inference.text.includes(successSecret));

const chat = await request(
  alice.jar,
  "POST",
  "/api/v1/inference/chat/completions",
  {
    model: "coding-default",
    messages: [{ role: "user", content: "Say hello" }],
    stream: false,
  },
  { ...orgHeaders, ...csrf(alice.jar) },
);
assert.equal(chat.status, 200);
assert.match(chat.text, /Hello from Lumi/);
const invalidChat = await request(
  alice.jar,
  "POST",
  "/api/v1/inference/chat/completions",
  {
    model: "coding-default",
    messages: [{ role: "user", content: "hello" }],
    max_tokens: 8,
    max_completion_tokens: 8,
  },
  { ...orgHeaders, ...csrf(alice.jar) },
);
assert.equal(invalidChat.status, 422);
assert.equal(invalidChat.payload.error.details.reason, "max_tokens_invalid");
const invalidTools = await request(
  alice.jar,
  "POST",
  "/api/v1/inference/chat/completions",
  {
    model: "coding-default",
    messages: [{ role: "user", content: "hello" }],
    tools: [{ type: "function", function: { name: "bad", parameters: "not-an-object" } }],
  },
  { ...orgHeaders, ...csrf(alice.jar) },
);
assert.equal(invalidTools.status, 422);
assert.equal(invalidTools.payload.error.details.reason, "tools_invalid");
assert.ok(!chat.text.includes(successSecret));

const usage = await request(alice.jar, "GET", `/api/v1/orgs/${orgId}/usage`, undefined, orgHeaders);
assert.equal(usage.status, 200);
assert.ok(usage.payload.items.length >= 1);
const usageEvent = usage.payload.items[0];
assert.equal(usageEvent.model_alias, "coding-default");
assert.equal(usageEvent.provider_id, successProvider.provider_id);
assert.equal(usageEvent.input_tokens, 4);
assert.equal(usageEvent.output_tokens, 3);

const postOutputRouteConfig = {
  strategy: "ordered_fallback",
  candidates: [
    {
      provider_id: postOutputProvider.provider_id,
      model_id: postOutputModel.model_id,
      weight: 70,
      timeout_ms: 1000,
      max_retries: 1,
      credential_id: postOutputCredential.credential_id,
    },
    {
      provider_id: successProvider.provider_id,
      model_id: successModel.model_id,
      weight: 30,
      timeout_ms: 1000,
      max_retries: 0,
      credential_id: successCredential.credential_id,
    },
  ],
};
result = await request(
  alice.jar,
  "POST",
  `/api/v1/orgs/${orgId}/routes`,
  {
    alias: "post-output-failure",
    display_name: "Post-output failure",
    strategy: "ordered_fallback",
    config: postOutputRouteConfig,
  },
  mutation(alice.jar),
);
assert.equal(result.status, 201);
const postOutputRoute = result.payload.route;
result = await request(
  alice.jar,
  "POST",
  `/api/v1/orgs/${orgId}/routes/${postOutputRoute.route_id}/publish`,
  { version: postOutputRoute.version, config: postOutputRouteConfig },
  mutation(alice.jar),
);
assert.equal(result.status, 200);
const committedFailure = await request(
  alice.jar,
  "POST",
  "/api/v1/inference/responses",
  {
    model: "post-output-failure",
    messages: [{ role: "user", content: [{ type: "text", text: "stream this" }] }],
    stream: true,
  },
  { ...orgHeaders, ...csrf(alice.jar) },
);
assert.equal(committedFailure.status, 200);
assert.match(committedFailure.text, /partial output/);
assert.match(committedFailure.text, /upstream_invalid_response/);
assert.equal((committedFailure.text.match(/event: error/g) ?? []).length, 1);
assert.ok(!committedFailure.text.includes("Hello from Lumi."));
assert.ok(!committedFailure.text.includes("response.completed"));

const timeoutRouteConfig = {
  strategy: "fixed",
  candidates: [
    {
      provider_id: timeoutProvider.provider_id,
      model_id: timeoutModel.model_id,
      weight: 100,
      timeout_ms: 1_000,
      max_retries: 0,
      credential_id: timeoutCredential.credential_id,
    },
  ],
};
result = await request(
  alice.jar,
  "POST",
  `/api/v1/orgs/${orgId}/routes`,
  {
    alias: "timeout-fixture",
    display_name: "Timeout fixture",
    strategy: "fixed",
    config: timeoutRouteConfig,
  },
  mutation(alice.jar),
);
assert.equal(result.status, 201);
const timeoutRoute = result.payload.route;
result = await request(
  alice.jar,
  "POST",
  `/api/v1/orgs/${orgId}/routes/${timeoutRoute.route_id}/publish`,
  { version: timeoutRoute.version, config: timeoutRouteConfig },
  mutation(alice.jar),
);
assert.equal(result.status, 200);
const timeoutAttempt = await request(
  alice.jar,
  "POST",
  "/api/v1/inference/responses",
  {
    model: "timeout-fixture",
    messages: [{ role: "user", content: [{ type: "text", text: "wait" }] }],
    stream: false,
  },
  { ...orgHeaders, ...csrf(alice.jar) },
);
assert.equal(timeoutAttempt.status, 503);
assert.equal(timeoutAttempt.payload.error.details.reason, "request_timeout");
const callerAbort = await abortRequest(
  alice.jar,
  "/api/v1/inference/responses",
  {
    model: "timeout-fixture",
    messages: [{ role: "user", content: [{ type: "text", text: "cancel" }] }],
    stream: true,
  },
  { ...orgHeaders, ...csrf(alice.jar) },
);

const revokedRouteConfig = {
  strategy: "fixed",
  candidates: [
    {
      provider_id: successProvider.provider_id,
      model_id: successModel.model_id,
      weight: 100,
      timeout_ms: 1000,
      max_retries: 0,
      credential_id: successCredential.credential_id,
    },
  ],
};
result = await request(
  alice.jar,
  "POST",
  `/api/v1/orgs/${orgId}/routes`,
  {
    alias: "coding-fast",
    display_name: "Revoked credential",
    strategy: "fixed",
    config: revokedRouteConfig,
  },
  mutation(alice.jar),
);
assert.equal(result.status, 201);
const revokedRoute = result.payload.route;
result = await request(
  alice.jar,
  "POST",
  `/api/v1/orgs/${orgId}/routes/${revokedRoute.route_id}/publish`,
  { version: revokedRoute.version, config: revokedRouteConfig },
  mutation(alice.jar),
);
assert.equal(result.status, 200);
const revokeKey = mutation(alice.jar);
result = await request(
  alice.jar,
  "POST",
  `/api/v1/orgs/${orgId}/credentials/${successCredential.credential_id}/revoke`,
  { version: successCredential.version },
  revokeKey,
);
assert.equal(result.status, 200);
const revokeReplay = await request(
  alice.jar,
  "POST",
  `/api/v1/orgs/${orgId}/credentials/${successCredential.credential_id}/revoke`,
  { version: successCredential.version },
  revokeKey,
);
assert.equal(revokeReplay.status, 200);
const revokedAttempt = await request(
  alice.jar,
  "POST",
  "/api/v1/inference/responses",
  {
    model: "coding-fast",
    messages: [{ role: "user", content: [{ type: "text", text: "must not use" }] }],
    stream: false,
  },
  { ...orgHeaders, ...csrf(alice.jar) },
);
assert.ok([403, 503].includes(revokedAttempt.status));
assert.equal(revokedAttempt.payload.error.details.reason, "credential_unavailable");
assert.ok(!revokedAttempt.text.includes(successSecret));

// A second immutable version proves rollback does not rewrite history.
const changedConfig = {
  ...routeConfig,
  candidates: [{ ...routeConfig.candidates[1], credential_id: postOutputCredential.credential_id }],
};
result = await request(
  alice.jar,
  "POST",
  `/api/v1/orgs/${orgId}/routes/${route.route_id}/publish`,
  { version: publishedRouteState.version, config: changedConfig },
  mutation(alice.jar),
);
assert.equal(result.status, 200);
const secondVersion = result.payload.version;
assert.ok(secondVersion.version > publishedVersion.version);
const rollbackKey = mutation(alice.jar);
result = await request(
  alice.jar,
  "POST",
  `/api/v1/orgs/${orgId}/routes/${route.route_id}/rollback`,
  { version: publishedVersion.version },
  rollbackKey,
);
assert.equal(result.status, 200);
assert.equal(result.payload.route.active_version_id, publishedVersion.route_version_id);
const rollbackReplay = await request(
  alice.jar,
  "POST",
  `/api/v1/orgs/${orgId}/routes/${route.route_id}/rollback`,
  { version: publishedVersion.version },
  rollbackKey,
);
assert.equal(rollbackReplay.status, 200);
const rollbackConflict = await request(
  alice.jar,
  "POST",
  `/api/v1/orgs/${orgId}/routes/${route.route_id}/rollback`,
  { version: secondVersion.version },
  rollbackKey,
);
assert.equal(rollbackConflict.status, 409);

const history = await request(
  alice.jar,
  "GET",
  `/api/v1/orgs/${orgId}/routes/${route.route_id}/history`,
  undefined,
  orgHeaders,
);
assert.equal(history.status, 200);
assert.ok(history.payload.items.some((item) => item.version === publishedVersion.version));
assert.ok(history.payload.items.some((item) => item.version === secondVersion.version));

const defaultPolicy = await request(
  alice.jar,
  "GET",
  `/api/v1/orgs/${orgId}/policy`,
  undefined,
  orgHeaders,
);
assert.equal(defaultPolicy.status, 200);
assert.equal(defaultPolicy.payload.version, 0);
assert.equal(defaultPolicy.payload.allowed_aliases, null);
const policyInput = {
  allowed_aliases: ["coding-default", "coding-fast"],
  allowed_models: [failModel.model_id, successModel.model_id, postOutputModel.model_id],
  allowed_providers: [
    failProvider.provider_id,
    successProvider.provider_id,
    postOutputProvider.provider_id,
  ],
  credential_mode: "organization_only",
  managed_route_enabled: true,
  version: defaultPolicy.payload.version,
};
const policyKey = mutation(alice.jar);
const policy = await request(alice.jar, "PUT", `/api/v1/orgs/${orgId}/policy`, policyInput, {
  ...orgHeaders,
  ...policyKey,
});
assert.equal(policy.status, 200);
assert.equal(policy.payload.credential_mode, "organization_only");
const policyReplay = await request(alice.jar, "PUT", `/api/v1/orgs/${orgId}/policy`, policyInput, {
  ...orgHeaders,
  ...policyKey,
});
assert.equal(policyReplay.status, 200);
const policyConflict = await request(
  alice.jar,
  "PUT",
  `/api/v1/orgs/${orgId}/policy`,
  { ...policyInput, managed_route_enabled: false },
  { ...orgHeaders, ...policyKey },
);
assert.equal(policyConflict.status, 409);

// Cross-tenant credential and route access is indistinguishable from absence.
const foreignRoute = await request(
  bob.jar,
  "GET",
  "/api/v1/inference/routes/coding-default",
  undefined,
  orgHeaders,
);
assert.ok([403, 404].includes(foreignRoute.status));
const foreignInference = await request(
  bob.jar,
  "POST",
  "/api/v1/inference/responses",
  {
    model: "coding-default",
    messages: [{ role: "user", content: [{ type: "text", text: "no" }] }],
  },
  { ...orgHeaders, ...csrf(bob.jar) },
);
assert.ok([403, 404].includes(foreignInference.status));
const unsupported = await request(
  alice.jar,
  "POST",
  "/api/v1/inference/responses",
  {
    model: "coding-default",
    messages: [{ role: "user", content: [{ type: "text", text: "vision please" }] }],
    required_capabilities: ["vision"],
    stream: false,
  },
  { ...orgHeaders, ...csrf(alice.jar) },
);
assert.ok([403, 404, 503].includes(unsupported.status));
assert.equal(unsupported.payload.error.details.reason, "unsupported_capability");

if (process.env.P04_DEBUG_SESSION) {
  const { writeFile } = await import("node:fs/promises");
  await writeFile(
    process.env.P04_DEBUG_SESSION,
    JSON.stringify({
      org_id: orgId,
      cookies: Object.fromEntries(alice.jar.cookies),
      route_id: timeoutRoute.route_id,
      alias: "timeout-fixture",
    }),
  );
}

console.log(
  JSON.stringify({
    ok: true,
    org_id: orgId,
    route_id: route.route_id,
    usage_events: usage.payload.items.length,
    caller_abort_attempted: callerAbort,
  }),
);
