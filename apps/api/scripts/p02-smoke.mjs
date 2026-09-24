import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";

const baseUrl = process.env.P02_API_BASE ?? "http://127.0.0.1:8787";

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
  return { status: response.status, payload };
}

async function authenticatedUser(label) {
  const jar = new CookieJar();
  const email = `${label}-${randomUUID().slice(0, 8)}@example.com`;
  let result = await request(jar, "POST", "/api/v1/auth/signup", { email, display_name: label });
  assert.equal(result.status, 201);
  const verification = result.payload.verification;
  result = await request(jar, "POST", "/api/v1/auth/verify-email", {
    challenge_id: verification.challenge_id,
    code: verification.development_code,
  });
  assert.equal(result.status, 200);
  result = await request(jar, "POST", "/api/v1/auth/login/start", { email });
  assert.equal(result.status, 202);
  result = await request(jar, "POST", "/api/v1/auth/login/complete", {
    challenge_id: result.payload.challenge_id,
    code: result.payload.development_code,
  });
  assert.equal(result.status, 200);
  return { jar, user: result.payload.user };
}

const alice = await authenticatedUser("P02 Alice");
const bob = await authenticatedUser("P02 Bob");
const csrf = (jar) => ({
  "X-CSRF-Token": jar.cookies.get("lumi_csrf"),
  "Idempotency-Key": randomUUID(),
});

const createIdempotencyKey = randomUUID();
const createBody = {
  display_name: "P02 Smoke Tenant",
  slug: `p02-smoke-${randomUUID().slice(0, 6)}`,
};
let result = await request(alice.jar, "POST", "/api/v1/orgs", createBody, {
  "X-CSRF-Token": alice.jar.cookies.get("lumi_csrf"),
  "Idempotency-Key": createIdempotencyKey,
});
assert.equal(result.status, 201);
const orgId = result.payload.organization.org_id;
const ownerMembershipId = result.payload.membership.membership_id;
result = await request(
  alice.jar,
  "PATCH",
  `/api/v1/orgs/${orgId}/members/${ownerMembershipId}`,
  { role: "viewer", version: 1 },
  { "X-CSRF-Token": alice.jar.cookies.get("lumi_csrf") },
);
assert.equal(result.status, 409);
assert.equal(result.payload.error.details.reason, "last_owner_required");
result = await request(alice.jar, "POST", "/api/v1/orgs", createBody, {
  "X-CSRF-Token": alice.jar.cookies.get("lumi_csrf"),
  "Idempotency-Key": createIdempotencyKey,
});
assert.equal(result.status, 200);

const lifecycleGrant = await request(
  alice.jar,
  "POST",
  "/api/v1/account/reauth",
  { purpose: "org_lifecycle" },
  { "X-CSRF-Token": alice.jar.cookies.get("lumi_csrf") },
);
assert.equal(lifecycleGrant.status, 201);
result = await request(
  alice.jar,
  "POST",
  `/api/v1/orgs/${orgId}/suspend`,
  {
    version: 1,
    reauth_grant_id: lifecycleGrant.payload.grant_id,
    reauth_token: lifecycleGrant.payload.token,
  },
  { "X-CSRF-Token": alice.jar.cookies.get("lumi_csrf") },
);
assert.equal(result.status, 200);
assert.equal(result.payload.state, "suspended");
result = await request(alice.jar, "GET", `/api/v1/orgs/${orgId}/members`);
assert.equal(result.status, 403);
const resumeGrant = await request(
  alice.jar,
  "POST",
  "/api/v1/account/reauth",
  { purpose: "org_lifecycle" },
  { "X-CSRF-Token": alice.jar.cookies.get("lumi_csrf") },
);
result = await request(
  alice.jar,
  "POST",
  `/api/v1/orgs/${orgId}/resume`,
  {
    version: 2,
    reauth_grant_id: resumeGrant.payload.grant_id,
    reauth_token: resumeGrant.payload.token,
  },
  { "X-CSRF-Token": alice.jar.cookies.get("lumi_csrf") },
);
assert.equal(result.status, 200);
assert.equal(result.payload.state, "active");

result = await request(
  alice.jar,
  "POST",
  `/api/v1/orgs/${orgId}/invitations`,
  { email: bob.user.email, role: "member" },
  csrf(alice.jar),
);
assert.equal(result.status, 201);
const invitationId = result.payload.invitation.id;
const invitationToken = result.payload.development_token;
assert.ok(invitationToken);

result = await request(
  bob.jar,
  "POST",
  `/api/v1/invitations/${invitationId}/accept`,
  { token: invitationToken },
  { "X-CSRF-Token": bob.jar.cookies.get("lumi_csrf") },
);
assert.equal(result.status, 200);
const bobMembershipId = result.payload.membership.membership_id;
result = await request(
  bob.jar,
  "POST",
  `/api/v1/invitations/${invitationId}/accept`,
  { token: invitationToken },
  { "X-CSRF-Token": bob.jar.cookies.get("lumi_csrf") },
);
assert.equal(result.status, 200);
result = await request(
  alice.jar,
  "POST",
  "/api/v1/orgs",
  { display_name: "P02 Other Tenant", slug: `p02-other-${randomUUID().slice(0, 6)}` },
  csrf(alice.jar),
);
assert.equal(result.status, 201);
const otherOrgId = result.payload.organization.org_id;
result = await request(bob.jar, "GET", `/api/v1/orgs/${otherOrgId}`);
assert.ok([403, 404].includes(result.status));
result = await request(bob.jar, "GET", `/api/v1/orgs/${orgId}/members`);
assert.equal(result.status, 200);
assert.equal(result.payload.items.length, 2);
result = await request(
  bob.jar,
  "PATCH",
  `/api/v1/orgs/${orgId}/members/${bobMembershipId}`,
  { role: "owner", version: 1 },
  { "X-CSRF-Token": bob.jar.cookies.get("lumi_csrf") },
);
assert.equal(result.status, 403);
result = await request(
  alice.jar,
  "POST",
  "/api/v1/account/reauth",
  { purpose: "identity_link" },
  { "X-CSRF-Token": alice.jar.cookies.get("lumi_csrf") },
);
assert.equal(result.status, 201);
const identityGrant = result.payload;
result = await request(
  alice.jar,
  "POST",
  "/api/v1/me/identities/link",
  {
    email: bob.user.email,
    reauth_grant_id: identityGrant.grant_id,
    reauth_token: identityGrant.token,
  },
  { "X-CSRF-Token": alice.jar.cookies.get("lumi_csrf") },
);
assert.equal(result.status, 409);
assert.equal(result.payload.error.details.reason, "identity_conflict");
result = await request(bob.jar, "GET", `/api/v1/orgs/${orgId}/audit`);
assert.equal(result.status, 403);
result = await request(
  alice.jar,
  "DELETE",
  `/api/v1/orgs/${orgId}/members/${bobMembershipId}`,
  undefined,
  { "X-CSRF-Token": alice.jar.cookies.get("lumi_csrf") },
);
assert.equal(result.status, 204);
result = await request(bob.jar, "GET", `/api/v1/orgs/${orgId}`);
assert.ok([403, 404].includes(result.status));
result = await request(alice.jar, "GET", `/api/v1/orgs/${orgId}/audit`);
assert.equal(result.status, 200);
const auditEvents = result.payload.items;
assert.ok(auditEvents.some((event) => event.action === "membership.accepted.v1"));
assert.ok(auditEvents.some((event) => event.action === "membership.removed.v1"));
assert.ok(auditEvents.every((event) => !JSON.stringify(event).includes(invitationToken)));

// Race two owner demotions in a separate tenant. Both requests start from
// two active owners; the conditional D1 update must leave one active owner.
result = await request(
  alice.jar,
  "POST",
  "/api/v1/orgs",
  { display_name: "P02 Owner Race", slug: `p02-race-${randomUUID().slice(0, 6)}` },
  csrf(alice.jar),
);
assert.equal(result.status, 201);
const raceOrgId = result.payload.organization.org_id;
const raceAliceMembership = result.payload.membership.membership_id;
result = await request(
  alice.jar,
  "POST",
  `/api/v1/orgs/${raceOrgId}/invitations`,
  { email: bob.user.email, role: "member" },
  csrf(alice.jar),
);
assert.equal(result.status, 201);
const raceInvitation = result.payload.invitation.id;
const raceToken = result.payload.development_token;
result = await request(
  bob.jar,
  "POST",
  `/api/v1/invitations/${raceInvitation}/accept`,
  { token: raceToken },
  { "X-CSRF-Token": bob.jar.cookies.get("lumi_csrf") },
);
assert.equal(result.status, 200);
const raceBobMembership = result.payload.membership.membership_id;
const raceGrant = await request(
  alice.jar,
  "POST",
  "/api/v1/account/reauth",
  { purpose: "ownership_transfer" },
  { "X-CSRF-Token": alice.jar.cookies.get("lumi_csrf") },
);
assert.equal(raceGrant.status, 201);
result = await request(
  alice.jar,
  "POST",
  `/api/v1/orgs/${raceOrgId}/ownership-transfer`,
  {
    target_membership_id: raceBobMembership,
    reauth_grant_id: raceGrant.payload.grant_id,
    reauth_token: raceGrant.payload.token,
  },
  { "X-CSRF-Token": alice.jar.cookies.get("lumi_csrf") },
);
assert.equal(result.status, 200);
const ownerRace = await Promise.all([
  request(
    alice.jar,
    "PATCH",
    `/api/v1/orgs/${raceOrgId}/members/${raceAliceMembership}`,
    { role: "admin", version: 2 },
    { "X-CSRF-Token": alice.jar.cookies.get("lumi_csrf") },
  ),
  request(
    bob.jar,
    "PATCH",
    `/api/v1/orgs/${raceOrgId}/members/${raceBobMembership}`,
    { role: "admin", version: 2 },
    { "X-CSRF-Token": bob.jar.cookies.get("lumi_csrf") },
  ),
]);
assert.deepEqual(ownerRace.map((item) => item.status).sort(), [200, 409]);

result = await request(
  alice.jar,
  "POST",
  "/api/v1/account/sessions/revoke-all",
  {},
  { "X-CSRF-Token": alice.jar.cookies.get("lumi_csrf") },
);
assert.equal(result.status, 204);
result = await request(alice.jar, "GET", "/api/v1/account/sessions");
assert.equal(result.status, 200);
const currentSessionId = result.payload.items[0].session_id;
result = await request(
  alice.jar,
  "DELETE",
  `/api/v1/account/sessions/${currentSessionId}`,
  undefined,
  { "X-CSRF-Token": alice.jar.cookies.get("lumi_csrf") },
);
assert.equal(result.status, 204);
result = await request(
  alice.jar,
  "POST",
  "/api/v1/auth/refresh",
  {},
  { "X-CSRF-Token": alice.jar.cookies.get("lumi_csrf") },
);
assert.equal(result.status, 401);

console.log(
  JSON.stringify({
    ok: true,
    org_id: orgId,
    owner_membership_id: ownerMembershipId,
    audit_events: auditEvents.length,
  }),
);
