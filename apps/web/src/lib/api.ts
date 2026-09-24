import { apiErrorFromEnvelope, makeInvalidResponseError, makeTransportError } from "@/lib/errors";

export interface HealthResponse {
  status: "ok";
  service: string;
}

export interface ApiMetaResponse {
  api_version: string;
  contract_version: string;
  service: string;
}

export type DeliveryStatus = "pending" | "queued" | "delivered" | "dead_letter";

export interface FoundationCheckResponse {
  event_id: string;
  delivery_status: DeliveryStatus;
}

export interface User {
  id: string;
  email: string;
  display_name: string;
  email_verified: boolean;
  created_at: string;
}

export interface Organization {
  org_id: string;
  display_name: string;
  slug: string;
  state: "active" | "suspended" | "pending_deletion" | "deleted";
  version: number;
  created_by_user_id: string;
  created_at: string;
  updated_at: string;
}

export interface OrganizationSummary {
  organization: Organization;
  membership_id: string;
  role: "owner" | "admin" | "member" | "viewer";
  status: "active" | "suspended" | "removed";
  membership_version: number;
}

export interface Membership {
  membership_id: string;
  org_id: string;
  user_id: string;
  role: "owner" | "admin" | "member" | "viewer";
  status: "active" | "suspended" | "removed";
  version: number;
  invited_by_user_id: string | null;
  joined_at: string | null;
  created_at: string;
  updated_at: string;
}

export interface Invitation {
  id: string;
  org_id: string;
  email: string;
  role: "admin" | "member" | "viewer";
  status: "pending" | "accepted" | "expired" | "revoked";
  expires_at: string;
  created_at: string;
}

export interface Team {
  team_id: string;
  org_id: string;
  display_name: string;
  slug: string;
  created_by_user_id: string;
  version: number;
  created_at: string;
  updated_at: string;
}

export interface SessionSummary {
  session_id: string;
  device_label: string;
  platform: string;
  expires_at: string;
  last_seen_at: string;
  created_at: string;
}

export interface SecurityEvent {
  event_id: string;
  org_id: string | null;
  actor_type: string;
  actor_id: string | null;
  effective_user_id: string | null;
  session_id: string | null;
  device_id: string | null;
  action: string;
  resource_type: string;
  resource_id: string | null;
  outcome: "success" | "denied" | "failure";
  reason: string | null;
  metadata: Record<string, unknown>;
  request_id: string;
  correlation_id: string;
  created_at: string;
}

export interface Page<T> {
  items: T[];
  next_cursor: string | null;
  has_more: boolean;
}

export interface ChallengeResponse {
  challenge_id: string;
  expires_at: string;
  development_code?: string;
}

export interface UserResponse {
  user: User;
  verification?: ChallengeResponse;
}

export interface MeResponse {
  user: User;
  organizations: OrganizationSummary[];
}

export interface AuthResponse {
  user: User;
}

export interface OrganizationResponse {
  organization: Organization;
  membership: Membership;
}

export interface InvitationResponse {
  invitation: Invitation;
  duplicate?: boolean;
  development_token?: string;
}

export interface IdentityLinkResponse {
  identity: {
    id: string;
    provider: string;
    email: string;
    email_verified: boolean;
  };
}

export interface ReauthResponse {
  grant_id: string;
  token: string;
  expires_at: string;
}

type Decoder<T> = (value: unknown) => value is T;
type JsonObject = Record<string, unknown>;

const INTERNAL_FOUNDATION_CHECKS = "/api/v1/_internal/foundation-checks";

export async function getHealth(signal?: AbortSignal): Promise<HealthResponse> {
  return requestJson("/api/health", signal ? { signal } : {}, isHealthResponse);
}

export async function getApiMeta(signal?: AbortSignal): Promise<ApiMetaResponse> {
  return requestJson("/api/v1/meta", signal ? { signal } : {}, isApiMetaResponse);
}

export async function createFoundationCheck(
  idempotencyKey: string,
  signal?: AbortSignal,
): Promise<FoundationCheckResponse> {
  return requestJson(
    INTERNAL_FOUNDATION_CHECKS,
    {
      method: "POST",
      body: {},
      idempotencyKey,
      ...(signal ? { signal } : {}),
    },
    isFoundationCheckResponse,
  );
}

export async function getFoundationCheckStatus(
  eventId: string,
  signal?: AbortSignal,
): Promise<FoundationCheckResponse> {
  return requestJson(
    `${INTERNAL_FOUNDATION_CHECKS}/${encodeURIComponent(eventId)}`,
    signal ? { signal } : {},
    isFoundationCheckResponse,
  );
}

export async function signup(
  input: { email: string; display_name: string },
  signal?: AbortSignal,
): Promise<UserResponse> {
  return requestJson(
    "/api/v1/auth/signup",
    { method: "POST", body: input, ...(signal ? { signal } : {}) },
    isUserResponse,
  );
}

export async function verifyEmail(
  input: { challenge_id: string; code: string },
  signal?: AbortSignal,
): Promise<AuthResponse> {
  return requestJson(
    "/api/v1/auth/verify-email",
    { method: "POST", body: input, ...(signal ? { signal } : {}) },
    isAuthResponse,
  );
}

export async function loginStart(
  input: { email: string },
  signal?: AbortSignal,
): Promise<ChallengeResponse> {
  return requestJson(
    "/api/v1/auth/login/start",
    { method: "POST", body: input, ...(signal ? { signal } : {}) },
    isChallengeResponse,
  );
}

export async function loginComplete(
  input: { challenge_id: string; code: string },
  signal?: AbortSignal,
): Promise<AuthResponse> {
  return requestJson(
    "/api/v1/auth/login/complete",
    { method: "POST", body: input, ...(signal ? { signal } : {}) },
    isAuthResponse,
  );
}

export async function logout(signal?: AbortSignal): Promise<void> {
  await requestJson(
    "/api/v1/auth/logout",
    { method: "POST", body: {}, ...(signal ? { signal } : {}) },
    isEmptyObject,
  );
}

export async function refreshSession(signal?: AbortSignal): Promise<AuthResponse> {
  return requestJson(
    "/api/v1/auth/refresh",
    { method: "POST", body: {}, ...(signal ? { signal } : {}) },
    isAuthResponse,
  );
}

export async function getMe(signal?: AbortSignal): Promise<MeResponse> {
  return requestJson("/api/v1/me", signal ? { signal } : {}, isMeResponse);
}

export async function createOrganization(
  input: { display_name: string; slug?: string },
  idempotencyKey: string,
  signal?: AbortSignal,
): Promise<OrganizationResponse> {
  return requestJson(
    "/api/v1/orgs",
    { method: "POST", body: input, idempotencyKey, ...(signal ? { signal } : {}) },
    isOrganizationResponse,
  );
}

export async function listOrganizations(signal?: AbortSignal): Promise<Page<OrganizationSummary>> {
  return requestJson("/api/v1/orgs", signal ? { signal } : {}, isOrganizationPage);
}

export async function getOrganization(orgId: string, signal?: AbortSignal): Promise<Organization> {
  return requestJson(
    `/api/v1/orgs/${encodeURIComponent(orgId)}`,
    signal ? { signal } : {},
    isOrganization,
  );
}

export async function updateOrganization(
  orgId: string,
  input: { display_name: string; slug: string; version: number },
  signal?: AbortSignal,
): Promise<Organization> {
  return requestJson(
    `/api/v1/orgs/${encodeURIComponent(orgId)}`,
    { method: "PATCH", body: input, ...(signal ? { signal } : {}) },
    isOrganization,
  );
}

export async function listMembers(orgId: string, signal?: AbortSignal): Promise<Page<Membership>> {
  return requestJson(
    `/api/v1/orgs/${encodeURIComponent(orgId)}/members`,
    signal ? { signal } : {},
    isMembershipPage,
  );
}

export async function inviteMember(
  orgId: string,
  input: { email: string; role: "admin" | "member" | "viewer" },
  idempotencyKey: string,
  signal?: AbortSignal,
): Promise<InvitationResponse> {
  return requestJson(
    `/api/v1/orgs/${encodeURIComponent(orgId)}/invitations`,
    { method: "POST", body: input, idempotencyKey, ...(signal ? { signal } : {}) },
    isInvitationResponse,
  );
}

export async function acceptInvitation(
  invitationId: string,
  token: string,
  signal?: AbortSignal,
): Promise<OrganizationResponse> {
  return requestJson(
    `/api/v1/invitations/${encodeURIComponent(invitationId)}/accept`,
    { method: "POST", body: { token }, ...(signal ? { signal } : {}) },
    isOrganizationResponse,
  );
}

export async function changeMemberRole(
  orgId: string,
  memberId: string,
  input: { role: Membership["role"]; version: number },
  signal?: AbortSignal,
): Promise<Membership> {
  return requestJson(
    `/api/v1/orgs/${encodeURIComponent(orgId)}/members/${encodeURIComponent(memberId)}`,
    { method: "PATCH", body: input, ...(signal ? { signal } : {}) },
    isMembership,
  );
}

export async function removeMember(
  orgId: string,
  memberId: string,
  signal?: AbortSignal,
): Promise<void> {
  await requestJson(
    `/api/v1/orgs/${encodeURIComponent(orgId)}/members/${encodeURIComponent(memberId)}`,
    { method: "DELETE", ...(signal ? { signal } : {}) },
    isEmptyResponse,
  );
}

export async function listTeams(orgId: string, signal?: AbortSignal): Promise<Page<Team>> {
  return requestJson(
    `/api/v1/orgs/${encodeURIComponent(orgId)}/teams`,
    signal ? { signal } : {},
    isTeamPage,
  );
}

export async function createTeam(
  orgId: string,
  input: { display_name: string; slug: string },
  signal?: AbortSignal,
): Promise<Team> {
  return requestJson(
    `/api/v1/orgs/${encodeURIComponent(orgId)}/teams`,
    { method: "POST", body: input, ...(signal ? { signal } : {}) },
    isTeam,
  );
}

export async function listSessions(signal?: AbortSignal): Promise<Page<SessionSummary>> {
  return requestJson("/api/v1/account/sessions", signal ? { signal } : {}, isSessionPage);
}

export async function revokeSession(sessionId: string, signal?: AbortSignal): Promise<void> {
  await requestJson(
    `/api/v1/account/sessions/${encodeURIComponent(sessionId)}`,
    { method: "DELETE", ...(signal ? { signal } : {}) },
    isEmptyResponse,
  );
}

export async function reauthenticate(signal?: AbortSignal): Promise<ReauthResponse> {
  return requestJson(
    "/api/v1/account/reauth",
    { method: "POST", body: {}, ...(signal ? { signal } : {}) },
    isReauthResponse,
  );
}

export async function linkEmailIdentity(
  input: { email: string; reauth_grant_id: string; reauth_token: string },
  signal?: AbortSignal,
): Promise<IdentityLinkResponse> {
  return requestJson(
    "/api/v1/me/identities/link",
    { method: "POST", body: input, ...(signal ? { signal } : {}) },
    isIdentityLinkResponse,
  );
}

export async function listSecurityEvents(signal?: AbortSignal): Promise<Page<SecurityEvent>> {
  return requestJson(
    "/api/v1/account/security-events",
    signal ? { signal } : {},
    isSecurityEventPage,
  );
}

async function requestJson<T>(
  path: string,
  options: RequestOptions,
  decode: Decoder<T>,
): Promise<T> {
  const method = (options.method ?? "GET").toUpperCase();
  const headers = new Headers(options.headers);
  headers.set("Accept", "application/json");
  if (options.body !== undefined) headers.set("Content-Type", "application/json");
  if (options.idempotencyKey) headers.set("Idempotency-Key", options.idempotencyKey);
  if (!isSafeMethod(method)) {
    const csrf = readCookie("lumi_csrf");
    if (csrf) headers.set("X-CSRF-Token", csrf);
  }
  const { body, idempotencyKey: _idempotencyKey, ...requestInit } = options;
  const init: RequestInit = {
    ...requestInit,
    method,
    headers,
    credentials: "include",
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  };
  const retrySafe = isSafeMethod(method) || options.idempotencyKey !== undefined;

  let response: Response;
  try {
    response = await fetch(path, init);
  } catch (cause) {
    throw makeTransportError(cause, options.signal ?? undefined, { retryable: retrySafe });
  }

  const requestId = readRequestId(response.headers.get("X-Request-ID"));
  let responseText: string;
  try {
    responseText = await response.text();
  } catch (cause) {
    throw makeTransportError(cause, options.signal ?? undefined, {
      requestId,
      status: response.status,
      retryable: response.status >= 500 || response.status === 429,
    });
  }

  let payload: unknown;
  let validJson = responseText.length > 0;
  if (validJson) {
    try {
      payload = JSON.parse(responseText) as unknown;
    } catch {
      validJson = false;
    }
  }
  if (!response.ok) {
    const apiCode = readApiErrorCode(payload);
    throw apiErrorFromEnvelope(
      response.status,
      validJson ? payload : undefined,
      requestId,
      isRetryableStatus(response.status, apiCode, retrySafe),
    );
  }
  if (!validJson || !decode(payload)) {
    if (response.status === 204) return undefined as T;
    throw makeInvalidResponseError({ requestId, status: response.status });
  }
  return payload;
}

interface RequestOptions extends Omit<RequestInit, "body" | "method"> {
  method?: string;
  body?: unknown;
  idempotencyKey?: string;
}

function isSafeMethod(method: string): boolean {
  return method === "GET" || method === "HEAD" || method === "OPTIONS";
}

function isRetryableStatus(status: number, code: string | undefined, retrySafe: boolean): boolean {
  if (!retrySafe) return false;
  return (
    status === 408 ||
    status === 425 ||
    status === 429 ||
    status >= 500 ||
    code === "idempotency_in_progress"
  );
}

function readCookie(name: string): string | undefined {
  if (typeof document === "undefined") return undefined;
  const value = document.cookie
    .split(";")
    .map((part) => part.trim())
    .find((part) => part.startsWith(`${name}=`))
    ?.slice(name.length + 1);
  return value && value.length <= 256 ? value : undefined;
}

function readRequestId(value: string | null): string | undefined {
  if (value === null) return undefined;
  const normalized = value.trim();
  return normalized.length > 0 && normalized.length <= 160 ? normalized : undefined;
}

function readApiErrorCode(payload: unknown): string | undefined {
  if (!isObject(payload)) return undefined;
  const error = payload.error;
  return isObject(error) && typeof error.code === "string" ? error.code : undefined;
}

function isObject(value: unknown): value is JsonObject {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isHealthResponse(value: unknown): value is HealthResponse {
  return isObject(value) && value.status === "ok" && typeof value.service === "string";
}

function isApiMetaResponse(value: unknown): value is ApiMetaResponse {
  return (
    isObject(value) &&
    typeof value.api_version === "string" &&
    typeof value.contract_version === "string" &&
    typeof value.service === "string"
  );
}

function isFoundationCheckResponse(value: unknown): value is FoundationCheckResponse {
  return (
    isObject(value) && typeof value.event_id === "string" && isDeliveryStatus(value.delivery_status)
  );
}

function isUser(value: unknown): value is User {
  return (
    isObject(value) &&
    typeof value.id === "string" &&
    typeof value.email === "string" &&
    typeof value.display_name === "string" &&
    typeof value.email_verified === "boolean" &&
    typeof value.created_at === "string"
  );
}

function isOrganization(value: unknown): value is Organization {
  return (
    isObject(value) &&
    typeof value.org_id === "string" &&
    typeof value.display_name === "string" &&
    typeof value.slug === "string" &&
    typeof value.state === "string" &&
    typeof value.version === "number"
  );
}

function isOrganizationSummary(value: unknown): value is OrganizationSummary {
  return (
    isObject(value) &&
    isOrganization(value.organization) &&
    typeof value.membership_id === "string" &&
    typeof value.role === "string" &&
    typeof value.status === "string" &&
    typeof value.membership_version === "number"
  );
}

function isMembership(value: unknown): value is Membership {
  return (
    isObject(value) &&
    typeof value.membership_id === "string" &&
    typeof value.org_id === "string" &&
    typeof value.user_id === "string" &&
    typeof value.role === "string" &&
    typeof value.status === "string" &&
    typeof value.version === "number"
  );
}

function isInvitation(value: unknown): value is Invitation {
  return (
    isObject(value) &&
    typeof value.id === "string" &&
    typeof value.org_id === "string" &&
    typeof value.email === "string" &&
    typeof value.role === "string" &&
    typeof value.status === "string" &&
    typeof value.expires_at === "string" &&
    typeof value.created_at === "string"
  );
}

function isTeam(value: unknown): value is Team {
  return (
    isObject(value) &&
    typeof value.team_id === "string" &&
    typeof value.org_id === "string" &&
    typeof value.display_name === "string" &&
    typeof value.slug === "string" &&
    typeof value.version === "number"
  );
}

function isSession(value: unknown): value is SessionSummary {
  return (
    isObject(value) &&
    typeof value.session_id === "string" &&
    typeof value.device_label === "string" &&
    typeof value.platform === "string" &&
    typeof value.expires_at === "string" &&
    typeof value.last_seen_at === "string" &&
    typeof value.created_at === "string"
  );
}

function isSecurityEvent(value: unknown): value is SecurityEvent {
  return (
    isObject(value) &&
    typeof value.event_id === "string" &&
    typeof value.action === "string" &&
    typeof value.outcome === "string" &&
    typeof value.created_at === "string" &&
    isObject(value.metadata)
  );
}

function isPage<T>(value: unknown, item: Decoder<T>): value is Page<T> {
  return (
    isObject(value) &&
    Array.isArray(value.items) &&
    value.items.every(item) &&
    (value.next_cursor === null || typeof value.next_cursor === "string") &&
    typeof value.has_more === "boolean"
  );
}

function isEmptyObject(value: unknown): value is Record<string, never> {
  return isObject(value) && Object.keys(value).length === 0;
}

function isEmptyResponse(_value: unknown): _value is undefined {
  return true;
}

function isUserResponse(value: unknown): value is UserResponse {
  return (
    isObject(value) &&
    isUser(value.user) &&
    (value.verification === undefined || isChallengeResponse(value.verification))
  );
}

function isAuthResponse(value: unknown): value is AuthResponse {
  return isObject(value) && isUser(value.user);
}

function isChallengeResponse(value: unknown): value is ChallengeResponse {
  return (
    isObject(value) &&
    typeof value.challenge_id === "string" &&
    typeof value.expires_at === "string" &&
    (value.development_code === undefined || typeof value.development_code === "string")
  );
}

function isMeResponse(value: unknown): value is MeResponse {
  return (
    isObject(value) &&
    isUser(value.user) &&
    Array.isArray(value.organizations) &&
    value.organizations.every(isOrganizationSummary)
  );
}

function isOrganizationResponse(value: unknown): value is OrganizationResponse {
  return isObject(value) && isOrganization(value.organization) && isMembership(value.membership);
}

function isInvitationResponse(value: unknown): value is InvitationResponse {
  return (
    isObject(value) &&
    isInvitation(value.invitation) &&
    (value.duplicate === undefined || typeof value.duplicate === "boolean") &&
    (value.development_token === undefined || typeof value.development_token === "string")
  );
}

function isReauthResponse(value: unknown): value is ReauthResponse {
  return (
    isObject(value) &&
    typeof value.grant_id === "string" &&
    typeof value.token === "string" &&
    typeof value.expires_at === "string"
  );
}

function isIdentityLinkResponse(value: unknown): value is IdentityLinkResponse {
  return (
    isObject(value) &&
    isObject(value.identity) &&
    typeof value.identity.id === "string" &&
    typeof value.identity.provider === "string" &&
    typeof value.identity.email === "string" &&
    typeof value.identity.email_verified === "boolean"
  );
}

function isOrganizationPage(value: unknown): value is Page<OrganizationSummary> {
  return isPage(value, isOrganizationSummary);
}
function isMembershipPage(value: unknown): value is Page<Membership> {
  return isPage(value, isMembership);
}
function isTeamPage(value: unknown): value is Page<Team> {
  return isPage(value, isTeam);
}
function isSessionPage(value: unknown): value is Page<SessionSummary> {
  return isPage(value, isSession);
}
function isSecurityEventPage(value: unknown): value is Page<SecurityEvent> {
  return isPage(value, isSecurityEvent);
}

function isDeliveryStatus(value: unknown): value is DeliveryStatus {
  return (
    value === "pending" || value === "queued" || value === "delivered" || value === "dead_letter"
  );
}
