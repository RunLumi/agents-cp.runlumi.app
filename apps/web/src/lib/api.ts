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

export type ModelCapability =
  | "text"
  | "vision"
  | "tools"
  | "structured_output"
  | "reasoning"
  | "audio"
  | "embeddings";

export interface CatalogProvider {
  provider_id: string;
  provider_key: string;
  display_name: string;
  adapter: "openai_compatible" | "anthropic" | "mock";
  lifecycle: "active" | "deprecated" | "disabled";
  version: number;
  endpoint_id: string | null;
  endpoint_url?: string | null;
  created_at: string;
  updated_at: string;
}

export interface CatalogModel {
  model_id: string;
  provider_id: string;
  provider_model_id: string;
  display_name: string;
  capabilities: ModelCapability[];
  max_input_tokens: number | null;
  max_output_tokens: number | null;
  lifecycle: "active" | "deprecated" | "disabled";
  pricing_version: string | null;
  version: number;
  created_at: string;
  updated_at: string;
}

export interface ModelAlias {
  alias_id: string;
  alias: string;
  display_name: string;
  lifecycle: "active" | "deprecated" | "disabled";
  description: string | null;
  created_at: string;
  updated_at: string;
}

export interface ProviderHealth {
  provider_id: string;
  state: "ready" | "degraded" | "cooldown";
  cooldown_until: string | null;
  last_error_code: string | null;
  success_count: number;
  failure_count: number;
  timeout_count: number;
  rate_limit_count: number;
  sample_count: number;
  ttft_ms_total: number;
  completion_latency_ms_total: number;
  updated_at: string;
}

export interface CatalogResponse {
  catalog_version: string;
  providers: CatalogProvider[];
  models: CatalogModel[];
  aliases: ModelAlias[];
  health: ProviderHealth[];
}

export interface CredentialMetadata {
  credential_id: string;
  org_id: string | null;
  owner_type: "platform" | "organization" | "user" | "service_account" | "local_only";
  owner_user_id: string | null;
  provider_id: string;
  label: string;
  status: "active" | "rotating" | "revoked";
  version: number;
  fingerprint: string;
  key_version: string | null;
  parent_credential_id: string | null;
  created_at: string;
  updated_at: string;
  last_used_at: string | null;
  has_secret: boolean;
}

export interface CredentialResponse {
  credential: CredentialMetadata;
  duplicate: boolean;
}

export interface RouteCandidate {
  provider_id: string;
  model_id: string;
  weight: number;
  timeout_ms: number;
  max_retries: number;
  credential_id: string | null;
}

export interface RouteConfig {
  strategy: "fixed" | "ordered_fallback" | "weighted_health_aware";
  candidates: RouteCandidate[];
}

export interface Route {
  route_id: string;
  org_id: string;
  alias: string;
  display_name: string;
  strategy: RouteConfig["strategy"];
  lifecycle: "draft" | "published" | "disabled";
  active_version_id: string | null;
  version: number;
  created_at: string;
  updated_at: string;
}

export interface RouteVersion {
  route_version_id: string;
  route_id: string;
  version: number;
  config: RouteConfig;
  config_hash: string;
  created_by_user_id: string;
  created_at: string;
  published_at: string | null;
}

export interface RouteResponse {
  route: Route;
  version: RouteVersion | null;
  duplicate: boolean;
}

export interface UsageMetadata {
  usage_event_id: string;
  request_id: string;
  org_id: string;
  project_id: string | null;
  run_id: string | null;
  principal_user_id: string;
  session_id: string | null;
  device_id: string | null;
  model_alias: string;
  route_version_id: string;
  provider_id: string;
  model_id: string;
  input_tokens: number | null;
  output_tokens: number | null;
  cached_tokens: number | null;
  provider_usage: Record<string, unknown>;
  estimated_cost_minor: number | null;
  actual_cost_minor: number | null;
  currency: string | null;
  pricing_version: string | null;
  budget_decision: string;
  ttft_ms: number | null;
  total_latency_ms: number | null;
  created_at: string;
}

export interface ModelPolicy {
  org_id: string;
  policy_version: number;
  allowed_aliases: string[] | null;
  allowed_models: string[] | null;
  allowed_providers: string[] | null;
  credential_mode:
    | "platform_only"
    | "organization_only"
    | "user_allowed"
    | "platform_or_organization"
    | "local_direct"
    | "ordered_fallback";
  managed_route_enabled: boolean;
  version: number;
  created_at: string;
  updated_at: string;
}

export interface ModelAliasView {
  alias: string;
  display_name: string;
  lifecycle: string;
  description: string | null;
  route_id: string | null;
  route_version_id: string | null;
  available: boolean;
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

export interface CeremonyStartResponse {
  ceremony_id: string;
  expires_at: string;
  public_key: Record<string, unknown>;
}

export interface PasskeySummary {
  passkey_id: string;
  label: string;
  transports: string[];
  backup_eligible: boolean | null;
  backup_state: boolean | null;
  created_at: string;
  last_used_at: string | null;
}

export interface PasskeyListResponse {
  items: PasskeySummary[];
  password_configured: boolean;
}

export interface PasswordStatusResponse {
  configured: boolean;
}

export async function passkeySignupStart(
  input: { email: string; display_name: string },
  signal?: AbortSignal,
): Promise<CeremonyStartResponse> {
  return requestJson(
    "/api/v1/auth/passkey/signup/start",
    { method: "POST", body: input, ...(signal ? { signal } : {}) },
    isCeremonyStartResponse,
  );
}

export async function passkeySignupComplete(
  input: { ceremony_id: string; credential: Record<string, unknown> },
  signal?: AbortSignal,
): Promise<UserResponse> {
  return requestJson(
    "/api/v1/auth/passkey/signup/complete",
    { method: "POST", body: input, ...(signal ? { signal } : {}) },
    isUserResponse,
  );
}

export async function passkeyLoginStart(signal?: AbortSignal): Promise<CeremonyStartResponse> {
  return requestJson(
    "/api/v1/auth/passkey/login/start",
    { method: "POST", body: {}, ...(signal ? { signal } : {}) },
    isCeremonyStartResponse,
  );
}

export async function passkeyLoginComplete(
  input: { ceremony_id: string; credential: Record<string, unknown> },
  signal?: AbortSignal,
): Promise<AuthResponse> {
  return requestJson(
    "/api/v1/auth/passkey/login/complete",
    { method: "POST", body: input, ...(signal ? { signal } : {}) },
    isAuthResponse,
  );
}

export async function passwordSignup(
  input: { email: string; display_name: string; password: string },
  signal?: AbortSignal,
): Promise<UserResponse> {
  return requestJson(
    "/api/v1/auth/password/signup",
    { method: "POST", body: input, ...(signal ? { signal } : {}) },
    isUserResponse,
  );
}

export async function passwordLogin(
  input: { email: string; password: string },
  signal?: AbortSignal,
): Promise<AuthResponse> {
  return requestJson(
    "/api/v1/auth/password/login",
    { method: "POST", body: input, ...(signal ? { signal } : {}) },
    isAuthResponse,
  );
}

export async function passwordForgot(
  input: { email: string },
  signal?: AbortSignal,
): Promise<ChallengeResponse> {
  return requestJson(
    "/api/v1/auth/password/forgot",
    { method: "POST", body: input, ...(signal ? { signal } : {}) },
    isChallengeResponse,
  );
}

export async function passwordReset(
  input: { challenge_id: string; code: string; password: string },
  signal?: AbortSignal,
): Promise<void> {
  await requestJson(
    "/api/v1/auth/password/reset",
    { method: "POST", body: input, ...(signal ? { signal } : {}) },
    isEmptyResponse,
  );
}

export async function listPasskeys(signal?: AbortSignal): Promise<PasskeyListResponse> {
  return requestJson("/api/v1/account/passkeys", signal ? { signal } : {}, isPasskeyListResponse);
}

export async function passkeyRegisterStart(
  input: { label: string; reauth_grant_id: string; reauth_token: string },
  signal?: AbortSignal,
): Promise<CeremonyStartResponse> {
  return requestJson(
    "/api/v1/account/passkeys/register/start",
    { method: "POST", body: input, ...(signal ? { signal } : {}) },
    isCeremonyStartResponse,
  );
}

export async function passkeyRegisterComplete(
  input: { ceremony_id: string; credential: Record<string, unknown> },
  signal?: AbortSignal,
): Promise<{ passkey_id: string }> {
  return requestJson(
    "/api/v1/account/passkeys/register/complete",
    { method: "POST", body: input, ...(signal ? { signal } : {}) },
    isPasskeyIdResponse,
  );
}

export async function revokePasskey(
  passkeyId: string,
  input: { reauth_grant_id: string; reauth_token: string },
  signal?: AbortSignal,
): Promise<void> {
  await requestJson(
    `/api/v1/account/passkeys/${encodeURIComponent(passkeyId)}`,
    { method: "DELETE", body: input, ...(signal ? { signal } : {}) },
    isEmptyResponse,
  );
}

export async function renamePasskey(
  passkeyId: string,
  input: { label: string; reauth_grant_id: string; reauth_token: string },
  signal?: AbortSignal,
): Promise<{ passkey_id: string; label: string }> {
  return requestJson(
    `/api/v1/account/passkeys/${encodeURIComponent(passkeyId)}`,
    { method: "PATCH", body: input, ...(signal ? { signal } : {}) },
    isPasskeyRenameResponse,
  );
}

export async function passwordStatus(signal?: AbortSignal): Promise<PasswordStatusResponse> {
  return requestJson(
    "/api/v1/account/password/status",
    signal ? { signal } : {},
    isPasswordStatusResponse,
  );
}

export async function setAccountPassword(
  input: { password: string; reauth_grant_id: string; reauth_token: string },
  signal?: AbortSignal,
): Promise<void> {
  await requestJson(
    "/api/v1/account/password",
    { method: "POST", body: input, ...(signal ? { signal } : {}) },
    isEmptyResponse,
  );
}

export async function reauthPasskeyStart(
  input: { purpose: string },
  signal?: AbortSignal,
): Promise<CeremonyStartResponse> {
  return requestJson(
    "/api/v1/account/reauth/passkey/start",
    { method: "POST", body: input, ...(signal ? { signal } : {}) },
    isCeremonyStartResponse,
  );
}

export async function reauthPasskeyComplete(
  input: { ceremony_id: string; credential: Record<string, unknown> },
  signal?: AbortSignal,
): Promise<{ grant: ReauthResponse }> {
  return requestJson(
    "/api/v1/account/reauth/passkey/complete",
    { method: "POST", body: input, ...(signal ? { signal } : {}) },
    isReauthGrantResponse,
  );
}

export async function reauthWithPassword(
  input: { purpose: string; password: string },
  signal?: AbortSignal,
): Promise<{ grant: ReauthResponse }> {
  return requestJson(
    "/api/v1/account/reauth/password",
    { method: "POST", body: input, ...(signal ? { signal } : {}) },
    isReauthGrantResponse,
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

export async function listInvitations(
  orgId: string,
  signal?: AbortSignal,
): Promise<Page<Invitation>> {
  return requestJson(
    `/api/v1/orgs/${encodeURIComponent(orgId)}/invitations`,
    signal ? { signal } : {},
    isInvitationPage,
  );
}

export async function revokeInvitation(
  orgId: string,
  invitationId: string,
  signal?: AbortSignal,
): Promise<void> {
  await requestJson(
    `/api/v1/orgs/${encodeURIComponent(orgId)}/invitations/${encodeURIComponent(invitationId)}`,
    { method: "DELETE", ...(signal ? { signal } : {}) },
    isEmptyResponse,
  );
}

export async function resendInvitation(
  orgId: string,
  invitationId: string,
  signal?: AbortSignal,
): Promise<InvitationResponse> {
  return requestJson(
    `/api/v1/orgs/${encodeURIComponent(orgId)}/invitations/${encodeURIComponent(invitationId)}/resend`,
    { method: "POST", body: {}, ...(signal ? { signal } : {}) },
    isInvitationResponse,
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

export async function leaveOrganization(orgId: string, signal?: AbortSignal): Promise<void> {
  await requestJson(
    `/api/v1/orgs/${encodeURIComponent(orgId)}/leave`,
    { method: "POST", body: {}, ...(signal ? { signal } : {}) },
    isEmptyResponse,
  );
}

export async function transitionOrganization(
  orgId: string,
  transition: "suspend" | "resume" | "deletion",
  input: { version: number; reauth_grant_id: string; reauth_token: string; confirmation?: string },
  signal?: AbortSignal,
): Promise<Organization> {
  return requestJson(
    `/api/v1/orgs/${encodeURIComponent(orgId)}/${transition}`,
    { method: "POST", body: input, ...(signal ? { signal } : {}) },
    isOrganization,
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

export async function startLinkEmailIdentity(
  input: { email: string; reauth_grant_id: string; reauth_token: string },
  signal?: AbortSignal,
): Promise<ChallengeResponse> {
  return requestJson(
    "/api/v1/me/identities/link/start",
    { method: "POST", body: input, ...(signal ? { signal } : {}) },
    isChallengeResponse,
  );
}

export async function linkEmailIdentity(
  input: { challenge_id: string; code: string },
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

export async function createProvider(
  orgId: string,
  input: {
    provider_key: string;
    display_name: string;
    adapter: CatalogProvider["adapter"];
    endpoint_url: string;
  },
  idempotencyKey: string,
  signal?: AbortSignal,
): Promise<{ provider: CatalogProvider }> {
  return requestJson(
    `/api/v1/orgs/${encodeURIComponent(orgId)}/catalog/providers`,
    { method: "POST", body: input, idempotencyKey, ...(signal ? { signal } : {}) },
    (value): value is { provider: CatalogProvider } =>
      isObject(value) && isCatalogProvider(value.provider),
  );
}

export async function createModel(
  orgId: string,
  input: {
    provider_id: string;
    provider_model_id: string;
    display_name: string;
    capabilities: ModelCapability[];
    max_input_tokens?: number;
    max_output_tokens?: number;
    pricing_version?: string;
  },
  idempotencyKey: string,
  signal?: AbortSignal,
): Promise<{ model: CatalogModel }> {
  return requestJson(
    `/api/v1/orgs/${encodeURIComponent(orgId)}/catalog/models`,
    { method: "POST", body: input, idempotencyKey, ...(signal ? { signal } : {}) },
    (value): value is { model: CatalogModel } => isObject(value) && isCatalogModel(value.model),
  );
}

export async function getCatalog(orgId: string, signal?: AbortSignal): Promise<CatalogResponse> {
  return requestJson(
    `/api/v1/orgs/${encodeURIComponent(orgId)}/catalog`,
    signal ? { signal } : {},
    isCatalogResponse,
  );
}

export async function listCredentials(
  orgId: string,
  signal?: AbortSignal,
): Promise<Page<CredentialMetadata>> {
  return requestJson(
    `/api/v1/orgs/${encodeURIComponent(orgId)}/credentials`,
    signal ? { signal } : {},
    isCredentialPage,
  );
}

export async function createCredential(
  orgId: string,
  input: {
    provider_id: string;
    owner_type: "organization" | "user" | "local_only";
    label: string;
    secret?: string;
  },
  idempotencyKey: string,
  signal?: AbortSignal,
): Promise<CredentialResponse> {
  return requestJson(
    `/api/v1/orgs/${encodeURIComponent(orgId)}/credentials`,
    {
      method: "POST",
      body: input,
      idempotencyKey,
      ...(signal ? { signal } : {}),
    },
    isCredentialResponse,
  );
}

export async function rotateCredential(
  orgId: string,
  credentialId: string,
  input: { label?: string; secret: string },
  idempotencyKey: string,
  signal?: AbortSignal,
): Promise<CredentialResponse> {
  return requestJson(
    `/api/v1/orgs/${encodeURIComponent(orgId)}/credentials/${encodeURIComponent(credentialId)}/rotate`,
    {
      method: "POST",
      body: input,
      idempotencyKey,
      ...(signal ? { signal } : {}),
    },
    isCredentialResponse,
  );
}

export async function revokeCredential(
  orgId: string,
  credentialId: string,
  version: number,
  idempotencyKey: string,
  signal?: AbortSignal,
): Promise<CredentialMetadata> {
  return requestJson(
    `/api/v1/orgs/${encodeURIComponent(orgId)}/credentials/${encodeURIComponent(credentialId)}/revoke`,
    {
      method: "POST",
      body: { version },
      idempotencyKey,
      ...(signal ? { signal } : {}),
    },
    isCredentialMetadata,
  );
}

export async function listRoutes(orgId: string, signal?: AbortSignal): Promise<Page<Route>> {
  return requestJson(
    `/api/v1/orgs/${encodeURIComponent(orgId)}/routes`,
    signal ? { signal } : {},
    isRoutePage,
  );
}

export async function createRoute(
  orgId: string,
  input: {
    alias: string;
    display_name: string;
    strategy: RouteConfig["strategy"];
    config: RouteConfig;
  },
  idempotencyKey: string,
  signal?: AbortSignal,
): Promise<RouteResponse> {
  return requestJson(
    `/api/v1/orgs/${encodeURIComponent(orgId)}/routes`,
    { method: "POST", body: input, idempotencyKey, ...(signal ? { signal } : {}) },
    isRouteResponse,
  );
}

export async function publishRoute(
  orgId: string,
  routeId: string,
  input: { version: number; config: RouteConfig },
  idempotencyKey: string,
  signal?: AbortSignal,
): Promise<RouteResponse> {
  return requestJson(
    `/api/v1/orgs/${encodeURIComponent(orgId)}/routes/${encodeURIComponent(routeId)}/publish`,
    { method: "POST", body: input, idempotencyKey, ...(signal ? { signal } : {}) },
    isRouteResponse,
  );
}

export async function rollbackRoute(
  orgId: string,
  routeId: string,
  version: number,
  idempotencyKey: string,
  signal?: AbortSignal,
): Promise<RouteResponse> {
  return requestJson(
    `/api/v1/orgs/${encodeURIComponent(orgId)}/routes/${encodeURIComponent(routeId)}/rollback`,
    { method: "POST", body: { version }, idempotencyKey, ...(signal ? { signal } : {}) },
    isRouteResponse,
  );
}

export async function getModelPolicy(orgId: string, signal?: AbortSignal): Promise<ModelPolicy> {
  return requestJson(
    `/api/v1/orgs/${encodeURIComponent(orgId)}/policy`,
    signal ? { signal } : {},
    isModelPolicy,
  );
}

export async function updateProviderLifecycle(
  orgId: string,
  providerId: string,
  input: { lifecycle: CatalogProvider["lifecycle"]; version: number },
  idempotencyKey: string,
  signal?: AbortSignal,
): Promise<{ provider: CatalogProvider }> {
  return requestJson(
    `/api/v1/orgs/${encodeURIComponent(orgId)}/catalog/providers/${encodeURIComponent(providerId)}`,
    { method: "PATCH", body: input, idempotencyKey, ...(signal ? { signal } : {}) },
    (value): value is { provider: CatalogProvider } =>
      isObject(value) && isCatalogProvider(value.provider),
  );
}

export async function updateModelLifecycle(
  orgId: string,
  modelId: string,
  input: { lifecycle: CatalogModel["lifecycle"]; version: number },
  idempotencyKey: string,
  signal?: AbortSignal,
): Promise<{ model: CatalogModel }> {
  return requestJson(
    `/api/v1/orgs/${encodeURIComponent(orgId)}/catalog/models/${encodeURIComponent(modelId)}`,
    { method: "PATCH", body: input, idempotencyKey, ...(signal ? { signal } : {}) },
    (value): value is { model: CatalogModel } => isObject(value) && isCatalogModel(value.model),
  );
}

export async function updateRouteLifecycle(
  orgId: string,
  routeId: string,
  input: { lifecycle: Route["lifecycle"]; version: number },
  idempotencyKey: string,
  signal?: AbortSignal,
): Promise<Route> {
  return requestJson(
    `/api/v1/orgs/${encodeURIComponent(orgId)}/routes/${encodeURIComponent(routeId)}`,
    { method: "PATCH", body: input, idempotencyKey, ...(signal ? { signal } : {}) },
    isRoute,
  );
}

export async function updateModelPolicy(
  orgId: string,
  input: {
    allowed_aliases: string[];
    allowed_models: string[];
    allowed_providers: string[];
    credential_mode: ModelPolicy["credential_mode"];
    managed_route_enabled: boolean;
    version: number;
  },
  idempotencyKey: string,
  signal?: AbortSignal,
): Promise<ModelPolicy> {
  return requestJson(
    `/api/v1/orgs/${encodeURIComponent(orgId)}/policy`,
    { method: "PUT", body: input, idempotencyKey, ...(signal ? { signal } : {}) },
    isModelPolicy,
  );
}

export async function listRouteHistory(
  orgId: string,
  routeId: string,
  signal?: AbortSignal,
): Promise<Page<RouteVersion>> {
  return requestJson(
    `/api/v1/orgs/${encodeURIComponent(orgId)}/routes/${encodeURIComponent(routeId)}/history`,
    signal ? { signal } : {},
    isRouteVersionPage,
  );
}

export async function listUsage(orgId: string, signal?: AbortSignal): Promise<Page<UsageMetadata>> {
  return requestJson(
    `/api/v1/orgs/${encodeURIComponent(orgId)}/usage`,
    signal ? { signal } : {},
    isUsagePage,
  );
}

export async function listInferenceModels(
  orgId: string,
  signal?: AbortSignal,
): Promise<Page<ModelAliasView>> {
  return requestJson(
    "/api/v1/inference/models",
    { headers: { "X-Org-ID": orgId }, ...(signal ? { signal } : {}) },
    isModelAliasPage,
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

function isModelCapability(value: unknown): value is ModelCapability {
  return (
    value === "text" ||
    value === "vision" ||
    value === "tools" ||
    value === "structured_output" ||
    value === "reasoning" ||
    value === "audio" ||
    value === "embeddings"
  );
}

function isCatalogProvider(value: unknown): value is CatalogProvider {
  return (
    isObject(value) &&
    typeof value.provider_id === "string" &&
    typeof value.provider_key === "string" &&
    typeof value.display_name === "string" &&
    (value.adapter === "openai_compatible" ||
      value.adapter === "anthropic" ||
      value.adapter === "mock") &&
    (value.lifecycle === "active" ||
      value.lifecycle === "deprecated" ||
      value.lifecycle === "disabled") &&
    typeof value.version === "number" &&
    (value.endpoint_id === null || typeof value.endpoint_id === "string") &&
    (value.endpoint_url === undefined ||
      value.endpoint_url === null ||
      typeof value.endpoint_url === "string") &&
    typeof value.created_at === "string" &&
    typeof value.updated_at === "string"
  );
}

function isCatalogModel(value: unknown): value is CatalogModel {
  return (
    isObject(value) &&
    typeof value.model_id === "string" &&
    typeof value.provider_id === "string" &&
    typeof value.provider_model_id === "string" &&
    typeof value.display_name === "string" &&
    Array.isArray(value.capabilities) &&
    value.capabilities.every(isModelCapability) &&
    (value.max_input_tokens === null || typeof value.max_input_tokens === "number") &&
    (value.max_output_tokens === null || typeof value.max_output_tokens === "number") &&
    (value.lifecycle === "active" ||
      value.lifecycle === "deprecated" ||
      value.lifecycle === "disabled") &&
    (value.pricing_version === null || typeof value.pricing_version === "string") &&
    typeof value.version === "number" &&
    typeof value.created_at === "string" &&
    typeof value.updated_at === "string"
  );
}

function isModelAlias(value: unknown): value is ModelAlias {
  return (
    isObject(value) &&
    typeof value.alias_id === "string" &&
    typeof value.alias === "string" &&
    typeof value.display_name === "string" &&
    (value.lifecycle === "active" ||
      value.lifecycle === "deprecated" ||
      value.lifecycle === "disabled") &&
    (value.description === null || typeof value.description === "string") &&
    typeof value.created_at === "string" &&
    typeof value.updated_at === "string"
  );
}

function isProviderHealth(value: unknown): value is ProviderHealth {
  return (
    isObject(value) &&
    typeof value.provider_id === "string" &&
    (value.state === "ready" || value.state === "degraded" || value.state === "cooldown") &&
    (value.cooldown_until === null || typeof value.cooldown_until === "string") &&
    (value.last_error_code === null || typeof value.last_error_code === "string") &&
    typeof value.success_count === "number" &&
    typeof value.failure_count === "number" &&
    typeof value.timeout_count === "number" &&
    typeof value.rate_limit_count === "number" &&
    typeof value.sample_count === "number" &&
    typeof value.ttft_ms_total === "number" &&
    typeof value.completion_latency_ms_total === "number" &&
    typeof value.updated_at === "string"
  );
}

function isCatalogResponse(value: unknown): value is CatalogResponse {
  return (
    isObject(value) &&
    typeof value.catalog_version === "string" &&
    Array.isArray(value.providers) &&
    value.providers.every(isCatalogProvider) &&
    Array.isArray(value.models) &&
    value.models.every(isCatalogModel) &&
    Array.isArray(value.aliases) &&
    value.aliases.every(isModelAlias) &&
    Array.isArray(value.health) &&
    value.health.every(isProviderHealth)
  );
}

function isCredentialMetadata(value: unknown): value is CredentialMetadata {
  return (
    isObject(value) &&
    typeof value.credential_id === "string" &&
    (value.org_id === null || typeof value.org_id === "string") &&
    ["platform", "organization", "user", "service_account", "local_only"].includes(
      String(value.owner_type),
    ) &&
    (value.owner_user_id === null || typeof value.owner_user_id === "string") &&
    typeof value.provider_id === "string" &&
    typeof value.label === "string" &&
    ["active", "rotating", "revoked"].includes(String(value.status)) &&
    typeof value.version === "number" &&
    typeof value.fingerprint === "string" &&
    (value.key_version === null || typeof value.key_version === "string") &&
    (value.parent_credential_id === null || typeof value.parent_credential_id === "string") &&
    typeof value.created_at === "string" &&
    typeof value.updated_at === "string" &&
    (value.last_used_at === null || typeof value.last_used_at === "string") &&
    typeof value.has_secret === "boolean"
  );
}

function isCredentialResponse(value: unknown): value is CredentialResponse {
  return (
    isObject(value) &&
    isCredentialMetadata(value.credential) &&
    typeof value.duplicate === "boolean"
  );
}

function isRouteCandidate(value: unknown): value is RouteCandidate {
  return (
    isObject(value) &&
    typeof value.provider_id === "string" &&
    typeof value.model_id === "string" &&
    typeof value.weight === "number" &&
    typeof value.timeout_ms === "number" &&
    typeof value.max_retries === "number" &&
    (value.credential_id === null || typeof value.credential_id === "string")
  );
}

function isRouteConfig(value: unknown): value is RouteConfig {
  return (
    isObject(value) &&
    ["fixed", "ordered_fallback", "weighted_health_aware"].includes(String(value.strategy)) &&
    Array.isArray(value.candidates) &&
    value.candidates.every(isRouteCandidate)
  );
}

function isRoute(value: unknown): value is Route {
  return (
    isObject(value) &&
    typeof value.route_id === "string" &&
    typeof value.org_id === "string" &&
    typeof value.alias === "string" &&
    typeof value.display_name === "string" &&
    ["fixed", "ordered_fallback", "weighted_health_aware"].includes(String(value.strategy)) &&
    ["draft", "published", "disabled"].includes(String(value.lifecycle)) &&
    (value.active_version_id === null || typeof value.active_version_id === "string") &&
    typeof value.version === "number" &&
    typeof value.created_at === "string" &&
    typeof value.updated_at === "string"
  );
}

function isRouteVersion(value: unknown): value is RouteVersion {
  return (
    isObject(value) &&
    typeof value.route_version_id === "string" &&
    typeof value.route_id === "string" &&
    typeof value.version === "number" &&
    isRouteConfig(value.config) &&
    typeof value.config_hash === "string" &&
    typeof value.created_by_user_id === "string" &&
    typeof value.created_at === "string" &&
    (value.published_at === null || typeof value.published_at === "string")
  );
}

function isRouteResponse(value: unknown): value is RouteResponse {
  return (
    isObject(value) &&
    isRoute(value.route) &&
    (value.version === null || isRouteVersion(value.version)) &&
    typeof value.duplicate === "boolean"
  );
}

function isModelPolicy(value: unknown): value is ModelPolicy {
  return (
    isObject(value) &&
    typeof value.org_id === "string" &&
    typeof value.policy_version === "number" &&
    (value.allowed_aliases === null ||
      (Array.isArray(value.allowed_aliases) &&
        value.allowed_aliases.every((item) => typeof item === "string"))) &&
    (value.allowed_models === null ||
      (Array.isArray(value.allowed_models) &&
        value.allowed_models.every((item) => typeof item === "string"))) &&
    (value.allowed_providers === null ||
      (Array.isArray(value.allowed_providers) &&
        value.allowed_providers.every((item) => typeof item === "string"))) &&
    [
      "platform_only",
      "organization_only",
      "user_allowed",
      "platform_or_organization",
      "local_direct",
      "ordered_fallback",
    ].includes(String(value.credential_mode)) &&
    typeof value.managed_route_enabled === "boolean" &&
    typeof value.version === "number" &&
    typeof value.created_at === "string" &&
    typeof value.updated_at === "string"
  );
}

function isUsageMetadata(value: unknown): value is UsageMetadata {
  return (
    isObject(value) &&
    typeof value.usage_event_id === "string" &&
    typeof value.request_id === "string" &&
    typeof value.org_id === "string" &&
    (value.project_id === null || typeof value.project_id === "string") &&
    (value.run_id === null || typeof value.run_id === "string") &&
    typeof value.principal_user_id === "string" &&
    (value.session_id === null || typeof value.session_id === "string") &&
    (value.device_id === null || typeof value.device_id === "string") &&
    typeof value.model_alias === "string" &&
    typeof value.route_version_id === "string" &&
    typeof value.provider_id === "string" &&
    typeof value.model_id === "string" &&
    (value.input_tokens === null || typeof value.input_tokens === "number") &&
    (value.output_tokens === null || typeof value.output_tokens === "number") &&
    (value.cached_tokens === null || typeof value.cached_tokens === "number") &&
    isObject(value.provider_usage) &&
    (value.estimated_cost_minor === null || typeof value.estimated_cost_minor === "number") &&
    (value.actual_cost_minor === null || typeof value.actual_cost_minor === "number") &&
    (value.currency === null || typeof value.currency === "string") &&
    (value.pricing_version === null || typeof value.pricing_version === "string") &&
    typeof value.budget_decision === "string" &&
    (value.ttft_ms === null || typeof value.ttft_ms === "number") &&
    (value.total_latency_ms === null || typeof value.total_latency_ms === "number") &&
    typeof value.created_at === "string"
  );
}

function isModelAliasView(value: unknown): value is ModelAliasView {
  return (
    isObject(value) &&
    typeof value.alias === "string" &&
    typeof value.display_name === "string" &&
    typeof value.lifecycle === "string" &&
    (value.description === null || typeof value.description === "string") &&
    (value.route_id === null || typeof value.route_id === "string") &&
    (value.route_version_id === null || typeof value.route_version_id === "string") &&
    typeof value.available === "boolean"
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

function isCeremonyStartResponse(value: unknown): value is CeremonyStartResponse {
  return (
    isObject(value) &&
    typeof value.ceremony_id === "string" &&
    typeof value.expires_at === "string" &&
    isObject(value.public_key)
  );
}

function isPasskeySummary(value: unknown): value is PasskeySummary {
  return (
    isObject(value) &&
    typeof value.passkey_id === "string" &&
    typeof value.label === "string" &&
    Array.isArray(value.transports) &&
    (value.backup_eligible === null ||
      value.backup_eligible === undefined ||
      typeof value.backup_eligible === "boolean") &&
    (value.backup_state === null ||
      value.backup_state === undefined ||
      typeof value.backup_state === "boolean") &&
    typeof value.created_at === "string" &&
    (value.last_used_at === null ||
      value.last_used_at === undefined ||
      typeof value.last_used_at === "string")
  );
}

function isPasskeyListResponse(value: unknown): value is PasskeyListResponse {
  return (
    isObject(value) &&
    Array.isArray(value.items) &&
    value.items.every(isPasskeySummary) &&
    typeof value.password_configured === "boolean"
  );
}

function isPasswordStatusResponse(value: unknown): value is PasswordStatusResponse {
  return isObject(value) && typeof value.configured === "boolean";
}

function isPasskeyIdResponse(value: unknown): value is { passkey_id: string } {
  return isObject(value) && typeof value.passkey_id === "string";
}

function isPasskeyRenameResponse(value: unknown): value is { passkey_id: string; label: string } {
  return isObject(value) && typeof value.passkey_id === "string" && typeof value.label === "string";
}

function isReauthGrantResponse(value: unknown): value is { grant: ReauthResponse } {
  return isObject(value) && isObject(value.grant) && isReauthResponse(value.grant);
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

function isCredentialPage(value: unknown): value is Page<CredentialMetadata> {
  return isPage(value, isCredentialMetadata);
}
function isRoutePage(value: unknown): value is Page<Route> {
  return isPage(value, isRoute);
}
function isRouteVersionPage(value: unknown): value is Page<RouteVersion> {
  return isPage(value, isRouteVersion);
}
function isUsagePage(value: unknown): value is Page<UsageMetadata> {
  return isPage(value, isUsageMetadata);
}
function isModelAliasPage(value: unknown): value is Page<ModelAliasView> {
  return isPage(value, isModelAliasView);
}

function isOrganizationPage(value: unknown): value is Page<OrganizationSummary> {
  return isPage(value, isOrganizationSummary);
}
function isMembershipPage(value: unknown): value is Page<Membership> {
  return isPage(value, isMembership);
}
function isInvitationPage(value: unknown): value is Page<Invitation> {
  return isPage(value, isInvitation);
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

// ---------------------------------------------------------------------------
// P03 — devices, projects, workspace bindings, policy snapshots
// ---------------------------------------------------------------------------

export interface ManagedDevice {
  id: string;
  org_id: string;
  name: string;
  platform: string;
  app_version: string;
  status: "active" | "revoked";
  capabilities: Record<string, unknown> | null;
  last_seen_at: string | null;
  revoked_at: string | null;
  enrolled_by_user_id: string;
  created_at: string;
}

export interface Project {
  id: string;
  org_id: string;
  name: string;
  slug: string;
  visibility: "org" | "restricted";
  archived: boolean;
  version: number;
  created_by_user_id: string;
  created_at: string;
  updated_at: string;
}

export interface WorkspaceBinding {
  id: string;
  org_id: string;
  project_id: string;
  device_id: string;
  workspace_identity: string;
  display_name: string;
  environment_type: "local" | "ssh" | "wsl" | "docker" | "remote";
  last_seen_at: string | null;
  created_at: string;
}

export interface PolicySnapshot {
  policy_id: string | null;
  org_id: string;
  policy_version: number;
  issued_at: string;
  expires_at: string;
  signature: string | null;
  payload: Record<string, unknown>;
  persisted: boolean;
}

function isManagedDevice(value: unknown): value is ManagedDevice {
  return (
    isObject(value) &&
    typeof value.id === "string" &&
    typeof value.org_id === "string" &&
    typeof value.name === "string" &&
    typeof value.platform === "string" &&
    typeof value.app_version === "string" &&
    typeof value.status === "string" &&
    typeof value.enrolled_by_user_id === "string" &&
    typeof value.created_at === "string"
  );
}

function isManagedDevicePage(value: unknown): value is Page<ManagedDevice> {
  return isPage(value, isManagedDevice);
}

function isProject(value: unknown): value is Project {
  return (
    isObject(value) &&
    typeof value.id === "string" &&
    typeof value.org_id === "string" &&
    typeof value.name === "string" &&
    typeof value.slug === "string" &&
    typeof value.visibility === "string" &&
    typeof value.archived === "boolean" &&
    typeof value.version === "number" &&
    typeof value.created_at === "string"
  );
}

function isProjectPage(value: unknown): value is Page<Project> {
  return isPage(value, isProject);
}

function isWorkspaceBinding(value: unknown): value is WorkspaceBinding {
  return (
    isObject(value) &&
    typeof value.id === "string" &&
    typeof value.project_id === "string" &&
    typeof value.device_id === "string" &&
    typeof value.workspace_identity === "string" &&
    typeof value.environment_type === "string"
  );
}

function isWorkspaceBindingList(value: unknown): value is { items: WorkspaceBinding[] } {
  return isObject(value) && Array.isArray(value.items) && value.items.every(isWorkspaceBinding);
}

function isPolicySnapshot(value: unknown): value is PolicySnapshot {
  return (
    isObject(value) &&
    (value.policy_id === null || typeof value.policy_id === "string") &&
    typeof value.org_id === "string" &&
    typeof value.policy_version === "number" &&
    value.policy_version >= 0 &&
    typeof value.issued_at === "string" &&
    typeof value.expires_at === "string" &&
    isObject(value.payload) &&
    typeof value.persisted === "boolean"
  );
}

export async function listDevices(
  orgId: string,
  signal?: AbortSignal,
): Promise<Page<ManagedDevice>> {
  return requestJson(
    `/api/v1/orgs/${encodeURIComponent(orgId)}/devices`,
    signal ? { signal } : {},
    isManagedDevicePage,
  );
}

export async function approveDeviceEnrollment(
  orgId: string,
  enrollmentId: string,
  idempotencyKey: string,
  signal?: AbortSignal,
): Promise<{ device: ManagedDevice; device_token: string; policy_version: number }> {
  return requestJson(
    `/api/v1/orgs/${encodeURIComponent(orgId)}/devices/enrollments/${encodeURIComponent(enrollmentId)}/approve`,
    {
      method: "POST",
      body: {},
      idempotencyKey,
      ...(signal ? { signal } : {}),
    },
    isApproveEnrollmentResponse,
  );
}

function isApproveEnrollmentResponse(value: unknown): value is {
  device: ManagedDevice;
  device_token: string;
  policy_version: number;
} {
  return isObject(value) && isManagedDevice(value.device) && typeof value.device_token === "string";
}

export async function revokeDevice(
  orgId: string,
  deviceId: string,
  idempotencyKey: string,
  signal?: AbortSignal,
): Promise<void> {
  await requestJson(
    `/api/v1/orgs/${encodeURIComponent(orgId)}/devices/${encodeURIComponent(deviceId)}`,
    {
      method: "DELETE",
      idempotencyKey,
      ...(signal ? { signal } : {}),
    },
    isEmptyResponse,
  );
}

export async function listProjects(orgId: string, signal?: AbortSignal): Promise<Page<Project>> {
  return requestJson(
    `/api/v1/orgs/${encodeURIComponent(orgId)}/projects`,
    signal ? { signal } : {},
    isProjectPage,
  );
}

export async function createProject(
  orgId: string,
  input: { name: string; visibility: "org" | "restricted"; slug?: string },
  idempotencyKey: string,
  signal?: AbortSignal,
): Promise<Project> {
  return requestJson(
    `/api/v1/orgs/${encodeURIComponent(orgId)}/projects`,
    {
      method: "POST",
      body: input,
      idempotencyKey,
      ...(signal ? { signal } : {}),
    },
    isProject,
  );
}

export async function patchProject(
  orgId: string,
  projectId: string,
  input: { name: string; visibility: "org" | "restricted"; archived?: boolean; version: number },
  signal?: AbortSignal,
): Promise<Project> {
  return requestJson(
    `/api/v1/orgs/${encodeURIComponent(orgId)}/projects/${encodeURIComponent(projectId)}`,
    { method: "PATCH", body: input, ...(signal ? { signal } : {}) },
    isProject,
  );
}

export async function listProjectBindings(
  orgId: string,
  projectId: string,
  signal?: AbortSignal,
): Promise<{ items: WorkspaceBinding[] }> {
  return requestJson(
    `/api/v1/orgs/${encodeURIComponent(orgId)}/projects/${encodeURIComponent(projectId)}/bindings`,
    signal ? { signal } : {},
    isWorkspaceBindingList,
  );
}

export async function getOrgPolicy(orgId: string, signal?: AbortSignal): Promise<PolicySnapshot> {
  return requestJson(
    `/api/v1/orgs/${encodeURIComponent(orgId)}/policy`,
    signal ? { signal } : {},
    isPolicySnapshot,
  );
}
