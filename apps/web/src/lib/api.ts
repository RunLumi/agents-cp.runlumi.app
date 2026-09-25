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
interface NormalizedDecoder<T> {
  decode(value: unknown): T | undefined;
}
type ResponseDecoder<T> = Decoder<T> | NormalizedDecoder<T>;
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
  decode: ResponseDecoder<T>,
): Promise<T> {
  const method = (options.method ?? "GET").toUpperCase();
  const headers = new Headers(options.headers);
  headers.set("Accept", "application/json");
  if (options.body !== undefined) headers.set("Content-Type", "application/json");
  if (options.idempotencyKey) headers.set("Idempotency-Key", options.idempotencyKey);
  if (!isSafeMethod(method) && !options.skipCsrf) {
    const csrf = readCookie("lumi_csrf");
    if (csrf) headers.set("X-CSRF-Token", csrf);
  }
  const { body, idempotencyKey: _idempotencyKey, skipCsrf: _skipCsrf, ...requestInit } = options;
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
  if (response.status === 204) return undefined as T;
  const decoded = validJson ? decodeResponse(payload, decode) : undefined;
  if (decoded === undefined) {
    throw makeInvalidResponseError({ requestId, status: response.status });
  }
  return decoded;
}

function decodeResponse<T>(value: unknown, decoder: ResponseDecoder<T>): T | undefined {
  if (typeof decoder === "function") return decoder(value) ? value : undefined;
  return decoder.decode(value);
}

interface RequestOptions extends Omit<RequestInit, "body" | "method"> {
  method?: string;
  body?: unknown;
  idempotencyKey?: string;
  /** Device/service routes authenticate with their own bearer boundary. */
  skipCsrf?: boolean;
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

// ---------------------------------------------------------------------------
// P05 — agents, agent sessions, runs, timelines, and artifact references
// ---------------------------------------------------------------------------

export type AgentDefinitionLifecycle = "active" | "archived" | "disabled";
export type AgentSessionLifecycle = "active" | "closed" | "archived";

export const RUN_STATES = [
  "queued",
  "dispatching",
  "running",
  "waiting_user",
  "waiting_approval",
  "succeeded",
  "failed",
  "cancelled",
  "timed_out",
] as const;

export type RunState = (typeof RUN_STATES)[number];
export type P05RunState = RunState;

export interface AgentDefinition {
  id: string;
  org_id: string;
  project_id: string | null;
  name: string;
  description: string | null;
  instructions_ref: string | null;
  default_model_alias: string | null;
  required_capabilities: string[];
  allowed_tool_ids: string[];
  runtime_requirements: string[];
  lifecycle: AgentDefinitionLifecycle;
  version: number;
  created_at: string;
  updated_at: string;
}

export type AgentDefinitionRecord = AgentDefinition;

export interface CreateAgentInput {
  name: string;
  description?: string | null;
  instructions_ref?: string | null;
  default_model_alias?: string | null;
  required_capabilities?: string[];
  allowed_tool_ids?: string[];
  runtime_requirements?: string[];
  project_id?: string | null;
}

export interface UpdateAgentInput {
  name?: string;
  description?: string | null;
  instructions_ref?: string | null;
  default_model_alias?: string | null;
  required_capabilities?: string[];
  allowed_tool_ids?: string[];
  runtime_requirements?: string[];
  project_id?: string | null;
  lifecycle?: AgentDefinitionLifecycle;
  version: number;
}

export type CreateAgentRequest = CreateAgentInput;
export type UpdateAgentRequest = UpdateAgentInput;

export interface ListAgentsQuery {
  limit?: number;
  cursor?: string;
  project_id?: string;
}

export interface AgentSession {
  id: string;
  org_id: string;
  project_id: string;
  device_id: string;
  workspace_binding_id: string | null;
  agent_definition_id: string;
  agent_definition_version: number;
  external_id: string | null;
  title: string | null;
  lifecycle: AgentSessionLifecycle;
  version: number;
  created_at: string;
  updated_at: string;
}

export type Session = AgentSession;
export type AgentSessionRecord = AgentSession;

export interface CreateAgentSessionInput {
  project_id: string;
  device_id: string;
  workspace_binding_id?: string | null;
  agent_definition_id: string;
  agent_definition_version?: number;
  external_id?: string | null;
  title?: string | null;
}

export type CreateSessionRequest = CreateAgentSessionInput;
export type CreateAgentSessionRequest = CreateAgentSessionInput;

export interface ListAgentSessionsQuery {
  limit?: number;
  cursor?: string;
  project_id?: string;
  lifecycle?: AgentSessionLifecycle;
}

export interface Run {
  id: string;
  org_id: string;
  project_id: string;
  agent_session_id: string;
  parent_run_id: string | null;
  attempt: number;
  agent_definition_id: string;
  agent_definition_version: number;
  principal_user_id: string;
  device_id: string;
  model_alias: string | null;
  route_id: string | null;
  route_version_id: string | null;
  state: RunState;
  failure_code: string | null;
  request_id: string | null;
  started_at: string | null;
  finished_at: string | null;
  version: number;
  state_version?: number | null;
  workspace_binding_id?: string | null;
  policy_snapshot_id?: string | null;
  policy_version?: number | null;
  cancel_requested_at?: string | null;
  resumed_from_run_id?: string | null;
  created_at: string;
  updated_at: string;
}

export type RunRecord = Run;

export interface StartRunInput {
  agent_session_id: string;
  model_alias?: string;
  input_ref?: string;
  parent_run_id?: string;
  execution_mode?: "managed" | "local_only";
}

export type StartRunRequest = StartRunInput;
export type CreateRunInput = StartRunInput;

export interface CancelRunInput {
  version: number;
  reason?: string;
}

export interface RetryRunInput {
  version: number;
}

export interface ListRunsQuery {
  limit?: number;
  cursor?: string;
  project_id?: string;
  session_id?: string;
  state?: RunState;
}

export type P05Metadata = Record<string, unknown>;

export interface RunEvent {
  id: string;
  run_id: string;
  sequence: number;
  event_type: string;
  occurred_at: string;
  actor_type: "user" | "device" | "service_account" | "system";
  actor_id?: string | null;
  correlation_id?: string | null;
  tool_call_id?: string | null;
  approval_id?: string | null;
  payload?: P05Metadata | null;
  org_id?: string | null;
  project_id?: string | null;
  request_id?: string | null;
  device_id?: string | null;
  agent_session_id?: string | null;
  schema_version?: number;
  recorded_at?: string | null;
}

export interface ListRunEventsQuery {
  limit?: number;
  cursor?: string;
  after_sequence?: number;
}

export type ArtifactKind = "local_only" | "cloud_uploaded" | "external_link";

export interface ArtifactRef {
  id: string;
  org_id: string;
  project_id: string;
  run_id: string;
  kind: ArtifactKind;
  content_ref?: string | null;
  mime_type: string | null;
  size_bytes: number | null;
  checksum: string | null;
  retention_policy: string;
  created_at: string;
}

export type ArtifactRecord = ArtifactRef;

export interface CreateArtifactInput {
  kind: ArtifactKind;
  content_ref?: string | null;
  mime_type?: string | null;
  size_bytes?: number | null;
  checksum?: string | null;
  retention_policy?: string;
}

export type CreateRunArtifactInput = CreateArtifactInput;
export type CreateArtifactRequest = CreateArtifactInput;

export async function listAgents(
  orgId: string,
  queryOrSignal?: ListAgentsQuery | AbortSignal,
  signal?: AbortSignal,
): Promise<Page<AgentDefinition>> {
  const request = resolveP05Query(queryOrSignal, signal);
  return requestJson(
    withP05Query(p05OrgPath(orgId, "agents"), request.query),
    request.signal ? { signal: request.signal } : {},
    isAgentDefinitionPage,
  );
}

export async function createAgent(
  orgId: string,
  input: CreateAgentInput,
  idempotencyKey: string,
  signal?: AbortSignal,
): Promise<AgentDefinition> {
  return requestJson(
    p05OrgPath(orgId, "agents"),
    {
      method: "POST",
      body: input,
      idempotencyKey,
      ...(signal ? { signal } : {}),
    },
    isAgentDefinition,
  );
}

export async function getAgent(
  orgId: string,
  agentId: string,
  signal?: AbortSignal,
): Promise<AgentDefinition> {
  return requestJson(
    `${p05OrgPath(orgId, "agents")}/${encodeURIComponent(agentId)}`,
    signal ? { signal } : {},
    isAgentDefinition,
  );
}

export async function updateAgent(
  orgId: string,
  agentId: string,
  input: UpdateAgentInput,
  signal?: AbortSignal,
): Promise<AgentDefinition> {
  return requestJson(
    `${p05OrgPath(orgId, "agents")}/${encodeURIComponent(agentId)}`,
    { method: "PATCH", body: input, ...(signal ? { signal } : {}) },
    isAgentDefinition,
  );
}

export const patchAgent = updateAgent;

export async function listAgentSessions(
  orgId: string,
  queryOrSignal?: ListAgentSessionsQuery | AbortSignal,
  signal?: AbortSignal,
): Promise<Page<AgentSession>> {
  const request = resolveP05Query(queryOrSignal, signal);
  return requestJson(
    withP05Query(p05OrgPath(orgId, "sessions"), request.query),
    request.signal ? { signal: request.signal } : {},
    isAgentSessionPage,
  );
}

export async function createAgentSession(
  orgId: string,
  input: CreateAgentSessionInput,
  idempotencyKey: string,
  signal?: AbortSignal,
): Promise<AgentSession> {
  return requestJson(
    p05OrgPath(orgId, "sessions"),
    {
      method: "POST",
      body: input,
      idempotencyKey,
      ...(signal ? { signal } : {}),
    },
    isAgentSession,
  );
}

export const createSession = createAgentSession;

export async function getAgentSession(
  orgId: string,
  sessionId: string,
  signal?: AbortSignal,
): Promise<AgentSession> {
  return requestJson(
    `${p05OrgPath(orgId, "sessions")}/${encodeURIComponent(sessionId)}`,
    signal ? { signal } : {},
    isAgentSession,
  );
}

export const getSession = getAgentSession;

export async function closeAgentSession(
  orgId: string,
  sessionId: string,
  input: { version: number },
  idempotencyKey: string,
  signal?: AbortSignal,
): Promise<AgentSession> {
  return requestJson(
    `${p05OrgPath(orgId, "sessions")}/${encodeURIComponent(sessionId)}/close`,
    {
      method: "POST",
      body: input,
      idempotencyKey,
      ...(signal ? { signal } : {}),
    },
    isAgentSession,
  );
}

export const closeSession = closeAgentSession;

export async function listRuns(
  orgId: string,
  queryOrSignal?: ListRunsQuery | AbortSignal,
  signal?: AbortSignal,
): Promise<Page<Run>> {
  const request = resolveP05Query(queryOrSignal, signal);
  return requestJson(
    withP05Query(p05OrgPath(orgId, "runs"), request.query),
    request.signal ? { signal: request.signal } : {},
    isRunPage,
  );
}

export async function startRun(
  orgId: string,
  input: StartRunInput,
  idempotencyKey: string,
  signal?: AbortSignal,
): Promise<Run> {
  return requestJson(
    p05OrgPath(orgId, "runs"),
    {
      method: "POST",
      body: input,
      idempotencyKey,
      ...(signal ? { signal } : {}),
    },
    isRun,
  );
}

export const createRun = startRun;

export async function getRun(orgId: string, runId: string, signal?: AbortSignal): Promise<Run> {
  return requestJson(
    `${p05OrgPath(orgId, "runs")}/${encodeURIComponent(runId)}`,
    signal ? { signal } : {},
    isRun,
  );
}

export async function cancelRun(
  orgId: string,
  runId: string,
  input: CancelRunInput,
  idempotencyKey: string,
  signal?: AbortSignal,
): Promise<Run> {
  return requestJson(
    `${p05OrgPath(orgId, "runs")}/${encodeURIComponent(runId)}/cancel`,
    {
      method: "POST",
      body: input,
      idempotencyKey,
      ...(signal ? { signal } : {}),
    },
    isRun,
  );
}

export async function retryRun(
  orgId: string,
  runId: string,
  input: RetryRunInput,
  idempotencyKey: string,
  signal?: AbortSignal,
): Promise<Run> {
  return requestJson(
    `${p05OrgPath(orgId, "runs")}/${encodeURIComponent(runId)}/retry`,
    {
      method: "POST",
      body: input,
      idempotencyKey,
      ...(signal ? { signal } : {}),
    },
    isRun,
  );
}

export async function listRunEvents(
  orgId: string,
  runId: string,
  queryOrSignal?: ListRunEventsQuery | AbortSignal,
  signal?: AbortSignal,
): Promise<Page<RunEvent>> {
  const request = resolveP05Query(queryOrSignal, signal);
  return requestJson(
    withP05Query(`${p05OrgPath(orgId, "runs")}/${encodeURIComponent(runId)}/events`, request.query),
    request.signal ? { signal: request.signal } : {},
    isRunEventPage,
  );
}

export async function listRunArtifacts(
  orgId: string,
  runId: string,
  queryOrSignal?: Pick<ListRunEventsQuery, "limit" | "cursor"> | AbortSignal,
  signal?: AbortSignal,
): Promise<Page<ArtifactRef>> {
  const request = resolveP05Query(queryOrSignal, signal);
  return requestJson(
    withP05Query(
      `${p05OrgPath(orgId, "runs")}/${encodeURIComponent(runId)}/artifacts`,
      request.query,
    ),
    request.signal ? { signal: request.signal } : {},
    isArtifactPage,
  );
}

export async function createRunArtifact(
  orgId: string,
  runId: string,
  input: CreateArtifactInput,
  idempotencyKey: string,
  signal?: AbortSignal,
): Promise<ArtifactRef> {
  return requestJson(
    `${p05OrgPath(orgId, "runs")}/${encodeURIComponent(runId)}/artifacts`,
    {
      method: "POST",
      body: input,
      idempotencyKey,
      ...(signal ? { signal } : {}),
    },
    isArtifactRef,
  );
}

export const createArtifact = createRunArtifact;

// ---------------------------------------------------------------------------
// P05 — tool catalog, MCP registrations, policy, and approvals
// ---------------------------------------------------------------------------

export type ToolSource = "built_in" | "plugin" | "custom";
export type ToolRiskClass =
  | "read_only"
  | "filesystem_write"
  | "process_execution"
  | "network"
  | "mcp"
  | "browser"
  | "computer"
  | "credential_bearing"
  | "external_side_effect"
  | "destructive";
export type ToolLifecycle = "active" | "review" | "disabled";
export type ToolDecision =
  | "allow"
  | "require_session_approval"
  | "require_per_use_approval"
  | "deny";
export type McpTransport = "http" | "sse" | "stdio" | "other";
export type McpPolicyStatus = "approved" | "pending_review" | "denied" | "disabled";
export type ApprovalMode = "session" | "per_use";
export type ApprovalStatus = "pending" | "approved" | "denied" | "expired" | "cancelled";
export type ApprovalDecision = "approved" | "denied";
export type ExternalSubmitDecision = "deny" | "allow" | "require_approval";

export interface CapabilityDefinition {
  capability_id: string;
  org_id: string | null;
  capability_key: string;
  display_name: string;
  risk_class: ToolRiskClass;
  metadata?: P05Metadata | null;
  version: number;
  created_at: string;
  updated_at: string;
}

export interface ToolDefinition {
  tool_id: string;
  org_id: string;
  name: string;
  source: ToolSource;
  risk_class: ToolRiskClass;
  capability_ids: string[];
  fingerprint: string;
  lifecycle: ToolLifecycle;
  metadata?: P05Metadata | null;
  version: number;
  created_by_user_id?: string | null;
  created_at: string;
  updated_at: string;
  decision?: ToolDecision;
  review_required?: boolean;
  mcp_id?: string | null;
}

export interface CreateToolInput {
  name: string;
  source: ToolSource;
  risk_class: ToolRiskClass;
  capability_ids: string[];
  fingerprint: string;
  metadata?: P05Metadata | null;
}

export interface UpdateToolInput {
  lifecycle?: ToolLifecycle;
  risk_class?: ToolRiskClass;
  capability_ids?: string[];
  fingerprint?: string;
  version: number;
}

export interface ListToolsQuery {
  limit?: number;
  cursor?: string;
  source?: ToolSource;
  risk_class?: ToolRiskClass;
}

export interface McpToolEntry {
  tool_id: string;
  name?: string;
  fingerprint?: string | null;
  risk_class?: ToolRiskClass;
  review_required?: boolean;
}

export interface McpRegistration {
  mcp_id: string;
  org_id: string;
  source: ToolSource;
  transport: McpTransport;
  endpoint_metadata?: P05Metadata | null;
  command_metadata?: P05Metadata | null;
  allowed_origins: string[];
  required_secret_handles: string[];
  tool_fingerprint: string | null;
  tool_list: Array<string | McpToolEntry>;
  policy_status: McpPolicyStatus;
  version: number;
  created_by_user_id?: string | null;
  created_at: string;
  updated_at: string;
}

export interface CreateMcpRegistrationInput {
  source: ToolSource;
  transport: McpTransport;
  endpoint_metadata?: P05Metadata | null;
  command_metadata?: P05Metadata | null;
  allowed_origins?: string[];
  required_secret_handles?: string[];
  tool_fingerprint?: string | null;
}

export interface UpdateMcpRegistrationInput {
  source?: ToolSource;
  transport?: McpTransport;
  endpoint_metadata?: P05Metadata | null;
  command_metadata?: P05Metadata | null;
  allowed_origins?: string[];
  required_secret_handles?: string[];
  tool_fingerprint?: string | null;
  policy_status?: McpPolicyStatus;
  version: number;
}

export interface BrowserPolicy {
  allowed_domains: string[];
  blocked_domains: string[];
  allow_download: boolean;
  allow_upload: boolean;
  allow_authenticated: boolean;
  allow_clipboard: boolean;
  external_submit: ExternalSubmitDecision;
}

export interface ComputerPolicy {
  allow_accessibility: boolean;
  allow_screen_capture: boolean;
  allow_keyboard_mouse: boolean;
  allow_shell_escalation: boolean;
  allowed_applications: string[];
  blocked_applications?: string[];
}

export interface ToolPolicyRule {
  tool_id: string;
  capability_id?: string | null;
  decision: ToolDecision;
  argument_scope?: string[];
}

export interface ToolPolicyEntry {
  tool_id: string;
  decision: ToolDecision;
  fingerprint?: string | null;
  review_required?: boolean;
}

export interface ToolPolicyDocument {
  schema_version: 1;
  default_posture: ToolDecision;
  tool_ids: string[];
  mcp_ids: string[];
  rules?: ToolPolicyRule[];
  tool_decisions?: Record<string, ToolDecision>;
  entries?: ToolPolicyEntry[];
  browser: BrowserPolicy;
  computer: ComputerPolicy;
}

export interface ToolPolicy {
  tool_policy_id?: string | null;
  org_id: string | null;
  project_id?: string | null;
  policy_version: number;
  version: number;
  document: ToolPolicyDocument;
  policy_state?: "ok" | "missing" | "schema_unsupported";
  created_at?: string | null;
  updated_at?: string | null;
  expires_at?: string | null;
}

export interface ListToolPolicyQuery {
  project_id?: string;
}

export interface FlatToolPolicyInput {
  schema_version: number;
  default_posture?: ToolPolicyDocument["default_posture"];
  tool_ids?: string[];
  mcp_ids?: string[];
  rules?: ToolPolicyRule[];
  tool_decisions?: Record<string, ToolDecision>;
  entries?: ToolPolicyEntry[];
  browser?: BrowserPolicy;
  computer?: ComputerPolicy;
}

export type UpdateToolPolicyInput =
  | (FlatToolPolicyInput & { version: number; project_id?: string | null })
  | { document: ToolPolicyDocument; version: number; project_id?: string | null };

export interface ApprovalRequest {
  id: string;
  org_id: string;
  project_id: string;
  run_id: string;
  agent_session_id?: string | null;
  tool_call_id: string;
  tool_id: string;
  tool_fingerprint: string | null;
  risk_class: ToolRiskClass;
  approval_mode: ApprovalMode;
  status: ApprovalStatus;
  arguments_summary: string;
  arguments_hash?: string | null;
  policy_snapshot_id?: string | null;
  policy_version?: number | null;
  requested_by_device_id?: string | null;
  requested_by_principal_id: string | null;
  requested_at: string;
  expires_at: string;
  resolved_by_principal_id: string | null;
  resolved_at: string | null;
  resolution_reason: string | null;
  decision?: ApprovalDecision | null;
  consumed_at?: string | null;
  consumed_by_device_id?: string | null;
  version: number;
}

export interface ListApprovalsQuery {
  limit?: number;
  cursor?: string;
  status?: ApprovalStatus;
  run_id?: string;
}

export interface ResolveApprovalInput {
  decision: ApprovalDecision;
  reason?: string;
  version: number;
}

export type ResolveApprovalRequest = ResolveApprovalInput;

export interface ToolDecisionResponse {
  decision: ToolDecision;
  approval_id?: string | null;
  policy_version: number;
}

export interface ToolDecisionRequest {
  tool_call_id: string;
  tool_id: string;
  tool_fingerprint: string;
  capability_ids: string[];
  risk_class: ToolRiskClass;
  arguments_summary: string;
}

export async function listTools(
  orgId: string,
  queryOrSignal?: ListToolsQuery | AbortSignal,
  signal?: AbortSignal,
): Promise<Page<ToolDefinition>> {
  const request = resolveP05Query(queryOrSignal, signal);
  return requestJson(
    withP05Query(p05OrgPath(orgId, "tools"), request.query),
    request.signal ? { signal: request.signal } : {},
    isToolDefinitionPage,
  );
}

export async function createTool(
  orgId: string,
  input: CreateToolInput,
  idempotencyKey: string,
  signal?: AbortSignal,
): Promise<ToolDefinition> {
  return requestJson(
    p05OrgPath(orgId, "tools"),
    {
      method: "POST",
      body: input,
      idempotencyKey,
      ...(signal ? { signal } : {}),
    },
    isToolDefinition,
  );
}

export async function updateTool(
  orgId: string,
  toolId: string,
  input: UpdateToolInput,
  signal?: AbortSignal,
): Promise<ToolDefinition> {
  return requestJson(
    `${p05OrgPath(orgId, "tools")}/${encodeURIComponent(toolId)}`,
    { method: "PATCH", body: input, ...(signal ? { signal } : {}) },
    isToolDefinition,
  );
}

export const patchTool = updateTool;

export async function listMcpRegistrations(
  orgId: string,
  queryOrSignal?: Pick<ListToolsQuery, "limit" | "cursor"> | AbortSignal,
  signal?: AbortSignal,
): Promise<Page<McpRegistration>> {
  const request = resolveP05Query(queryOrSignal, signal);
  return requestJson(
    withP05Query(p05OrgPath(orgId, "mcp"), request.query),
    request.signal ? { signal: request.signal } : {},
    isMcpRegistrationPage,
  );
}

export async function createMcpRegistration(
  orgId: string,
  input: CreateMcpRegistrationInput,
  idempotencyKey: string,
  signal?: AbortSignal,
): Promise<McpRegistration> {
  return requestJson(
    p05OrgPath(orgId, "mcp"),
    {
      method: "POST",
      body: input,
      idempotencyKey,
      ...(signal ? { signal } : {}),
    },
    isMcpRegistration,
  );
}

export async function updateMcpRegistration(
  orgId: string,
  mcpId: string,
  input: UpdateMcpRegistrationInput,
  signal?: AbortSignal,
): Promise<McpRegistration> {
  return requestJson(
    `${p05OrgPath(orgId, "mcp")}/${encodeURIComponent(mcpId)}`,
    { method: "PATCH", body: input, ...(signal ? { signal } : {}) },
    isMcpRegistration,
  );
}

export const patchMcpRegistration = updateMcpRegistration;

export async function getToolPolicy(
  orgId: string,
  queryOrSignal?: ListToolPolicyQuery | AbortSignal,
  signal?: AbortSignal,
): Promise<ToolPolicy> {
  const request = resolveP05Query(queryOrSignal, signal);
  return requestJson(
    withP05Query(p05OrgPath(orgId, "policy/tools"), request.query),
    request.signal ? { signal: request.signal } : {},
    isToolPolicy,
  );
}

export async function updateToolPolicy(
  orgId: string,
  input: UpdateToolPolicyInput,
  signal?: AbortSignal,
): Promise<ToolPolicy> {
  const body =
    "document" in input
      ? {
          ...input.document,
          version: input.version,
          ...(input.project_id === undefined ? {} : { project_id: input.project_id }),
        }
      : input;
  return requestJson(
    p05OrgPath(orgId, "policy/tools"),
    { method: "PUT", body, ...(signal ? { signal } : {}) },
    isToolPolicy,
  );
}

export const putToolPolicy = updateToolPolicy;

export async function listApprovals(
  orgId: string,
  queryOrSignal?: ListApprovalsQuery | AbortSignal,
  signal?: AbortSignal,
): Promise<Page<ApprovalRequest>> {
  const request = resolveP05Query(queryOrSignal, signal);
  return requestJson(
    withP05Query(p05OrgPath(orgId, "approvals"), request.query),
    request.signal ? { signal: request.signal } : {},
    isApprovalPage,
  );
}

export async function getApproval(
  orgId: string,
  approvalId: string,
  signal?: AbortSignal,
): Promise<ApprovalRequest> {
  return requestJson(
    `${p05OrgPath(orgId, "approvals")}/${encodeURIComponent(approvalId)}`,
    signal ? { signal } : {},
    isApproval,
  );
}

export async function resolveApproval(
  orgId: string,
  approvalId: string,
  input: ResolveApprovalInput,
  idempotencyKey: string,
  signal?: AbortSignal,
): Promise<ApprovalRequest> {
  return requestJson(
    `${p05OrgPath(orgId, "approvals")}/${encodeURIComponent(approvalId)}/resolve`,
    {
      method: "POST",
      body: input,
      idempotencyKey,
      ...(signal ? { signal } : {}),
    },
    isApproval,
  );
}

/**
 * The broker endpoint is device-token authenticated. The token is passed only
 * for this request and is never stored by the client.
 */
export async function requestToolDecision(
  runId: string,
  input: ToolDecisionRequest,
  deviceToken: string,
  signal?: AbortSignal,
): Promise<ToolDecisionResponse> {
  return requestJson(
    `/api/v1/runs/${encodeURIComponent(runId)}/tool-decisions`,
    {
      method: "POST",
      body: input,
      headers: { Authorization: `DeviceToken ${deviceToken}` },
      skipCsrf: true,
      ...(signal ? { signal } : {}),
    },
    isToolDecisionResponse,
  );
}

export const evaluateToolDecision = requestToolDecision;

// ---------------------------------------------------------------------------
// P05 — usage, cost, budgets, reservations, and rate/concurrency policies
// ---------------------------------------------------------------------------

export type UsageSource = "inference" | "run";
export type UsageReconciliationStatus = "recorded" | "pending" | "reconciled" | "conflict";
export type BudgetScopeType =
  | "organization"
  | "project"
  | "user"
  | "service_account"
  | "model_alias";
export type BudgetLifecycle = "active" | "paused" | "archived" | "disabled";
export type BudgetState = "active" | "paused" | "archived" | "disabled" | "unavailable";
export type RateLimitStatus = "healthy" | "rate_limited" | "degraded" | "unhealthy" | "unknown";
export type UsageDenialLimitType = "budget" | "rate_limit" | "concurrency" | "policy" | "unknown";

export interface UsageEvent {
  id: string;
  /** Present only when a backend projection preserves the P04 key name. */
  usage_event_id?: string;
  request_id: string | null;
  org_id: string;
  project_id: string | null;
  run_id: string | null;
  principal_user_id: string;
  session_id: string | null;
  device_id: string | null;
  source: UsageSource;
  external_id: string | null;
  reconciliation_status: UsageReconciliationStatus;
  model_alias: string | null;
  route_version_id?: string | null;
  provider_id?: string | null;
  model_id?: string | null;
  input_tokens: number | null;
  output_tokens: number | null;
  cached_tokens: number | null;
  provider_usage?: P05Metadata;
  estimated_cost_minor: number | null;
  actual_cost_minor: number | null;
  currency: string | null;
  pricing_version: string | null;
  budget_decision: string;
  ttft_ms?: number | null;
  total_latency_ms?: number | null;
  created_at: string;
  reconciliation_state?: UsageReconciliationStatus;
  reconciled_at?: string | null;
  denial_code?: string | null;
  credential_id?: string | null;
  agent_session_id?: string | null;
}

export type P05UsageEvent = UsageEvent;

export interface ListUsageEventsQuery {
  limit?: number;
  cursor?: string;
  project_id?: string;
  run_id?: string;
  from?: string;
  to?: string;
}

export interface ListUsageSummaryQuery {
  project_id?: string;
  run_id?: string;
  from?: string;
  to?: string;
}

export interface UsageSummary {
  org_id: string;
  project_id: string | null;
  run_id: string | null;
  from: string | null;
  to: string | null;
  event_count: number;
  input_tokens: number;
  output_tokens: number;
  cached_tokens: number;
  cost_minor: number;
}

export interface ListUsageRollupsQuery {
  limit?: number;
  cursor?: string;
  project_id?: string;
  principal_user_id?: string;
  model_alias?: string;
  from?: string;
  to?: string;
}

export interface UsageRollup {
  id: string;
  org_id: string;
  project_id: string | null;
  principal_user_id: string | null;
  model_alias: string | null;
  bucket_start: string;
  bucket_end: string;
  input_tokens: number;
  output_tokens: number;
  cached_tokens: number;
  cost_minor: number;
  usage_event_count: number;
  updated_at: string;
}

export interface PricingVersion {
  source: string;
  version: string;
  effective_at: string;
}

export interface CostRecord {
  id: string;
  /** Present only when a backend projection preserves the P04 key name. */
  cost_record_id?: string;
  usage_event_id: string;
  org_id: string;
  project_id: string | null;
  run_id: string | null;
  pricing_source: string;
  pricing_version: string;
  pricing_effective_at: string;
  calculation_kind: "estimated" | "actual" | "recalculated";
  input_tokens: number | null;
  output_tokens: number | null;
  cached_tokens: number | null;
  cost_minor: number;
  currency: string;
  created_at: string;
  recalculated_from_cost_record_id?: string | null;
}

interface UsageReconciliationInputBase {
  external_id?: string;
  actual_cost_minor?: number;
  provider_usage?: P05Metadata;
}

export type UsageReconciliationInput =
  | (UsageReconciliationInputBase & { request_id: string; run_id?: never })
  | (UsageReconciliationInputBase & { run_id: string; request_id?: never });

export interface UsageReconciliationResponse {
  usage_event: UsageEvent;
  cost_record: CostRecord | null;
}

export interface Budget {
  budget_id: string;
  org_id: string;
  scope_type: BudgetScopeType;
  scope_id: string | null;
  period_start: string;
  period_end: string;
  limit_minor: number;
  spent_minor: number | null;
  used_minor: number | null;
  reserved_minor: number | null;
  currency: string | null;
  hard: boolean;
  lifecycle: BudgetLifecycle;
  state: BudgetState;
  version: number;
  created_at?: string | null;
  updated_at: string | null;
}

export interface ListBudgetsQuery {
  limit?: number;
  cursor?: string;
  scope_type?: BudgetScopeType;
  scope_id?: string;
}

export interface CreateBudgetInput {
  scope_type: BudgetScopeType;
  scope_id?: string | null;
  period_start: string;
  period_end: string;
  limit_minor: number;
  currency: string;
  hard: boolean;
}

export interface UpdateBudgetInput {
  limit_minor?: number;
  period_start?: string;
  period_end?: string;
  lifecycle?: BudgetLifecycle;
  currency?: string;
  version: number;
}

export interface BudgetReservation {
  reservation_id: string;
  request_id: string;
  run_id: string | null;
  org_id: string;
  budget_id: string | null;
  reserved_minor: number;
  committed_minor: number | null;
  status: "reserved" | "committed" | "released" | "expired" | "failed";
  currency: string | null;
  expires_at: string;
  reconciled_at: string | null;
  created_at: string;
  updated_at?: string | null;
}

export interface CreateBudgetReservationInput {
  request_id: string;
  run_id?: string;
  reserved_minor: number;
  expires_at: string;
}

export type ReservationReconciliationStatus = "committed" | "released";

export interface ReconcileBudgetReservationInput {
  actual_minor?: number;
  status: ReservationReconciliationStatus;
}

export interface RateLimitPolicy {
  rate_limit_policy_id: string;
  org_id: string;
  scope_type: BudgetScopeType;
  scope_id: string | null;
  requests_per_minute: number | null;
  tokens_per_minute: number | null;
  max_concurrent_requests: number | null;
  applicable_model_aliases: string[];
  status: RateLimitStatus;
  version: number;
  updated_at: string | null;
  enabled?: boolean;
  created_at?: string | null;
}

export interface ListRateLimitsQuery {
  limit?: number;
  cursor?: string;
  scope_type?: BudgetScopeType;
  scope_id?: string;
}

export interface UpdateRateLimitInput {
  requests_per_minute?: number | null;
  tokens_per_minute?: number | null;
  max_concurrent_requests?: number | null;
  version: number;
}

export interface UsageDenial {
  id: string;
  denial_id: string;
  org_id: string;
  code: string;
  action: string;
  resource_type: string | null;
  resource_id: string | null;
  outcome: string;
  reason: string | null;
  request_id: string | null;
  correlation_id: string | null;
  run_id: string | null;
  agent_session_id: string | null;
  project_id: string | null;
  scope_type: BudgetScopeType | null;
  scope_id: string | null;
  model_alias: string | null;
  limit_type: UsageDenialLimitType;
  retry_after_seconds: number | null;
  created_at: string;
}

export interface ListUsageDenialsQuery {
  limit?: number;
  cursor?: string;
  from?: string;
  to?: string;
}

export async function listUsageEvents(
  orgId: string,
  queryOrSignal?: ListUsageEventsQuery | AbortSignal,
  signal?: AbortSignal,
): Promise<Page<UsageEvent>> {
  const request = resolveP05Query(queryOrSignal, signal);
  return requestJson(
    withP05Query(p05OrgPath(orgId, "usage"), request.query),
    request.signal ? { signal: request.signal } : {},
    isUsageEventPage,
  );
}

export async function listUsageSummary(
  orgId: string,
  queryOrSignal?: ListUsageSummaryQuery | AbortSignal,
  signal?: AbortSignal,
): Promise<UsageSummary> {
  const request = resolveP05Query(queryOrSignal, signal);
  return requestJson(
    withP05Query(p05OrgPath(orgId, "usage/summary"), request.query),
    request.signal ? { signal: request.signal } : {},
    isUsageSummary,
  );
}

export async function listUsageRollups(
  orgId: string,
  queryOrSignal?: ListUsageRollupsQuery | AbortSignal,
  signal?: AbortSignal,
): Promise<Page<UsageRollup>> {
  const request = resolveP05Query(queryOrSignal, signal);
  return requestJson(
    withP05Query(p05OrgPath(orgId, "usage/rollups"), request.query),
    request.signal ? { signal: request.signal } : {},
    isUsageRollupPage,
  );
}

/**
 * Internal accounting reconciliation. This route is not a browser mutation;
 * callers must provide their service-auth headers through `headers`. The
 * browser client does not persist the headers or provider payload.
 */
export async function reconcileUsage(
  orgId: string,
  input: UsageReconciliationInput,
  idempotencyKey: string,
  headersOrSignal?: HeadersInit | AbortSignal,
  signal?: AbortSignal,
): Promise<UsageReconciliationResponse> {
  const requestHeaders = isAbortSignal(headersOrSignal) ? undefined : headersOrSignal;
  const requestSignal = isAbortSignal(headersOrSignal) ? headersOrSignal : signal;
  return requestJson(
    p05OrgPath(orgId, "usage/reconcile"),
    {
      method: "POST",
      body: input,
      idempotencyKey,
      ...(requestHeaders ? { headers: requestHeaders } : {}),
      skipCsrf: true,
      ...(requestSignal ? { signal: requestSignal } : {}),
    },
    isUsageReconciliationResponse,
  );
}

export async function listBudgets(
  orgId: string,
  queryOrSignal?: ListBudgetsQuery | AbortSignal,
  signal?: AbortSignal,
): Promise<Page<Budget>> {
  const request = resolveP05Query(queryOrSignal, signal);
  return requestJson(
    withP05Query(p05OrgPath(orgId, "budgets"), request.query),
    request.signal ? { signal: request.signal } : {},
    isBudgetPage,
  );
}

export async function getBudget(
  orgId: string,
  budgetId: string,
  signal?: AbortSignal,
): Promise<Budget> {
  return requestJson(
    `${p05OrgPath(orgId, "budgets")}/${encodeURIComponent(budgetId)}`,
    signal ? { signal } : {},
    isBudget,
  );
}

export async function createBudget(
  orgId: string,
  input: CreateBudgetInput,
  idempotencyKey: string,
  signal?: AbortSignal,
): Promise<Budget> {
  return requestJson(
    p05OrgPath(orgId, "budgets"),
    {
      method: "POST",
      body: input,
      idempotencyKey,
      ...(signal ? { signal } : {}),
    },
    isBudget,
  );
}

export async function updateBudget(
  orgId: string,
  budgetId: string,
  input: UpdateBudgetInput,
  signal?: AbortSignal,
): Promise<Budget> {
  return requestJson(
    `${p05OrgPath(orgId, "budgets")}/${encodeURIComponent(budgetId)}`,
    { method: "PATCH", body: input, ...(signal ? { signal } : {}) },
    isBudget,
  );
}

export const patchBudget = updateBudget;

/**
 * Reservation writes are server/internal operations. The explicit headers
 * argument prevents a browser UI from accidentally treating this as a public
 * mutation; callers must supply the service identity expected by the Worker.
 */
export async function createBudgetReservation(
  orgId: string,
  budgetId: string,
  input: CreateBudgetReservationInput,
  idempotencyKey: string,
  headersOrSignal?: HeadersInit | AbortSignal,
  signal?: AbortSignal,
): Promise<BudgetReservation> {
  const requestHeaders = isAbortSignal(headersOrSignal) ? undefined : headersOrSignal;
  const requestSignal = isAbortSignal(headersOrSignal) ? headersOrSignal : signal;
  return requestJson(
    `${p05OrgPath(orgId, "budgets")}/${encodeURIComponent(budgetId)}/reservations`,
    {
      method: "POST",
      body: input,
      idempotencyKey,
      ...(requestHeaders ? { headers: requestHeaders } : {}),
      skipCsrf: true,
      ...(requestSignal ? { signal: requestSignal } : {}),
    },
    isBudgetReservation,
  );
}

export async function reconcileBudgetReservation(
  orgId: string,
  budgetId: string,
  reservationId: string,
  input: ReconcileBudgetReservationInput,
  idempotencyKey: string,
  headersOrSignal?: HeadersInit | AbortSignal,
  signal?: AbortSignal,
): Promise<BudgetReservation> {
  const requestHeaders = isAbortSignal(headersOrSignal) ? undefined : headersOrSignal;
  const requestSignal = isAbortSignal(headersOrSignal) ? headersOrSignal : signal;
  return requestJson(
    `${p05OrgPath(orgId, "budgets")}/${encodeURIComponent(budgetId)}/reservations/${encodeURIComponent(reservationId)}/reconcile`,
    {
      method: "POST",
      body: input,
      idempotencyKey,
      ...(requestHeaders ? { headers: requestHeaders } : {}),
      skipCsrf: true,
      ...(requestSignal ? { signal: requestSignal } : {}),
    },
    isBudgetReservation,
  );
}

export async function listBudgetReservations(
  orgId: string,
  queryOrSignal?: Pick<ListBudgetsQuery, "limit" | "cursor"> | AbortSignal,
  signal?: AbortSignal,
): Promise<Page<BudgetReservation>> {
  const request = resolveP05Query(queryOrSignal, signal);
  return requestJson(
    withP05Query(`${p05OrgPath(orgId, "budgets")}/reservations`, request.query),
    request.signal ? { signal: request.signal } : {},
    isBudgetReservationPage,
  );
}

export async function listRateLimits(
  orgId: string,
  queryOrSignal?: ListRateLimitsQuery | AbortSignal,
  signal?: AbortSignal,
): Promise<Page<RateLimitPolicy>> {
  const request = resolveP05Query(queryOrSignal, signal);
  return requestJson(
    withP05Query(p05OrgPath(orgId, "rate-limits"), request.query),
    request.signal ? { signal: request.signal } : {},
    { decode: normalizeRateLimitPolicyPage },
  );
}

export async function updateRateLimit(
  orgId: string,
  scopeType: BudgetScopeType,
  scopeId: string,
  input: UpdateRateLimitInput,
  signal?: AbortSignal,
): Promise<RateLimitPolicy> {
  return requestJson(
    `${p05OrgPath(orgId, "rate-limits")}/${encodeURIComponent(scopeType)}/${encodeURIComponent(scopeId)}`,
    { method: "PUT", body: input, ...(signal ? { signal } : {}) },
    { decode: normalizeRateLimitPolicy },
  );
}

export const putRateLimit = updateRateLimit;

export async function listUsageDenials(
  orgId: string,
  queryOrSignal?: ListUsageDenialsQuery | AbortSignal,
  signal?: AbortSignal,
): Promise<Page<UsageDenial>> {
  const request = resolveP05Query(queryOrSignal, signal);
  return requestJson(
    withP05Query(p05OrgPath(orgId, "usage/denials"), request.query),
    request.signal ? { signal: request.signal } : {},
    { decode: (value) => normalizeUsageDenialPage(value, orgId) },
  );
}

// ---------------------------------------------------------------------------
// P05 request helpers and strict response decoders
// ---------------------------------------------------------------------------

function p05OrgPath(orgId: string, suffix: string): string {
  return `/api/v1/orgs/${encodeURIComponent(orgId)}/${suffix}`;
}

function resolveP05Query<T extends object>(
  queryOrSignal: T | AbortSignal | undefined,
  signal: AbortSignal | undefined,
): { query: T | undefined; signal: AbortSignal | undefined } {
  if (isAbortSignal(queryOrSignal)) return { query: undefined, signal: queryOrSignal };
  return { query: queryOrSignal, signal };
}

function isAbortSignal(value: unknown): value is AbortSignal {
  return typeof value === "object" && value !== null && "aborted" in value;
}

function withP05Query(path: string, query: object | undefined): string {
  if (!query) return path;
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(query)) {
    if (value === undefined || value === null || value === "") continue;
    if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") {
      params.set(key, String(value));
    }
  }
  const encoded = params.toString();
  return encoded ? `${path}?${encoded}` : path;
}

function isNullableString(value: unknown): value is string | null {
  return value === null || typeof value === "string";
}

function isOptionalString(value: unknown): value is string | null | undefined {
  return value === undefined || isNullableString(value);
}

function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((item) => typeof item === "string");
}

function isPositiveInteger(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value > 0;
}

function isNonNegativeInteger(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}

function isOptionalNullableNonNegativeInteger(value: unknown): value is number | null | undefined {
  return value === undefined || value === null || isNonNegativeInteger(value);
}

function isOptionalPositiveInteger(value: unknown): value is number | null | undefined {
  return value === undefined || value === null || isPositiveInteger(value);
}

function isOptionalMetadata(value: unknown): value is P05Metadata | null | undefined {
  return value === undefined || value === null || isObject(value);
}

function isAgentDefinition(value: unknown): value is AgentDefinition {
  return (
    isObject(value) &&
    typeof value.id === "string" &&
    typeof value.org_id === "string" &&
    isNullableString(value.project_id) &&
    typeof value.name === "string" &&
    isNullableString(value.description) &&
    isNullableString(value.instructions_ref) &&
    isNullableString(value.default_model_alias) &&
    isStringArray(value.required_capabilities) &&
    isStringArray(value.allowed_tool_ids) &&
    isStringArray(value.runtime_requirements) &&
    isAgentDefinitionLifecycle(value.lifecycle) &&
    isPositiveInteger(value.version) &&
    typeof value.created_at === "string" &&
    typeof value.updated_at === "string"
  );
}

function isAgentDefinitionPage(value: unknown): value is Page<AgentDefinition> {
  return isPage(value, isAgentDefinition);
}

function isAgentSession(value: unknown): value is AgentSession {
  return (
    isObject(value) &&
    typeof value.id === "string" &&
    typeof value.org_id === "string" &&
    typeof value.project_id === "string" &&
    typeof value.device_id === "string" &&
    isNullableString(value.workspace_binding_id) &&
    typeof value.agent_definition_id === "string" &&
    isPositiveInteger(value.agent_definition_version) &&
    isNullableString(value.external_id) &&
    isNullableString(value.title) &&
    isAgentSessionLifecycle(value.lifecycle) &&
    isPositiveInteger(value.version) &&
    typeof value.created_at === "string" &&
    typeof value.updated_at === "string"
  );
}

function isAgentSessionPage(value: unknown): value is Page<AgentSession> {
  return isPage(value, isAgentSession);
}

function isRun(value: unknown): value is Run {
  return (
    isObject(value) &&
    typeof value.id === "string" &&
    typeof value.org_id === "string" &&
    typeof value.project_id === "string" &&
    typeof value.agent_session_id === "string" &&
    isNullableString(value.parent_run_id) &&
    isPositiveInteger(value.attempt) &&
    typeof value.agent_definition_id === "string" &&
    isPositiveInteger(value.agent_definition_version) &&
    typeof value.principal_user_id === "string" &&
    typeof value.device_id === "string" &&
    isNullableString(value.model_alias) &&
    isNullableString(value.route_id) &&
    isNullableString(value.route_version_id) &&
    isRunState(value.state) &&
    isNullableString(value.failure_code) &&
    isNullableString(value.request_id) &&
    isNullableString(value.started_at) &&
    isNullableString(value.finished_at) &&
    isPositiveInteger(value.version) &&
    isOptionalPositiveInteger(value.state_version) &&
    isOptionalString(value.workspace_binding_id) &&
    isOptionalString(value.policy_snapshot_id) &&
    isOptionalPositiveInteger(value.policy_version) &&
    isOptionalString(value.cancel_requested_at) &&
    isOptionalString(value.resumed_from_run_id) &&
    typeof value.created_at === "string" &&
    typeof value.updated_at === "string"
  );
}

function isRunPage(value: unknown): value is Page<Run> {
  return isPage(value, isRun);
}

function isRunEvent(value: unknown): value is RunEvent {
  return (
    isObject(value) &&
    typeof value.id === "string" &&
    typeof value.run_id === "string" &&
    isPositiveInteger(value.sequence) &&
    typeof value.event_type === "string" &&
    typeof value.occurred_at === "string" &&
    isRunActorType(value.actor_type) &&
    isOptionalString(value.actor_id) &&
    isOptionalString(value.correlation_id) &&
    isOptionalString(value.tool_call_id) &&
    isOptionalString(value.approval_id) &&
    isOptionalMetadata(value.payload) &&
    isOptionalString(value.org_id) &&
    isOptionalString(value.project_id) &&
    isOptionalString(value.request_id) &&
    isOptionalString(value.device_id) &&
    isOptionalString(value.agent_session_id) &&
    isOptionalPositiveInteger(value.schema_version) &&
    isOptionalString(value.recorded_at)
  );
}

function isRunEventPage(value: unknown): value is Page<RunEvent> {
  return isPage(value, isRunEvent);
}

function isArtifactRef(value: unknown): value is ArtifactRef {
  return (
    isObject(value) &&
    typeof value.id === "string" &&
    typeof value.org_id === "string" &&
    typeof value.project_id === "string" &&
    typeof value.run_id === "string" &&
    isArtifactKind(value.kind) &&
    isOptionalString(value.content_ref) &&
    isNullableString(value.mime_type) &&
    (value.size_bytes === null || isNonNegativeInteger(value.size_bytes)) &&
    isNullableString(value.checksum) &&
    typeof value.retention_policy === "string" &&
    typeof value.created_at === "string"
  );
}

function isArtifactPage(value: unknown): value is Page<ArtifactRef> {
  return isPage(value, isArtifactRef);
}

function isAgentDefinitionLifecycle(value: unknown): value is AgentDefinitionLifecycle {
  return value === "active" || value === "archived" || value === "disabled";
}

function isAgentSessionLifecycle(value: unknown): value is AgentSessionLifecycle {
  return value === "active" || value === "closed" || value === "archived";
}

function isRunState(value: unknown): value is RunState {
  return typeof value === "string" && (RUN_STATES as readonly string[]).includes(value);
}

function isRunActorType(value: unknown): value is "user" | "device" | "service_account" | "system" {
  return (
    value === "user" || value === "device" || value === "service_account" || value === "system"
  );
}

function isArtifactKind(value: unknown): value is ArtifactKind {
  return value === "local_only" || value === "cloud_uploaded" || value === "external_link";
}

function isToolDefinition(value: unknown): value is ToolDefinition {
  return (
    isObject(value) &&
    typeof value.tool_id === "string" &&
    typeof value.org_id === "string" &&
    typeof value.name === "string" &&
    isToolSource(value.source) &&
    isToolRiskClass(value.risk_class) &&
    isStringArray(value.capability_ids) &&
    typeof value.fingerprint === "string" &&
    isToolLifecycle(value.lifecycle) &&
    isOptionalMetadata(value.metadata) &&
    isPositiveInteger(value.version) &&
    isOptionalString(value.created_by_user_id) &&
    typeof value.created_at === "string" &&
    typeof value.updated_at === "string" &&
    (value.decision === undefined || isToolDecision(value.decision)) &&
    (value.review_required === undefined || typeof value.review_required === "boolean") &&
    isOptionalString(value.mcp_id)
  );
}

function isToolDefinitionPage(value: unknown): value is Page<ToolDefinition> {
  return isPage(value, isToolDefinition);
}

function isToolSource(value: unknown): value is ToolSource {
  return value === "built_in" || value === "plugin" || value === "custom";
}

function isToolRiskClass(value: unknown): value is ToolRiskClass {
  return (
    value === "read_only" ||
    value === "filesystem_write" ||
    value === "process_execution" ||
    value === "network" ||
    value === "mcp" ||
    value === "browser" ||
    value === "computer" ||
    value === "credential_bearing" ||
    value === "external_side_effect" ||
    value === "destructive"
  );
}

function isToolLifecycle(value: unknown): value is ToolLifecycle {
  return value === "active" || value === "review" || value === "disabled";
}

function isToolDecision(value: unknown): value is ToolDecision {
  return (
    value === "allow" ||
    value === "require_session_approval" ||
    value === "require_per_use_approval" ||
    value === "deny"
  );
}

function isMcpTransport(value: unknown): value is McpTransport {
  return value === "http" || value === "sse" || value === "stdio" || value === "other";
}

function isMcpPolicyStatus(value: unknown): value is McpPolicyStatus {
  return (
    value === "approved" || value === "pending_review" || value === "denied" || value === "disabled"
  );
}

function isMcpToolEntry(value: unknown): value is string | McpToolEntry {
  if (typeof value === "string") return true;
  return (
    isObject(value) &&
    typeof value.tool_id === "string" &&
    (value.name === undefined || typeof value.name === "string") &&
    isOptionalString(value.fingerprint) &&
    (value.risk_class === undefined || isToolRiskClass(value.risk_class)) &&
    (value.review_required === undefined || typeof value.review_required === "boolean")
  );
}

function isMcpRegistration(value: unknown): value is McpRegistration {
  return (
    isObject(value) &&
    typeof value.mcp_id === "string" &&
    typeof value.org_id === "string" &&
    isToolSource(value.source) &&
    isMcpTransport(value.transport) &&
    isOptionalMetadata(value.endpoint_metadata) &&
    isOptionalMetadata(value.command_metadata) &&
    isStringArray(value.allowed_origins) &&
    isStringArray(value.required_secret_handles) &&
    isNullableString(value.tool_fingerprint) &&
    Array.isArray(value.tool_list) &&
    value.tool_list.every(isMcpToolEntry) &&
    isMcpPolicyStatus(value.policy_status) &&
    isPositiveInteger(value.version) &&
    isOptionalString(value.created_by_user_id) &&
    typeof value.created_at === "string" &&
    typeof value.updated_at === "string"
  );
}

function isMcpRegistrationPage(value: unknown): value is Page<McpRegistration> {
  return isPage(value, isMcpRegistration);
}

function isExternalSubmitDecision(value: unknown): value is ExternalSubmitDecision {
  return value === "deny" || value === "allow" || value === "require_approval";
}

function isBrowserPolicy(value: unknown): value is BrowserPolicy {
  return (
    isObject(value) &&
    isStringArray(value.allowed_domains) &&
    isStringArray(value.blocked_domains) &&
    typeof value.allow_download === "boolean" &&
    typeof value.allow_upload === "boolean" &&
    typeof value.allow_authenticated === "boolean" &&
    typeof value.allow_clipboard === "boolean" &&
    isExternalSubmitDecision(value.external_submit)
  );
}

function isComputerPolicy(value: unknown): value is ComputerPolicy {
  return (
    isObject(value) &&
    typeof value.allow_accessibility === "boolean" &&
    typeof value.allow_screen_capture === "boolean" &&
    typeof value.allow_keyboard_mouse === "boolean" &&
    typeof value.allow_shell_escalation === "boolean" &&
    isStringArray(value.allowed_applications) &&
    (value.blocked_applications === undefined || isStringArray(value.blocked_applications))
  );
}

function isToolPolicyRule(value: unknown): value is ToolPolicyRule {
  return (
    isObject(value) &&
    typeof value.tool_id === "string" &&
    isOptionalString(value.capability_id) &&
    isToolDecision(value.decision) &&
    (value.argument_scope === undefined || isStringArray(value.argument_scope))
  );
}

function isToolPolicyEntry(value: unknown): value is ToolPolicyEntry {
  return (
    isObject(value) &&
    typeof value.tool_id === "string" &&
    isToolDecision(value.decision) &&
    isOptionalString(value.fingerprint) &&
    (value.review_required === undefined || typeof value.review_required === "boolean")
  );
}

function isToolDecisionMap(value: unknown): value is Record<string, ToolDecision> {
  if (!isObject(value)) return false;
  return Object.entries(value).every(
    ([key, decision]) => key.length > 0 && isToolDecision(decision),
  );
}

function isToolPolicyDocument(value: unknown): value is ToolPolicyDocument {
  return (
    isObject(value) &&
    value.schema_version === 1 &&
    isToolDecision(value.default_posture) &&
    isStringArray(value.tool_ids) &&
    isStringArray(value.mcp_ids) &&
    (value.rules === undefined ||
      (Array.isArray(value.rules) && value.rules.every(isToolPolicyRule))) &&
    (value.tool_decisions === undefined || isToolDecisionMap(value.tool_decisions)) &&
    (value.entries === undefined ||
      (Array.isArray(value.entries) && value.entries.every(isToolPolicyEntry))) &&
    isBrowserPolicy(value.browser) &&
    isComputerPolicy(value.computer)
  );
}

function isToolPolicy(value: unknown): value is ToolPolicy {
  return (
    isObject(value) &&
    isOptionalString(value.tool_policy_id) &&
    isNullableString(value.org_id) &&
    isOptionalString(value.project_id) &&
    isNonNegativeInteger(value.policy_version) &&
    isNonNegativeInteger(value.version) &&
    isToolPolicyDocument(value.document) &&
    (value.policy_state === undefined ||
      value.policy_state === "ok" ||
      value.policy_state === "missing" ||
      value.policy_state === "schema_unsupported") &&
    isOptionalString(value.created_at) &&
    isOptionalString(value.updated_at) &&
    isOptionalString(value.expires_at)
  );
}

function isApprovalStatus(value: unknown): value is ApprovalStatus {
  return (
    value === "pending" ||
    value === "approved" ||
    value === "denied" ||
    value === "expired" ||
    value === "cancelled"
  );
}

function isApprovalMode(value: unknown): value is ApprovalMode {
  return value === "session" || value === "per_use";
}

function isApproval(value: unknown): value is ApprovalRequest {
  return (
    isObject(value) &&
    typeof value.id === "string" &&
    typeof value.org_id === "string" &&
    typeof value.project_id === "string" &&
    typeof value.run_id === "string" &&
    isOptionalString(value.agent_session_id) &&
    typeof value.tool_call_id === "string" &&
    typeof value.tool_id === "string" &&
    isNullableString(value.tool_fingerprint) &&
    isToolRiskClass(value.risk_class) &&
    isApprovalMode(value.approval_mode) &&
    isApprovalStatus(value.status) &&
    typeof value.arguments_summary === "string" &&
    isOptionalString(value.arguments_hash) &&
    isOptionalString(value.policy_snapshot_id) &&
    isOptionalPositiveInteger(value.policy_version) &&
    isOptionalString(value.requested_by_device_id) &&
    isNullableString(value.requested_by_principal_id) &&
    typeof value.requested_at === "string" &&
    typeof value.expires_at === "string" &&
    isNullableString(value.resolved_by_principal_id) &&
    isNullableString(value.resolved_at) &&
    isNullableString(value.resolution_reason) &&
    (value.decision === undefined ||
      value.decision === null ||
      isApprovalDecision(value.decision)) &&
    isOptionalString(value.consumed_at) &&
    isOptionalString(value.consumed_by_device_id) &&
    isPositiveInteger(value.version)
  );
}

function isApprovalDecision(value: unknown): value is ApprovalDecision {
  return value === "approved" || value === "denied";
}

function isApprovalPage(value: unknown): value is Page<ApprovalRequest> {
  return isPage(value, isApproval);
}

function isToolDecisionResponse(value: unknown): value is ToolDecisionResponse {
  return (
    isObject(value) &&
    isToolDecision(value.decision) &&
    isOptionalString(value.approval_id) &&
    isNonNegativeInteger(value.policy_version)
  );
}

function isUsageSource(value: unknown): value is UsageSource {
  return value === "inference" || value === "run";
}

function isUsageReconciliationStatus(value: unknown): value is UsageReconciliationStatus {
  return (
    value === "recorded" || value === "pending" || value === "reconciled" || value === "conflict"
  );
}

function isUsageEvent(value: unknown): value is UsageEvent {
  return (
    isObject(value) &&
    typeof value.id === "string" &&
    isOptionalString(value.usage_event_id) &&
    isNullableString(value.request_id) &&
    typeof value.org_id === "string" &&
    isNullableString(value.project_id) &&
    isNullableString(value.run_id) &&
    typeof value.principal_user_id === "string" &&
    isNullableString(value.session_id) &&
    isNullableString(value.device_id) &&
    isUsageSource(value.source) &&
    isNullableString(value.external_id) &&
    isUsageReconciliationStatus(value.reconciliation_status) &&
    isNullableString(value.model_alias) &&
    isOptionalString(value.route_version_id) &&
    isOptionalString(value.provider_id) &&
    isOptionalString(value.model_id) &&
    isOptionalNullableNonNegativeInteger(value.input_tokens) &&
    isOptionalNullableNonNegativeInteger(value.output_tokens) &&
    isOptionalNullableNonNegativeInteger(value.cached_tokens) &&
    isOptionalMetadata(value.provider_usage) &&
    (value.estimated_cost_minor === null || isNonNegativeInteger(value.estimated_cost_minor)) &&
    (value.actual_cost_minor === null || isNonNegativeInteger(value.actual_cost_minor)) &&
    isNullableString(value.currency) &&
    isNullableString(value.pricing_version) &&
    typeof value.budget_decision === "string" &&
    isOptionalNullableNonNegativeInteger(value.ttft_ms) &&
    isOptionalNullableNonNegativeInteger(value.total_latency_ms) &&
    typeof value.created_at === "string" &&
    (value.reconciliation_state === undefined ||
      isUsageReconciliationStatus(value.reconciliation_state)) &&
    isOptionalString(value.reconciled_at) &&
    isOptionalString(value.denial_code) &&
    isOptionalString(value.credential_id) &&
    isOptionalString(value.agent_session_id)
  );
}

function isUsageEventPage(value: unknown): value is Page<UsageEvent> {
  return isPage(value, isUsageEvent);
}

function isUsageSummary(value: unknown): value is UsageSummary {
  return (
    isObject(value) &&
    typeof value.org_id === "string" &&
    isNullableString(value.project_id) &&
    isNullableString(value.run_id) &&
    isNullableString(value.from) &&
    isNullableString(value.to) &&
    isNonNegativeInteger(value.event_count) &&
    isNonNegativeInteger(value.input_tokens) &&
    isNonNegativeInteger(value.output_tokens) &&
    isNonNegativeInteger(value.cached_tokens) &&
    isNonNegativeInteger(value.cost_minor)
  );
}

function isUsageRollup(value: unknown): value is UsageRollup {
  return (
    isObject(value) &&
    typeof value.id === "string" &&
    typeof value.org_id === "string" &&
    isNullableString(value.project_id) &&
    isNullableString(value.principal_user_id) &&
    isNullableString(value.model_alias) &&
    typeof value.bucket_start === "string" &&
    typeof value.bucket_end === "string" &&
    isNonNegativeInteger(value.input_tokens) &&
    isNonNegativeInteger(value.output_tokens) &&
    isNonNegativeInteger(value.cached_tokens) &&
    isNonNegativeInteger(value.cost_minor) &&
    isNonNegativeInteger(value.usage_event_count) &&
    typeof value.updated_at === "string"
  );
}

function isUsageRollupPage(value: unknown): value is Page<UsageRollup> {
  return isPage(value, isUsageRollup);
}

function isCalculationKind(value: unknown): value is CostRecord["calculation_kind"] {
  return value === "estimated" || value === "actual" || value === "recalculated";
}

function isCostRecord(value: unknown): value is CostRecord {
  return (
    isObject(value) &&
    typeof value.id === "string" &&
    typeof value.usage_event_id === "string" &&
    typeof value.org_id === "string" &&
    isNullableString(value.project_id) &&
    isNullableString(value.run_id) &&
    typeof value.pricing_source === "string" &&
    typeof value.pricing_version === "string" &&
    typeof value.pricing_effective_at === "string" &&
    isCalculationKind(value.calculation_kind) &&
    (value.input_tokens === null || isNonNegativeInteger(value.input_tokens)) &&
    (value.output_tokens === null || isNonNegativeInteger(value.output_tokens)) &&
    (value.cached_tokens === null || isNonNegativeInteger(value.cached_tokens)) &&
    isNonNegativeInteger(value.cost_minor) &&
    typeof value.currency === "string" &&
    typeof value.created_at === "string" &&
    isOptionalString(value.recalculated_from_cost_record_id)
  );
}

function isUsageReconciliationResponse(value: unknown): value is UsageReconciliationResponse {
  return (
    isObject(value) &&
    isUsageEvent(value.usage_event) &&
    (value.cost_record === null || isCostRecord(value.cost_record))
  );
}

function isBudgetScopeType(value: unknown): value is BudgetScopeType {
  return (
    value === "organization" ||
    value === "project" ||
    value === "user" ||
    value === "service_account" ||
    value === "model_alias"
  );
}

function isBudgetLifecycle(value: unknown): value is BudgetLifecycle {
  return value === "active" || value === "paused" || value === "archived" || value === "disabled";
}

function isBudgetState(value: unknown): value is BudgetState {
  return (
    value === "active" ||
    value === "paused" ||
    value === "archived" ||
    value === "disabled" ||
    value === "unavailable"
  );
}

function isBudget(value: unknown): value is Budget {
  return (
    isObject(value) &&
    typeof value.budget_id === "string" &&
    typeof value.org_id === "string" &&
    isBudgetScopeType(value.scope_type) &&
    isNullableString(value.scope_id) &&
    typeof value.period_start === "string" &&
    typeof value.period_end === "string" &&
    isNonNegativeInteger(value.limit_minor) &&
    (value.spent_minor === undefined ||
      value.spent_minor === null ||
      isNonNegativeInteger(value.spent_minor)) &&
    (value.used_minor === undefined ||
      value.used_minor === null ||
      isNonNegativeInteger(value.used_minor)) &&
    (value.reserved_minor === undefined ||
      value.reserved_minor === null ||
      isNonNegativeInteger(value.reserved_minor)) &&
    isNullableString(value.currency) &&
    typeof value.hard === "boolean" &&
    isBudgetLifecycle(value.lifecycle) &&
    isBudgetState(value.state) &&
    isPositiveInteger(value.version) &&
    isOptionalString(value.created_at) &&
    isNullableString(value.updated_at)
  );
}

function isBudgetPage(value: unknown): value is Page<Budget> {
  return isPage(value, isBudget);
}

function isBudgetReservation(value: unknown): value is BudgetReservation {
  return (
    isObject(value) &&
    typeof value.reservation_id === "string" &&
    typeof value.request_id === "string" &&
    isNullableString(value.run_id) &&
    typeof value.org_id === "string" &&
    isNullableString(value.budget_id) &&
    isNonNegativeInteger(value.reserved_minor) &&
    (value.committed_minor === undefined ||
      value.committed_minor === null ||
      isNonNegativeInteger(value.committed_minor)) &&
    (value.status === "reserved" ||
      value.status === "committed" ||
      value.status === "released" ||
      value.status === "expired" ||
      value.status === "failed") &&
    isNullableString(value.currency) &&
    typeof value.expires_at === "string" &&
    isNullableString(value.reconciled_at) &&
    typeof value.created_at === "string" &&
    isOptionalString(value.updated_at)
  );
}

function isBudgetReservationPage(value: unknown): value is Page<BudgetReservation> {
  return isPage(value, isBudgetReservation);
}

function isRateLimitStatus(value: unknown): value is RateLimitStatus {
  return (
    value === "healthy" ||
    value === "rate_limited" ||
    value === "degraded" ||
    value === "unhealthy" ||
    value === "unknown"
  );
}

function normalizeRateLimitStatus(value: unknown): RateLimitStatus | undefined {
  if (value === "disabled") return "unknown";
  return isRateLimitStatus(value) ? value : undefined;
}

function normalizeRateLimitPolicy(value: unknown): RateLimitPolicy | undefined {
  if (!isObject(value)) return undefined;
  const status = normalizeRateLimitStatus(value.status);
  if (
    typeof value.rate_limit_policy_id !== "string" ||
    typeof value.org_id !== "string" ||
    !isBudgetScopeType(value.scope_type) ||
    !isNullableString(value.scope_id) ||
    !isOptionalNullableNonNegativeInteger(value.requests_per_minute) ||
    !isOptionalNullableNonNegativeInteger(value.tokens_per_minute) ||
    !isOptionalNullableNonNegativeInteger(value.max_concurrent_requests) ||
    !isStringArray(value.applicable_model_aliases) ||
    status === undefined ||
    !isPositiveInteger(value.version) ||
    !isOptionalString(value.updated_at) ||
    (value.enabled !== undefined && typeof value.enabled !== "boolean") ||
    !isOptionalString(value.created_at)
  ) {
    return undefined;
  }
  return {
    rate_limit_policy_id: value.rate_limit_policy_id,
    org_id: value.org_id,
    scope_type: value.scope_type,
    scope_id: value.scope_id,
    requests_per_minute: value.requests_per_minute ?? null,
    tokens_per_minute: value.tokens_per_minute ?? null,
    max_concurrent_requests: value.max_concurrent_requests ?? null,
    applicable_model_aliases: value.applicable_model_aliases,
    status,
    version: value.version,
    updated_at: value.updated_at ?? null,
    ...(value.enabled === undefined ? {} : { enabled: value.enabled }),
    ...(value.created_at === undefined ? {} : { created_at: value.created_at }),
  };
}

function normalizeRateLimitPolicyPage(value: unknown): Page<RateLimitPolicy> | undefined {
  if (!isObject(value) || !Array.isArray(value.items)) return undefined;
  if (value.next_cursor !== null && typeof value.next_cursor !== "string") return undefined;
  if (typeof value.has_more !== "boolean") return undefined;
  const items: RateLimitPolicy[] = [];
  for (const item of value.items) {
    const normalized = normalizeRateLimitPolicy(item);
    if (!normalized) return undefined;
    items.push(normalized);
  }
  return { items, next_cursor: value.next_cursor, has_more: value.has_more };
}

function isUsageDenialLimitType(value: unknown): value is UsageDenialLimitType {
  return (
    value === "budget" ||
    value === "rate_limit" ||
    value === "concurrency" ||
    value === "policy" ||
    value === "unknown"
  );
}

function normalizeUsageDenial(value: unknown, orgId: string): UsageDenial | undefined {
  if (!isObject(value)) return undefined;
  const id =
    typeof value.id === "string"
      ? value.id
      : typeof value.denial_id === "string"
        ? value.denial_id
        : undefined;
  const createdAt = typeof value.created_at === "string" ? value.created_at : undefined;
  if (!id || !createdAt) return undefined;

  const requestId = nullableText(value.request_id);
  const runId = nullableText(value.run_id);
  const projectId = nullableText(value.project_id);
  const scopeId = nullableText(value.scope_id);
  const modelAlias = nullableText(value.model_alias);
  const resourceType = nullableText(value.resource_type);
  const resourceId = nullableText(value.resource_id);
  const reason = nullableText(value.reason);
  const code =
    typeof value.code === "string" && value.code.length > 0
      ? value.code
      : (reason ?? "request_denied");
  const limitType =
    value.limit_type === undefined
      ? inferUsageDenialLimitType(code)
      : isUsageDenialLimitType(value.limit_type)
        ? value.limit_type
        : undefined;
  if (!limitType) return undefined;
  const retryAfter =
    value.retry_after_seconds === undefined || value.retry_after_seconds === null
      ? null
      : isNonNegativeInteger(value.retry_after_seconds)
        ? value.retry_after_seconds
        : undefined;
  if (retryAfter === undefined) return undefined;
  const scopeType =
    value.scope_type === undefined || value.scope_type === null
      ? null
      : isBudgetScopeType(value.scope_type)
        ? value.scope_type
        : undefined;
  if (scopeType === undefined) return undefined;

  return {
    id,
    denial_id: id,
    org_id: typeof value.org_id === "string" ? value.org_id : orgId,
    code,
    action: typeof value.action === "string" ? value.action : "request_denied",
    resource_type: resourceType,
    resource_id: resourceId,
    outcome: typeof value.outcome === "string" ? value.outcome : "denied",
    reason,
    request_id: requestId,
    correlation_id: nullableText(value.correlation_id),
    run_id: runId,
    agent_session_id: nullableText(value.agent_session_id),
    project_id: projectId,
    scope_type: scopeType,
    scope_id: scopeId,
    model_alias: modelAlias,
    limit_type: limitType,
    retry_after_seconds: retryAfter,
    created_at: createdAt,
  };
}

function normalizeUsageDenialPage(value: unknown, orgId: string): Page<UsageDenial> | undefined {
  if (!isObject(value) || !Array.isArray(value.items)) return undefined;
  if (value.next_cursor !== null && typeof value.next_cursor !== "string") return undefined;
  if (typeof value.has_more !== "boolean") return undefined;
  const items: UsageDenial[] = [];
  for (const item of value.items) {
    const normalized = normalizeUsageDenial(item, orgId);
    if (!normalized) return undefined;
    items.push(normalized);
  }
  return { items, next_cursor: value.next_cursor, has_more: value.has_more };
}

function nullableText(value: unknown): string | null {
  return typeof value === "string" ? value : null;
}

function inferUsageDenialLimitType(code: string): UsageDenialLimitType {
  if (code === "concurrency_limit_exceeded") return "concurrency";
  if (code === "rate_limit_exceeded" || code === "rate_limit_state_unavailable")
    return "rate_limit";
  if (code === "budget_exceeded" || code === "budget_state_unavailable") return "budget";
  if (code.includes("policy") || code.includes("tool") || code.includes("approval"))
    return "policy";
  return "unknown";
}
