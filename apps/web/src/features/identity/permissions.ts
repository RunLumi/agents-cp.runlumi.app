/**
 * Permission gating for the Identity & access surface.
 *
 * P07-CG §"Permissions and role behavior":
 *
 * | Permission             | Owner | Admin | Member | Viewer |
 * |---|---|---|---|---|
 * | `service_accounts.read`  | allow | allow | —     | —     |
 * | `service_accounts.manage` | allow | allow | —     | —     |
 *
 * "A credential is an ownership-level act", so both are admin-only and a member
 * or viewer is shown the read-refused state rather than an empty table. This
 * mirrors the gate the data and billing panels already use: the server enforces
 * the same matrix independently, and this only avoids rendering a control that
 * would fail closed with a 403.
 */

export type MembershipRole = "owner" | "admin" | "member" | "viewer";

/** Every gated action on this surface, with the permission it needs. */
export const IDENTITY_ACTIONS = [
  "read",
  "create_service_account",
  "update_service_account",
  "suspend_service_account",
  "create_api_key",
  "rotate_api_key",
  "revoke_api_key",
] as const;
export type IdentityAction = (typeof IDENTITY_ACTIONS)[number];

export const IDENTITY_ACTION_PERMISSIONS: Readonly<Record<IdentityAction, string>> = {
  read: "service_accounts.read",
  create_service_account: "service_accounts.manage",
  update_service_account: "service_accounts.manage",
  suspend_service_account: "service_accounts.manage",
  create_api_key: "service_accounts.manage",
  rotate_api_key: "service_accounts.manage",
  revoke_api_key: "service_accounts.manage",
};

export interface IdentityPermissions {
  readonly canRead: boolean;
  readonly canManage: boolean;
}

const NONE: IdentityPermissions = { canRead: false, canManage: false };

/**
 * Resolve the role to the two permission bits this surface needs.
 *
 * `service_accounts.manage` implies `service_accounts.read` on every role that
 * holds it, so the pair can never be contradictory.
 */
export function identityPermissions(role: MembershipRole | null | undefined): IdentityPermissions {
  if (role === "owner" || role === "admin") {
    return { canRead: true, canManage: true };
  }
  return NONE;
}

export function isIdentityActionPermitted(
  permissions: IdentityPermissions,
  action: IdentityAction,
): boolean {
  return action === "read" ? permissions.canRead : permissions.canManage;
}

export function permittedIdentityActions(permissions: IdentityPermissions): IdentityAction[] {
  return IDENTITY_ACTIONS.filter((action) => isIdentityActionPermitted(permissions, action));
}

/** Why the surface is empty for a member or viewer, in their own terms. */
export const IDENTITY_REFUSAL_COPY =
  "Reading and changing service accounts and API keys is an administrator action in this organization. Ask an owner or an administrator for access. Nothing is hidden from the audit log, and this page shows no credential data at all without permission.";

/**
 * Why the picker is not offered.
 *
 * A viewer must not be told "you have no access" to a control they were never
 * going to see; the honest statement is that the control does not exist for them.
 */
export const IDENTITY_MANAGE_ONLY_COPY =
  "Creating, suspending, rotating, and revoking credentials is an administrator action. You can read the current credentials and their last-used time, but not create or change one.";
