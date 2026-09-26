/**
 * Plugin governance presentation for a stable P07 reason code.
 *
 * The server's own message is never rendered. Each entry answers the question an
 * operator actually has, because "try again" is the wrong remediation for a
 * quarantined artifact or a package that is on both policy lists.
 */

import { ApiClientError, presentApiError, type ErrorPresentation } from "@/lib/errors";

import type { Tone } from "./contracts";

export interface PluginErrorCopy {
  readonly title: string;
  readonly message: string;
  readonly tone: Tone;
}

/**
 * Every stable P07 plugin reason code, in the order the gate lists it.
 */
export const PLUGIN_ERROR_COPY: Readonly<Record<string, PluginErrorCopy>> = {
  plugin_blocked: {
    title: "Package is blocked",
    message:
      "This organization blocks the package, so new installs and new executions are denied. Unblock it, or choose another package.",
    tone: "warning",
  },
  plugin_quarantined: {
    title: "This version is quarantined by the platform",
    message:
      "The platform quarantined this exact package@version. A managed organization cannot execute it even if the files are still on disk. Running in-flight work finishes under the policy it started with; only new invocations are denied.",
    tone: "danger",
  },
  plugin_permission_expanded: {
    title: "Update widens capability",
    message:
      "This version asks for more than the organization already approved, so managed mode refused the install. Read the permission diff and approve it deliberately if the gain is intended.",
    tone: "warning",
  },
  plugin_incompatible: {
    title: "Version is not compatible with this host",
    message:
      "The version's declared host runtime range excludes the reporting agent, so it cannot be installed here. Choose a version whose range includes this host.",
    tone: "warning",
  },
  plugin_integrity_failed: {
    title: "Package integrity check failed",
    message:
      "The artifact digest did not match the trusted distribution manifest, so nothing was recorded. This is treated as a security event. Fetch the artifact again from the official distribution and re-check the digest.",
    tone: "danger",
  },
  plugin_pinned: {
    title: "Package is pinned",
    message:
      "This package is pinned to an exact version and cannot move to any other, including a security update. Lift the pin as a separate, audited action, then install the version you want.",
    tone: "warning",
  },
  plugin_pinned_conflict: {
    title: "Pin conflicts with the current pin",
    message:
      "The package is already pinned to a different version. Lifting a pin is a distinct action so the unfreeze is deliberate; it is not done as a side effect of pinning elsewhere.",
    tone: "warning",
  },
  plugin_tool_unregistered: {
    title: "Tool is not registered",
    message:
      "The plugin declares this tool but the organization has no registration for it at this version, so it is denied. Unknown and new tools default to denied; register the tool deliberately to enable it.",
    tone: "warning",
  },
  plugin_publisher_not_allowed: {
    title: "Publisher is not allowed",
    message:
      "This organization's publisher policy does not permit this publisher. Add it to the approved publisher list, or install a package from a permitted publisher.",
    tone: "warning",
  },
  policy_conflict: {
    title: "The policy contradicts itself",
    message:
      "The change would put a package on both the allow list and the block list. Blocked wins and the contradiction is reported rather than resolved. Remove one of the two entries so the intent is explicit.",
    tone: "danger",
  },
  version_not_pending_review: {
    title: "Nothing is waiting for approval",
    message:
      "This package has no install awaiting review, so there is nothing to approve. Install the version first, then approve it if managed mode holds it.",
    tone: "warning",
  },
  manifest_invalid: {
    title: "The reported manifest is not valid",
    message:
      "The manifest the host reported could not be parsed. Nothing was changed. Re-report from the host agent.",
    tone: "danger",
  },
  manifest_digest_mismatch: {
    title: "Reported manifest digest does not match",
    message:
      "The digest in the report does not match the recorded one, so the report was not accepted. The server is the authority; a report is evidence, never permission.",
    tone: "danger",
  },
  version_conflict: {
    title: "The policy changed while you were working",
    message:
      "Someone else changed the plugin policy, so the write was refused rather than overwriting their change. Review the current policy, then repeat the action.",
    tone: "warning",
  },
  permission_denied: {
    title: "Access not permitted",
    message:
      "Ask an administrator to grant plugin access. Reading plugins is available to every member; installing, approving, pinning, and blocking are administrator actions.",
    tone: "warning",
  },
};

export function presentPluginError(error: unknown): ErrorPresentation & { tone: Tone } {
  if (error instanceof ApiClientError) {
    const reason = error.details.reason;
    const candidates = [error.code, typeof reason === "string" ? reason : null];
    for (const entry of candidates) {
      if (entry === null) continue;
      const known = PLUGIN_ERROR_COPY[entry];
      if (known) {
        return {
          title: known.title,
          message: known.message,
          code: entry,
          requestId: error.requestId,
          retryable: error.retryable,
          tone: known.tone,
        };
      }
    }
  }
  const base = presentApiError(error);
  return { ...base, tone: base.retryable ? "warning" : "danger" };
}
