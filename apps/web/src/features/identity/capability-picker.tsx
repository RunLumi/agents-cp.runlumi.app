/**
 * The capability picker and its permission preview.
 *
 * F14 Web UX: "create with permission preview". The operator chooses from the
 * real permission names, and the preview states exactly what the resulting
 * credential may do *before* anything is saved — because a credential's scope is
 * the only description of it that survives, and a scope nobody understood at the
 * moment of granting is a scope nobody will audit later.
 *
 * F14-001 is enforced structurally: {@link CAPABILITY_GROUPS} has no wildcard
 * entry, and the five human-only permissions are not in it at all. The copy below
 * says so in the interface rather than leaving it to be inferred, and the human
 * only capabilities are listed in a closed section so an operator who was looking
 * for `data.delete` learns why it is not offered.
 */

import { useId } from "react";

import {
  CAPABILITY_GROUPS,
  HUMAN_ONLY_CAPABILITIES,
  HUMAN_ONLY_REASONS,
  describeScope,
  toggleCapability,
  unknownCapabilities,
} from "./capabilities";
import type { ApiKey, ServiceAccount } from "./api";
import { Notice, checkboxClass } from "./ui";

export function CapabilityPicker({
  selected,
  onChange,
  disabled = false,
  /** Capabilities the server already holds, shown as a reference column. */
  inheritedFrom,
}: {
  selected: readonly string[];
  onChange: (next: string[]) => void;
  disabled?: boolean;
  inheritedFrom?: readonly string[];
}) {
  const inherited = new Set(inheritedFrom ?? []);
  return (
    <div className="space-y-4">
      {CAPABILITY_GROUPS.map((group) => {
        const groupSelected = group.options.filter((option) => selected.includes(option.name));
        return (
          <fieldset
            key={group.id}
            disabled={disabled}
            className="rounded-lg border border-[var(--border)] bg-[var(--panel)]"
          >
            <legend className="px-3 text-xs font-semibold tracking-[0.08em] text-[var(--muted)] uppercase">
              {group.label}
            </legend>
            <div className="divide-y divide-[var(--border)]">
              {group.options.map((option) => {
                const checked = selected.includes(option.name);
                const id = `${group.id}-${option.name.replaceAll(".", "-")}`;
                return (
                  <div key={option.name} className="flex gap-3 px-3 py-2.5">
                    <input
                      id={id}
                      type="checkbox"
                      className={`${checkboxClass} mt-0.5`}
                      checked={checked}
                      disabled={disabled}
                      onChange={() => onChange(toggleCapability(selected, option.name))}
                    />
                    <label htmlFor={id} className="min-w-0 cursor-pointer">
                      <span className="block font-mono text-xs text-[var(--civic-navy)]">
                        {option.name}
                      </span>
                      <span className="mt-0.5 block text-sm leading-5 text-[var(--muted-strong)]">
                        {option.effect}
                      </span>
                      {inherited.has(option.name) ? (
                        <span className="mt-0.5 block text-xs text-[var(--muted)]">
                          Held by the service account; a key can only narrow this list.
                        </span>
                      ) : null}
                    </label>
                  </div>
                );
              })}
            </div>
            {groupSelected.length > 0 ? (
              <p className="border-t border-[var(--border)] px-3 py-2 text-xs text-[var(--muted)]">
                {groupSelected.length} selected in this group
              </p>
            ) : null}
          </fieldset>
        );
      })}
    </div>
  );
}

/**
 * What the credential will be able to do, stated before it exists.
 *
 * The narrowing rule is the part an operator most often gets wrong, so it is
 * stated as its own line rather than folded into a paragraph: a key may hold
 * only what its service account holds.
 */
export function CapabilityPreview({
  subject,
  selected,
  available,
  networkAllowlist,
  expiresAt,
  projectIds,
  modelAliases,
  kind,
}: {
  subject: string;
  selected: readonly string[];
  /** The parent account's capability set, for the narrowing rule. */
  available?: readonly string[];
  networkAllowlist?: readonly string[];
  expiresAt?: string | null;
  projectIds?: readonly string[];
  modelAliases?: readonly string[];
  kind: "service_account" | "api_key";
}) {
  const unknown = unknownCapabilities(selected);
  const widening = available ? selected.filter((name) => !available.includes(name)) : [];

  return (
    <div
      className="rounded-lg border border-[var(--lumi-blue)]/30 bg-[var(--lumi-blue-soft)] p-4"
      aria-label="Permission preview"
    >
      <p className="text-[11px] font-semibold tracking-[0.1em] text-[var(--lumi-blue)] uppercase">
        Permission preview
      </p>
      <h4 className="mt-1.5 text-sm font-semibold text-[var(--civic-navy)]">
        What {subject} will be able to do
      </h4>
      <p className="mt-1 text-sm leading-5 text-[var(--civic-navy)]">{describeScope(selected)}</p>

      <dl className="mt-3 space-y-2 text-sm">
        <PreviewRow term="Authorisation" detail={describeAuthorisation(selected)} />
        {kind === "api_key" && available ? (
          <PreviewRow
            term="Narrowing"
            detail={
              widening.length === 0
                ? "Every selected capability is already held by the service account, so this key can be used."
                : `${widening.join(", ")} ${widening.length === 1 ? "is" : "are"} not held by the service account and will be refused. Widen the account first.`
            }
          />
        ) : null}{" "}
        <PreviewRow
          term="Wildcard"
          detail="Not available. There is no all-capabilities option, and a credential never inherits its creator's permissions."
        />
        <PreviewRow
          term="Human-only actions"
          detail="Not available. Transferring or deleting the organization, leaving it, changing the plan, and deleting data stay with a signed-in person."
        />
        {projectIds ? (
          <PreviewRow
            term="Projects"
            detail={
              projectIds.length === 0
                ? "No project restriction. The key can reach any project in this organization it is otherwise permitted to touch."
                : `Restricted to ${projectIds.length} named ${projectIds.length === 1 ? "project" : "projects"}. A project-scoped key cannot reach another project inside this organization.`
            }
          />
        ) : null}
        {modelAliases ? (
          <PreviewRow
            term="Model aliases"
            detail={
              modelAliases.length === 0
                ? "No alias restriction. Any alias the key is otherwise permitted to use is reachable."
                : `Restricted to ${modelAliases.join(", ")}.`
            }
          />
        ) : null}
        {networkAllowlist ? (
          <PreviewRow
            term="Network"
            detail={
              networkAllowlist.length === 0
                ? "No network restriction. Any caller address is accepted."
                : `Restricted to ${networkAllowlist.length} ${networkAllowlist.length === 1 ? "entry" : "entries"}. If the edge cannot report a caller address the request is denied rather than allowed.`
            }
          />
        ) : null}
        {expiresAt !== undefined ? (
          <PreviewRow
            term="Expiry"
            detail={
              expiresAt
                ? `Expires ${expiresAt}. An expired key is refused even if it has not been revoked.`
                : "No expiry. Revocation is then the only way to stop it."
            }
          />
        ) : null}
        <PreviewRow
          term="Storage"
          detail="The secret is shown once and hashed at rest. A database compromise of the key table alone yields no usable credential."
        />
      </dl>

      {selected.length > 0 ? (
        <ul className="mt-3 flex flex-wrap gap-1.5">
          {selected.map((name) => (
            <li
              key={name}
              className="rounded-md bg-[var(--panel)] px-2 py-1 font-mono text-xs text-[var(--civic-navy)]"
            >
              {name}
            </li>
          ))}
        </ul>
      ) : null}

      {widening.length > 0 ? (
        <div className="mt-3">
          <Notice tone="warning" title="This selection will be refused">
            A key may hold only the capabilities its service account already has. Widen the account
            first, then create the key.
          </Notice>
        </div>
      ) : null}

      {unknown.length > 0 ? (
        <div className="mt-3">
          <Notice tone="warning" title="A capability is not recognised here">
            {unknown.join(", ")} is held by this credential but is not in the vocabulary this
            control plane can describe. Review the credential before trusting it.
          </Notice>
        </div>
      ) : null}
    </div>
  );
}

/**
 * The closed list of human-only capabilities, shown rather than hidden.
 *
 * An operator looking for `data.delete` and finding nothing should be told it is
 * permanently unavailable and why, rather than concluding the feature is missing.
 */
export function HumanOnlyNotice() {
  const id = useId();
  return (
    <details className="rounded-lg border border-[var(--border)] bg-[var(--panel-hover)] p-4">
      <summary className="cursor-pointer text-sm font-semibold text-[var(--civic-navy)] outline-none focus-visible:ring-2 focus-visible:ring-[var(--ring)] focus-visible:ring-offset-2">
        Why some permissions are not offered
      </summary>
      <div id={id} className="mt-3 space-y-3 text-sm leading-5 text-[var(--muted-strong)]">
        <p>
          {HUMAN_ONLY_CAPABILITIES.length} permissions are permanently unavailable to any machine
          credential. The server refuses them before it even looks at the key's scope, so requesting
          one cannot store it either.
        </p>
        <dl className="space-y-2">
          {HUMAN_ONLY_CAPABILITIES.map((capability) => (
            <div key={capability}>
              <dt className="font-mono text-xs text-[var(--civic-navy)]">{capability}</dt>
              <dd className="text-sm leading-5 text-[var(--muted-strong)]">
                {HUMAN_ONLY_REASONS[capability]}
              </dd>
            </div>
          ))}
        </dl>
      </div>
    </details>
  );
}

function PreviewRow({ term, detail }: { term: string; detail: string }) {
  return (
    <div className="grid gap-0.5 sm:grid-cols-[10rem_minmax(0,1fr)] sm:gap-3">
      <dt className="text-xs font-semibold tracking-[0.04em] text-[var(--muted)] uppercase">
        {term}
      </dt>
      <dd className="leading-5 text-[var(--civic-navy)]">{detail}</dd>
    </div>
  );
}

/**
 * One line naming the whole authorisation rule.
 *
 * Three independent checks run before any capability is consulted: the key must
 * authenticate, its owning account must be active, and the target must be inside
 * the key's organization. Saying so prevents the most common misreading of a 403
 * — that the capability list is the whole story.
 */
function describeAuthorisation(selected: readonly string[]): string {
  const count = selected.length;
  const granted =
    count === 0 ? "nothing" : count === 1 ? "one capability" : `${count} capabilities`;
  return `Every request is checked in order: the key authenticates, its service account is active, the target is inside this organization, and only then is ${granted} consulted. A suspended account denies everything regardless of scope or expiry.`;
}

/** The scope of a service account, rendered on the row and the detail surface. */
export function AccountScopeSummary({ account }: { account: ServiceAccount }) {
  return (
    <ScopeSummary
      capabilities={account.capabilities}
      extra={describeAccountExpiry(account.expires_at, account.status, account.suspend_reason)}
    />
  );
}

/** The scope of a key, rendered on the row and the detail surface. */
export function KeyScopeSummary({ apiKey }: { apiKey: ApiKey }) {
  return (
    <ScopeSummary
      capabilities={apiKey.capabilities}
      extra={[
        apiKey.project_ids.length > 0
          ? `${apiKey.project_ids.length} ${apiKey.project_ids.length === 1 ? "project" : "projects"}`
          : "all projects",
        apiKey.model_aliases.length > 0
          ? `${apiKey.model_aliases.length} model aliases`
          : "all model aliases",
        apiKey.network_allowlist.length > 0
          ? `${apiKey.network_allowlist.length} network ${apiKey.network_allowlist.length === 1 ? "entry" : "entries"}`
          : "any network",
      ].join(" · ")}
    />
  );
}

function ScopeSummary({ capabilities, extra }: { capabilities: readonly string[]; extra: string }) {
  return (
    <div className="min-w-0">
      <p className="text-xs text-[var(--muted)]">
        {capabilities.length} {capabilities.length === 1 ? "capability" : "capabilities"} · {extra}
      </p>
      <ul className="mt-1 flex flex-wrap gap-1">
        {capabilities.slice(0, 4).map((name) => (
          <li
            key={name}
            className="rounded bg-[var(--panel-strong)] px-1.5 py-0.5 font-mono text-[11px] text-[var(--muted-strong)]"
          >
            {name}
          </li>
        ))}
        {capabilities.length > 4 ? (
          <li className="rounded bg-[var(--panel-strong)] px-1.5 py-0.5 text-[11px] text-[var(--muted)]">
            +{capabilities.length - 4} more
          </li>
        ) : null}
      </ul>
    </div>
  );
}

function describeAccountExpiry(
  expiresAt: string | null,
  status: ServiceAccount["status"],
  suspendReason: string | null,
): string {
  if (status === "suspended") {
    return suspendReason ? `suspended — ${suspendReason}` : "suspended";
  }
  return expiresAt ? `expires ${expiresAt}` : "no expiry";
}
