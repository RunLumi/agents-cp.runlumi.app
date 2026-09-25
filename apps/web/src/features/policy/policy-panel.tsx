import { useCallback, useEffect, useState } from "react";

import { getOrgPolicy, type PolicySnapshot } from "@/lib/api";
import { presentApiError } from "@/lib/errors";

interface PolicyPanelProps {
  orgId: string;
}

type PolicyState =
  | { kind: "loading" }
  | { kind: "ready"; snapshot: PolicySnapshot }
  | { kind: "empty" }
  | { kind: "error"; message: string };

/**
 * Read-only effective policy inspector (plan03 P03-FE-03). Displays the
 * latest versioned snapshot; P04/P05 sections are shown as opaque JSON
 * placeholders until those phases own them.
 */
export function PolicyPanel({ orgId }: PolicyPanelProps) {
  const [state, setState] = useState<PolicyState>({ kind: "loading" });

  const load = useCallback(async () => {
    setState({ kind: "loading" });
    try {
      const snapshot = await getOrgPolicy(orgId);
      setState({ kind: "ready", snapshot });
    } catch (error) {
      const presentation = presentApiError(error);
      if (presentation.code === "not_found") {
        setState({ kind: "empty" });
        return;
      }
      setState({ kind: "error", message: `${presentation.title}. ${presentation.message}` });
    }
  }, [orgId]);

  useEffect(() => {
    void load();
  }, [load]);

  if (state.kind === "loading") {
    return (
      <p role="status" className="text-sm text-[var(--muted-strong)]">
        Loading policy…
      </p>
    );
  }
  if (state.kind === "empty") {
    return (
      <p className="text-sm text-[var(--muted-strong)]">
        No policy snapshot has been published for this organization yet. It is generated when the
        first device enrolls or a workspace binding changes.
      </p>
    );
  }
  if (state.kind === "error") {
    return (
      <p role="alert" className="text-sm text-[var(--danger)]">
        {state.message}
      </p>
    );
  }

  const expired = state.snapshot.expires_at <= new Date().toISOString();

  return (
    <section aria-label="Effective policy" className="space-y-5">
      <div className="rounded-xl border border-[var(--border)] bg-[var(--panel)] p-5 shadow-[var(--shadow)]">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <h2 className="text-sm font-semibold">Policy version {state.snapshot.policy_version}</h2>
          <span
            className={
              expired
                ? "inline-block rounded-full bg-[var(--danger)]/10 px-2 py-0.5 text-xs text-[var(--danger)]"
                : "inline-block rounded-full bg-[var(--success)]/10 px-2 py-0.5 text-xs text-[var(--success)]"
            }
          >
            {expired ? "expired" : "current"}
          </span>
        </div>
        <p className="mt-1 text-xs text-[var(--muted-strong)]">
          Issued {new Date(state.snapshot.issued_at).toLocaleString()} · expires{" "}
          {new Date(state.snapshot.expires_at).toLocaleString()}
        </p>
      </div>

      <div className="space-y-3">
        {Object.entries(state.snapshot.payload).map(([section, value]) => (
          <details
            key={section}
            className="rounded-xl border border-[var(--border)] bg-[var(--panel)] shadow-[var(--shadow)]"
          >
            <summary className="cursor-pointer px-4 py-3 text-sm font-medium outline-none focus-visible:ring-2 focus-visible:ring-[var(--lumi-blue)]">
              {section}
            </summary>
            <pre className="overflow-x-auto border-t border-[var(--border)] px-4 py-3 font-mono text-xs leading-5 text-[var(--muted-strong)]">
              {JSON.stringify(value, null, 2)}
            </pre>
          </details>
        ))}
      </div>

      <p className="text-xs text-[var(--muted)]">
        The snapshot is read-only here. Devices receive the same versioned content, audience-bound
        to their enrollment, and acknowledge it.
      </p>
    </section>
  );
}
