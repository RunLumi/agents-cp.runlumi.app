import { useCallback, useEffect, useState } from "react";

import { approveDeviceEnrollment, listDevices, revokeDevice, type ManagedDevice } from "@/lib/api";
import { presentApiError } from "@/lib/errors";

interface DevicesPanelProps {
  orgId: string;
  currentUserId: string;
}

type DevicesState =
  | { kind: "loading" }
  | { kind: "ready"; devices: ManagedDevice[] }
  | { kind: "error"; message: string };

/**
 * Org device administration (P03): approve pending enrollments by the
 * enrollment ID shown on the device, review fleet state, revoke devices.
 * Revocation blocks token refresh, policy fetch, and heartbeats server-side.
 */
export function DevicesPanel({ orgId, currentUserId }: DevicesPanelProps) {
  const [state, setState] = useState<DevicesState>({ kind: "loading" });
  const [enrollmentId, setEnrollmentId] = useState("");
  const [actionError, setActionError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    setState({ kind: "loading" });
    try {
      const page = await listDevices(orgId);
      setState({ kind: "ready", devices: page.items });
    } catch (error) {
      const presentation = presentApiError(error);
      setState({ kind: "error", message: `${presentation.title}. ${presentation.message}` });
    }
  }, [orgId]);

  useEffect(() => {
    void load();
  }, [load]);

  async function approve() {
    const trimmed = enrollmentId.trim();
    if (!trimmed || busy) return;
    setBusy(true);
    setActionError(null);
    try {
      await approveDeviceEnrollment(orgId, trimmed, `approve-${trimmed}`);
      setEnrollmentId("");
      await load();
    } catch (error) {
      const presentation = presentApiError(error);
      setActionError(
        presentation.code === "enrollment_expired"
          ? "That enrollment is no longer pending. Ask the device to start again."
          : `${presentation.title}. ${presentation.message}`,
      );
    } finally {
      setBusy(false);
    }
  }

  async function revoke(device: ManagedDevice) {
    if (busy) return;
    setBusy(true);
    setActionError(null);
    try {
      await revokeDevice(orgId, device.id, `revoke-${device.id}`);
      await load();
    } catch (error) {
      const presentation = presentApiError(error);
      setActionError(`${presentation.title}. ${presentation.message}`);
    } finally {
      setBusy(false);
    }
  }

  if (state.kind === "loading") {
    return (
      <p role="status" className="text-sm text-[var(--muted-strong)]">
        Loading devices…
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

  return (
    <section aria-label="Devices" className="space-y-5">
      <div className="rounded-xl border border-[var(--border)] bg-[var(--panel)] p-5 shadow-[var(--shadow)]">
        <h2 className="text-sm font-semibold">Approve device enrollment</h2>
        <p className="mt-1 text-sm text-[var(--muted-strong)]">
          Enter the enrollment ID displayed by the desktop client after it generates its device key.
          Approval is explicit and audited.
        </p>
        <div className="mt-3 flex flex-col gap-2 sm:flex-row">
          <input
            type="text"
            value={enrollmentId}
            onChange={(event) => setEnrollmentId(event.target.value)}
            placeholder="enr_…"
            aria-label="Enrollment ID"
            className="min-h-9 flex-1 rounded-lg border border-[var(--border)] bg-[var(--surface)] px-3 py-1.5 text-sm outline-none focus-visible:ring-2 focus-visible:ring-[var(--lumi-blue)]"
          />
          <button
            type="button"
            onClick={() => void approve()}
            disabled={busy || enrollmentId.trim().length === 0}
            className="min-h-9 rounded-lg bg-[var(--lumi-blue)] px-4 py-1.5 text-sm font-medium text-white outline-none transition hover:bg-[var(--lumi-blue-hover)] focus-visible:ring-2 focus-visible:ring-[var(--lumi-blue)] disabled:cursor-not-allowed disabled:opacity-60"
          >
            {busy ? "Approving…" : "Approve"}
          </button>
        </div>
        {actionError ? (
          <p role="alert" className="mt-3 text-sm text-[var(--danger)]">
            {actionError}
          </p>
        ) : null}
      </div>

      {state.devices.length === 0 ? (
        <p className="text-sm text-[var(--muted-strong)]">No devices enrolled yet.</p>
      ) : (
        <ul className="divide-y divide-[var(--border)] overflow-hidden rounded-xl border border-[var(--border)] bg-[var(--panel)] shadow-[var(--shadow)]">
          {state.devices.map((device) => (
            <li
              key={device.id}
              className="flex flex-col gap-2 p-4 sm:flex-row sm:items-center sm:justify-between"
            >
              <div className="min-w-0">
                <p className="text-sm font-medium">
                  {device.name}{" "}
                  <span
                    className={
                      device.status === "active"
                        ? "ml-1 inline-block rounded-full bg-[var(--success)]/10 px-2 py-0.5 text-xs text-[var(--success)]"
                        : "ml-1 inline-block rounded-full bg-[var(--danger)]/10 px-2 py-0.5 text-xs text-[var(--danger)]"
                    }
                  >
                    {device.status}
                  </span>
                </p>
                <p className="mt-0.5 truncate text-xs text-[var(--muted-strong)]">
                  {device.platform} · v{device.app_version} ·{" "}
                  {device.last_seen_at
                    ? `last seen ${new Date(device.last_seen_at).toLocaleString()}`
                    : "never seen"}
                </p>
                <p className="truncate font-mono text-xs text-[var(--muted)]">{device.id}</p>
              </div>
              {device.status === "active" ? (
                <button
                  type="button"
                  onClick={() => void revoke(device)}
                  disabled={busy}
                  className="min-h-9 self-start rounded-lg border border-[var(--border)] px-3 py-1.5 text-sm font-medium text-[var(--danger)] outline-none transition hover:bg-[var(--danger)]/5 focus-visible:ring-2 focus-visible:ring-[var(--lumi-blue)] disabled:cursor-not-allowed disabled:opacity-60 sm:self-auto"
                >
                  Revoke
                </button>
              ) : (
                <span className="text-xs text-[var(--muted)] self-start sm:self-auto">
                  revoked {device.revoked_at ? new Date(device.revoked_at).toLocaleString() : ""}
                </span>
              )}
            </li>
          ))}
        </ul>
      )}
      <p className="text-xs text-[var(--muted)]">Current member: {currentUserId}</p>
    </section>
  );
}
