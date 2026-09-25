import { useEffect, useState } from "react";

import {
  listSecurityEvents,
  listSessions,
  reauthenticate,
  revokeSession,
  type MeResponse,
  type SecurityEvent,
  type SessionSummary,
} from "@/lib/api";
import { presentApiError } from "@/lib/errors";

export function AccountPanel({ me }: { me: MeResponse }) {
  const [sessions, setSessions] = useState<SessionSummary[]>([]);
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);

  async function load() {
    setBusy(true);
    setError(null);
    try {
      const [sessionPage, eventPage] = await Promise.all([listSessions(), listSecurityEvents()]);
      setSessions(sessionPage.items);
      setEvents(eventPage.items);
    } catch (requestError) {
      setError(requestError);
    } finally {
      setBusy(false);
    }
  }

  useEffect(() => {
    void load();
  }, []);

  async function revoke(sessionId: string) {
    setBusy(true);
    setError(null);
    try {
      await revokeSession(sessionId);
      setNotice("The selected session was revoked.");
      await load();
    } catch (requestError) {
      setError(requestError);
    } finally {
      setBusy(false);
    }
  }

  async function reauth() {
    setBusy(true);
    setError(null);
    try {
      const grant = await reauthenticate();
      setNotice(
        `A security check is valid until ${new Date(grant.expires_at).toLocaleTimeString()}.`,
      );
    } catch (requestError) {
      setError(requestError);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="space-y-6">
      <section className="rounded-xl border border-[var(--border)] bg-[var(--panel)] p-5 shadow-[var(--shadow)]">
        <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
          <div>
            <h2 className="text-base font-semibold text-[var(--civic-navy)]">Account security</h2>
            <p className="mt-1 text-sm text-[var(--muted-strong)]">
              Review active sessions and recent security events for {me.user.email}.
            </p>
          </div>
          <button
            type="button"
            onClick={() => void reauth()}
            disabled={busy}
            className={secondaryButton}
          >
            Start security check
          </button>
        </div>
        {notice ? (
          <p
            role="status"
            className="mt-4 rounded-lg border border-[var(--success)]/30 bg-[var(--success)]/5 p-3 text-sm text-[var(--success)]"
          >
            {notice}
          </p>
        ) : null}
        {error ? (
          <p
            role="alert"
            className="mt-4 rounded-lg border border-[var(--danger)]/30 bg-[var(--danger)]/5 p-3 text-sm text-[var(--danger)]"
          >
            {presentApiError(error).message}
          </p>
        ) : null}
        <div className="mt-5 grid gap-3 sm:grid-cols-2">
          <Info label="Email" value={me.user.email} />
          <Info label="Verification" value={me.user.email_verified ? "Verified" : "Pending"} />
        </div>
      </section>
      <section className="overflow-hidden rounded-xl border border-[var(--border)] bg-[var(--panel)] shadow-[var(--shadow)]">
        <div className="flex items-center justify-between border-b border-[var(--border)] px-5 py-4">
          <div>
            <h2 className="text-base font-semibold text-[var(--civic-navy)]">Active sessions</h2>
            <p className="mt-1 text-sm text-[var(--muted-strong)]">
              Revoking a session blocks its next refresh immediately.
            </p>
          </div>
          <button
            type="button"
            onClick={() => void load()}
            disabled={busy}
            className={secondaryButton}
          >
            Refresh
          </button>
        </div>
        {sessions.length === 0 ? (
          <p className="p-5 text-sm text-[var(--muted)]">No active sessions found.</p>
        ) : (
          <ul className="divide-y divide-[var(--border)]">
            {sessions.map((session) => (
              <li
                key={session.session_id}
                className="flex flex-col gap-3 px-5 py-4 sm:flex-row sm:items-center sm:justify-between"
              >
                <div>
                  <p className="font-medium text-[var(--civic-navy)]">{session.device_label}</p>
                  <p className="mt-1 text-xs tabular-nums text-[var(--muted)]">
                    {session.platform} · Last seen {new Date(session.last_seen_at).toLocaleString()}
                  </p>
                </div>
                <button
                  type="button"
                  onClick={() => void revoke(session.session_id)}
                  disabled={busy}
                  className={dangerButton}
                >
                  Revoke
                </button>
              </li>
            ))}
          </ul>
        )}
      </section>
      <section className="overflow-hidden rounded-xl border border-[var(--border)] bg-[var(--panel)] shadow-[var(--shadow)]">
        <div className="border-b border-[var(--border)] px-5 py-4">
          <h2 className="text-base font-semibold text-[var(--civic-navy)]">Security activity</h2>
          <p className="mt-1 text-sm text-[var(--muted-strong)]">
            Material account and organization changes are recorded as immutable events.
          </p>
        </div>
        {events.length === 0 ? (
          <p className="p-5 text-sm text-[var(--muted)]">No recent security activity.</p>
        ) : (
          <ul className="divide-y divide-[var(--border)]">
            {events.slice(0, 12).map((event) => (
              <li key={event.event_id} className="flex items-start justify-between gap-4 px-5 py-3">
                <div>
                  <p className="text-sm font-medium text-[var(--civic-navy)]">{event.action}</p>
                  <p className="mt-1 text-xs tabular-nums text-[var(--muted)]">
                    {new Date(event.created_at).toLocaleString()}
                  </p>
                </div>
                <span className="text-xs text-[var(--muted)]">{event.outcome}</span>
              </li>
            ))}
          </ul>
        )}
      </section>
    </div>
  );
}

function Info({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <p className="text-xs text-[var(--muted)]">{label}</p>
      <p className="mt-1 text-sm text-[var(--civic-navy)]">{value}</p>
    </div>
  );
}
const secondaryButton =
  "min-h-10 rounded-lg border border-[var(--lumi-blue)]/40 bg-[var(--panel)] px-3 text-sm font-medium text-[var(--lumi-blue)] outline-none transition hover:border-[var(--lumi-blue)]/60 hover:bg-[var(--lumi-blue-soft)] active:translate-y-px focus-visible:ring-2 focus-visible:ring-[var(--ring)] focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50";
const dangerButton =
  "min-h-10 rounded-lg border border-[var(--danger)]/40 bg-[var(--panel)] px-3 text-sm font-medium text-[var(--danger)] outline-none transition hover:bg-[var(--danger)]/5 active:translate-y-px focus-visible:ring-2 focus-visible:ring-[var(--ring)] focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50";
