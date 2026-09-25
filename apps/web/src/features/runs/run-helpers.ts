import { RUN_STATES, type AgentSessionLifecycle, type RunState } from "@/lib/api";
import { ApiClientError } from "@/lib/errors";

export { RUN_STATES };
export type { RunState };

const TERMINAL_STATES = new Set<RunState>(["succeeded", "failed", "cancelled", "timed_out"]);
const RETRYABLE_STATES = new Set<RunState>(["failed", "cancelled", "timed_out"]);

export function isRunState(value: string): value is RunState {
  return (RUN_STATES as readonly string[]).includes(value);
}

export function runStateLabel(value: string): string {
  if (!isRunState(value)) return "Unknown";
  return value.replaceAll("_", " ");
}

export function isTerminalRunState(value: string): boolean {
  return isRunState(value) && TERMINAL_STATES.has(value);
}

export function canCancelRun(value: string): boolean {
  return isRunState(value) && !TERMINAL_STATES.has(value);
}

export function canRetryRun(value: string): boolean {
  return isRunState(value) && RETRYABLE_STATES.has(value);
}

export function isPermissionFailure(error: unknown): boolean {
  return (
    error instanceof ApiClientError &&
    (error.status === 403 || ["permission_denied", "project_access_denied"].includes(error.code))
  );
}

export function isRunVersionConflict(error: unknown): boolean {
  return (
    error instanceof ApiClientError &&
    [
      "version_conflict",
      "invalid_run_transition",
      "run_terminal",
      "run_cancel_not_allowed",
      "run_retry_not_allowed",
    ].includes(error.code)
  );
}

export function isAmbiguousRunMutationFailure(error: unknown): boolean {
  return (
    error instanceof ApiClientError &&
    (error.kind === "network" ||
      error.kind === "invalid_response" ||
      error.code === "idempotency_in_progress" ||
      error.status === 408 ||
      error.status === 429 ||
      (error.status !== undefined && error.status >= 500))
  );
}

export function formatDateTime(value: string | null | undefined): string {
  if (!value) return "Not recorded";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

export function formatDuration(startedAt: string | null, finishedAt: string | null): string {
  if (!startedAt || !finishedAt) return "In progress or not recorded";
  const started = new Date(startedAt).getTime();
  const finished = new Date(finishedAt).getTime();
  if (!Number.isFinite(started) || !Number.isFinite(finished) || finished < started)
    return "Not recorded";

  const totalSeconds = Math.max(0, Math.round((finished - started) / 1000));
  if (totalSeconds < 60) return `${totalSeconds}s`;
  const minutes = Math.floor(totalSeconds / 60);
  const seconds = totalSeconds % 60;
  if (minutes < 60) return seconds === 0 ? `${minutes}m` : `${minutes}m ${seconds}s`;
  const hours = Math.floor(minutes / 60);
  const remainingMinutes = minutes % 60;
  return remainingMinutes === 0 ? `${hours}h` : `${hours}h ${remainingMinutes}m`;
}

export function formatBytes(value: number | null): string {
  if (value === null || !Number.isFinite(value) || value < 0) return "Not recorded";
  if (value < 1024) return `${value} B`;
  const units = ["KiB", "MiB", "GiB", "TiB"] as const;
  let amount = value / 1024;
  let unitIndex = 0;
  while (amount >= 1024 && unitIndex < units.length - 1) {
    amount /= 1024;
    unitIndex += 1;
  }
  return `${amount.toFixed(amount >= 10 ? 1 : 2)} ${units[unitIndex]}`;
}

interface ScopedUrlValue<T> {
  orgId: string;
  value: T;
}

const runScopeUrlParam = "runs_scope";
const runStateUrlParam = "run_state";
const runSessionUrlParam = "run_session";
const sessionLifecycleUrlParam = "session_lifecycle";

function currentUrlParams(orgId: string): URLSearchParams | null {
  if (typeof window === "undefined") return null;
  const params = new URLSearchParams(window.location.search);
  return params.get(runScopeUrlParam) === orgId ? params : null;
}

export function readRunStateFromUrl(orgId: string): ScopedUrlValue<RunState | ""> {
  const value = currentUrlParams(orgId)?.get(runStateUrlParam) ?? "";
  return { orgId, value: isRunState(value) ? value : "" };
}

export function readSessionFromUrl(orgId: string): ScopedUrlValue<string | null> {
  const value = currentUrlParams(orgId)?.get(runSessionUrlParam) ?? "";
  return { orgId, value: /^rse_[a-f0-9]{32}$/.test(value) ? value : null };
}

export function readSessionLifecycleFromUrl(
  orgId: string,
): ScopedUrlValue<AgentSessionLifecycle | ""> {
  const value = currentUrlParams(orgId)?.get(sessionLifecycleUrlParam);
  return {
    orgId,
    value: value === "active" || value === "closed" || value === "archived" ? value : "",
  };
}

export function syncRunFiltersToUrl(
  orgId: string,
  runState: RunState | "",
  sessionId: string | null,
  sessionLifecycle: AgentSessionLifecycle | "",
): void {
  if (typeof window === "undefined") return;
  const url = new URL(window.location.href);
  const normalizedSessionId = sessionId && /^rse_[a-f0-9]{32}$/.test(sessionId) ? sessionId : null;
  const hasFilter = Boolean(runState || normalizedSessionId || sessionLifecycle);
  if (hasFilter) url.searchParams.set(runScopeUrlParam, orgId);
  else url.searchParams.delete(runScopeUrlParam);

  if (runState) url.searchParams.set(runStateUrlParam, runState);
  else url.searchParams.delete(runStateUrlParam);

  if (normalizedSessionId) url.searchParams.set(runSessionUrlParam, normalizedSessionId);
  else url.searchParams.delete(runSessionUrlParam);

  if (sessionLifecycle) url.searchParams.set(sessionLifecycleUrlParam, sessionLifecycle);
  else url.searchParams.delete(sessionLifecycleUrlParam);

  window.history.replaceState(window.history.state, "", `${url.pathname}${url.search}${url.hash}`);
}
