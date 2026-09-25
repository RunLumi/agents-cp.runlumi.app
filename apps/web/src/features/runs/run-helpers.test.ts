import { afterEach, describe, expect, it, vi } from "vitest";

import {
  canCancelRun,
  canRetryRun,
  formatBytes,
  formatDuration,
  isAmbiguousRunMutationFailure,
  isPermissionFailure,
  isRunState,
  isTerminalRunState,
  readRunStateFromUrl,
  readSessionFromUrl,
  readSessionLifecycleFromUrl,
  runStateLabel,
  syncRunFiltersToUrl,
} from "@/features/runs/run-helpers";
import { ApiClientError } from "@/lib/errors";

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("run state helpers", () => {
  it("recognizes only canonical P05 run states", () => {
    expect(isRunState("waiting_approval")).toBe(true);
    expect(isRunState("paused")).toBe(false);
    expect(runStateLabel("timed_out")).toBe("timed out");
  });

  it("keeps terminal history immutable", () => {
    expect(isTerminalRunState("succeeded")).toBe(true);
    expect(isTerminalRunState("cancelled")).toBe(true);
    expect(isTerminalRunState("running")).toBe(false);
    expect(canCancelRun("succeeded")).toBe(false);
    expect(canCancelRun("waiting_user")).toBe(true);
  });

  it("offers retry only for unsuccessful terminal attempts", () => {
    expect(canRetryRun("failed")).toBe(true);
    expect(canRetryRun("timed_out")).toBe(true);
    expect(canRetryRun("cancelled")).toBe(true);
    expect(canRetryRun("succeeded")).toBe(false);
    expect(canRetryRun("running")).toBe(false);
  });
});

describe("run action error helpers", () => {
  it("recognizes explicit and project-scoped permission failures", () => {
    expect(
      isPermissionFailure(
        new ApiClientError({
          code: "permission_denied",
          kind: "api",
          status: 403,
          requestId: undefined,
          retryable: false,
        }),
      ),
    ).toBe(true);
    expect(
      isPermissionFailure(
        new ApiClientError({
          code: "project_access_denied",
          kind: "api",
          status: 400,
          requestId: undefined,
          retryable: false,
        }),
      ),
    ).toBe(true);
  });

  it("marks unconfirmed mutations as ambiguous", () => {
    expect(
      isAmbiguousRunMutationFailure(
        new ApiClientError({
          code: "network_error",
          kind: "network",
          status: undefined,
          requestId: undefined,
          retryable: true,
        }),
      ),
    ).toBe(true);
  });
});

describe("run URL filters", () => {
  const orgId = "org_0123456789abcdef0123456789abcdef";
  const sessionId = "rse_0123456789abcdef0123456789abcdef";

  it("restores filters only within the active organization scope", () => {
    const search = new URLSearchParams({
      runs_scope: orgId,
      run_state: "failed",
      run_session: sessionId,
      session_lifecycle: "active",
    });
    vi.stubGlobal("window", {
      location: {
        search: `?${search.toString()}`,
        href: `https://control.example/org/acme/runs?${search.toString()}`,
      },
      history: { state: null, replaceState: vi.fn() },
    });

    expect(readRunStateFromUrl(orgId).value).toBe("failed");
    expect(readSessionFromUrl(orgId).value).toBe(sessionId);
    expect(readSessionLifecycleFromUrl(orgId).value).toBe("active");
    expect(readRunStateFromUrl("org_different").value).toBe("");
    expect(readSessionFromUrl("org_different").value).toBeNull();
  });

  it("removes stale run filter parameters without changing the route", () => {
    const replaceState = vi.fn();
    vi.stubGlobal("window", {
      location: {
        search: "?runs_scope=old&run_state=failed&run_session=invalid",
        href: "https://control.example/org/acme/runs?runs_scope=old&run_state=failed",
      },
      history: { state: { source: "test" }, replaceState },
    });

    syncRunFiltersToUrl(orgId, "", null, "");
    expect(replaceState).toHaveBeenCalledWith({ source: "test" }, "", "/org/acme/runs");
  });
});

describe("run metadata formatting", () => {
  it("formats bounded artifact sizes", () => {
    expect(formatBytes(null)).toBe("Not recorded");
    expect(formatBytes(512)).toBe("512 B");
    expect(formatBytes(1536)).toBe("1.50 KiB");
  });

  it("does not invent duration for incomplete or invalid timestamps", () => {
    expect(formatDuration("2026-09-25T12:00:00.000Z", null)).toBe("In progress or not recorded");
    expect(formatDuration("not-a-date", "also-not-a-date")).toBe("Not recorded");
    expect(formatDuration("2026-09-25T12:00:00.000Z", "2026-09-25T12:01:05.000Z")).toBe("1m 5s");
  });
});
