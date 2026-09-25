export type ApiErrorKind = "api" | "network" | "invalid_response" | "aborted";

export interface ApiClientErrorOptions {
  code: string;
  kind: ApiErrorKind;
  status: number | undefined;
  requestId: string | undefined;
  details?: Record<string, unknown>;
  retryable: boolean;
}

/** A normalized failure from an API request. Server prose is deliberately not exposed. */
export class ApiClientError extends Error {
  readonly code: string;
  readonly kind: ApiErrorKind;
  readonly status: number | undefined;
  readonly requestId: string | undefined;
  readonly details: Readonly<Record<string, unknown>>;
  readonly retryable: boolean;

  constructor(options: ApiClientErrorOptions) {
    super("The request could not be completed.");
    this.name = "ApiClientError";
    this.code = options.code;
    this.kind = options.kind;
    this.status = options.status;
    this.requestId = options.requestId;
    this.details = options.details ?? {};
    this.retryable = options.retryable;
  }
}

export interface ErrorPresentation {
  title: string;
  message: string;
  code: string;
  requestId: string | undefined;
  retryable: boolean;
}

/** Convert API state into safe, user-facing copy without displaying server messages. */
export function presentApiError(error: unknown): ErrorPresentation {
  if (!(error instanceof ApiClientError)) {
    return {
      title: "Something went wrong",
      message: "The request could not be completed. Try again or contact your administrator.",
      code: "unknown_error",
      requestId: undefined,
      retryable: false,
    };
  }

  if (error.status === 401 || error.code === "authentication_required") {
    return {
      title: "Sign-in required",
      message: "Sign in again, then retry this request.",
      code: error.code,
      requestId: error.requestId,
      retryable: error.retryable,
    };
  }

  const p05Presentation = presentP05Error(error);
  if (p05Presentation) return p05Presentation;

  if (error.status === 403 || error.code === "permission_denied") {
    return {
      title: "Access not permitted",
      message: "Ask an administrator to grant access to this action.",
      code: error.code,
      requestId: error.requestId,
      retryable: error.retryable,
    };
  }

  if (error.status === 404 || error.code === "not_found") {
    return {
      title: "This resource could not be found",
      message: "Reload the page. If the problem continues, contact your administrator.",
      code: error.code,
      requestId: error.requestId,
      retryable: error.retryable,
    };
  }

  if ((error.status !== undefined && error.status >= 500) || error.code === "service_unavailable") {
    return {
      title: "The service is temporarily unavailable",
      message: "Wait a moment, then try again.",
      code: error.code,
      requestId: error.requestId,
      retryable: error.retryable,
    };
  }

  if (error.kind === "network") {
    return {
      title: "The API could not be reached",
      message: "Check your connection, then try again.",
      code: error.code,
      requestId: error.requestId,
      retryable: error.retryable,
    };
  }

  if (error.kind === "aborted") {
    return {
      title: "Request canceled",
      message: "Start the request again when you are ready.",
      code: error.code,
      requestId: error.requestId,
      retryable: false,
    };
  }

  if (error.kind === "invalid_response") {
    return {
      title: "The API returned an unexpected response",
      message: "Try again. If the problem continues, contact your administrator.",
      code: error.code,
      requestId: error.requestId,
      retryable: error.retryable,
    };
  }

  return {
    title: "The request could not be completed",
    message: "Try again if the problem continues, contact your administrator.",
    code: error.code,
    requestId: error.requestId,
    retryable: error.retryable,
  };
}

const P05_OPERATIONAL_CODES = new Set([
  "agent_not_found",
  "session_not_found",
  "run_not_found",
  "invalid_run_transition",
  "run_terminal",
  "run_retry_not_allowed",
  "run_cancel_not_allowed",
  "project_access_denied",
  "device_not_approved",
  "device_revoked",
  "tool_not_found",
  "tool_fingerprint_changed",
  "tool_denied",
  "approval_required",
  "approval_not_found",
  "approval_already_resolved",
  "approval_expired",
  "mcp_source_not_allowed",
  "mcp_tool_requires_review",
  "browser_action_denied",
  "computer_action_denied",
  "budget_exceeded",
  "budget_state_unavailable",
  "reservation_not_found",
  "reservation_already_reconciled",
  "rate_limit_exceeded",
  "concurrency_limit_exceeded",
  "usage_reconciliation_conflict",
  "artifact_not_found",
  "rate_limit_state_unavailable",
]);

function presentP05Error(error: ApiClientError): ErrorPresentation | undefined {
  const reason = error.details.reason;
  const code = P05_OPERATIONAL_CODES.has(error.code)
    ? error.code
    : typeof reason === "string" && P05_OPERATIONAL_CODES.has(reason)
      ? reason
      : error.code;
  switch (code) {
    case "agent_not_found":
      return p05Presentation(
        error,
        "Agent definition not found",
        "The requested agent definition is not available in your current organization scope.",
      );
    case "session_not_found":
      return p05Presentation(
        error,
        "Session not found",
        "The requested session is not available in your current organization scope.",
      );
    case "run_not_found":
      return p05Presentation(
        error,
        "Run not found",
        "The requested run is not available in your current organization scope.",
      );
    case "invalid_run_transition":
      return p05Presentation(
        error,
        "Run state changed",
        "This run can no longer accept that action. Refresh the run before trying again.",
      );
    case "run_terminal":
      return p05Presentation(
        error,
        "Run is already finished",
        "The run has a terminal state and its history is immutable.",
      );
    case "run_retry_not_allowed":
      return p05Presentation(
        error,
        "Run cannot be retried",
        "This run cannot be retried from its current state. Start a new run under current policy instead.",
      );
    case "run_cancel_not_allowed":
      return p05Presentation(
        error,
        "Run cannot be canceled",
        "This run is no longer in a cancellable state. Refresh to see the current status.",
      );
    case "project_access_denied":
      return p05Presentation(
        error,
        "Project access not permitted",
        "Your current organization membership cannot access this project. Ask an administrator to review access.",
      );
    case "device_not_approved":
      return p05Presentation(
        error,
        "Device approval required",
        "The execution device is not approved for managed work. Complete device enrollment before retrying.",
      );
    case "device_revoked":
      return p05Presentation(
        error,
        "Device access revoked",
        "The execution device is no longer active. Re-enroll or use an approved device before retrying.",
      );
    case "tool_not_found":
      return p05Presentation(
        error,
        "Tool not found",
        "The requested tool is not available in the current policy scope.",
      );
    case "tool_fingerprint_changed":
      return p05Presentation(
        error,
        "Tool review required",
        "The tool fingerprint changed. Review the catalog and current policy before using it again.",
      );
    case "tool_denied":
      return p05Presentation(
        error,
        "Tool action denied",
        "Organization policy does not allow this tool action.",
      );
    case "approval_required":
      return p05Presentation(
        error,
        "Approval required",
        "A human must approve this action before the execution host can continue.",
      );
    case "approval_not_found":
      return p05Presentation(
        error,
        "Approval not found",
        "The requested approval is not available in your current organization scope.",
      );
    case "approval_already_resolved":
      return p05Presentation(
        error,
        "Approval already resolved",
        "This approval has already been decided and cannot be changed again.",
      );
    case "approval_expired":
      return p05Presentation(
        error,
        "Approval expired",
        "The approval window has closed. Request a new approval for the exact action.",
      );
    case "mcp_source_not_allowed":
      return p05Presentation(
        error,
        "MCP source not allowed",
        "The organization policy does not allow this MCP source.",
      );
    case "mcp_tool_requires_review":
      return p05Presentation(
        error,
        "MCP tool review required",
        "A new or changed MCP tool is not approved for use. Review its fingerprint and source first.",
      );
    case "browser_action_denied":
      return p05Presentation(
        error,
        "Browser action denied",
        "Organization policy does not allow this browser action.",
      );
    case "computer_action_denied":
      return p05Presentation(
        error,
        "Computer action denied",
        "Organization policy does not allow this computer-use action.",
      );
    case "budget_exceeded":
      return p05Presentation(
        error,
        "Budget limit reached",
        "This request cannot continue under the current budget. Review the budget before retrying.",
      );
    case "budget_state_unavailable":
    case "rate_limit_state_unavailable":
      return p05Presentation(
        error,
        "Control state unavailable",
        "The service could not verify the current control state. Do not treat it as available; retry when state is readable.",
      );
    case "reservation_not_found":
      return p05Presentation(
        error,
        "Budget reservation not found",
        "The requested budget reservation is not available in your current organization scope.",
      );
    case "reservation_already_reconciled":
      return p05Presentation(
        error,
        "Reservation already reconciled",
        "This budget reservation already has a terminal reconciliation result.",
      );
    case "rate_limit_exceeded":
      return p05Presentation(
        error,
        "Rate limit reached",
        "The current request or token rate limit was reached. Wait before retrying.",
      );
    case "concurrency_limit_exceeded":
      return p05Presentation(
        error,
        "Concurrency limit reached",
        "The maximum number of active managed requests is already in use. Wait before retrying.",
      );
    case "usage_reconciliation_conflict":
      return p05Presentation(
        error,
        "Usage reconciliation conflict",
        "The provider usage or cost does not match the immutable usage record. Review the accounting state.",
      );
    case "artifact_not_found":
      return p05Presentation(
        error,
        "Artifact not found",
        "The requested artifact reference is not available in your current organization scope.",
      );
    default:
      return undefined;
  }
}

function p05Presentation(error: ApiClientError, title: string, message: string): ErrorPresentation {
  return {
    title,
    message,
    code: error.code,
    requestId: error.requestId,
    retryable: error.retryable,
  };
}

export function apiErrorFromEnvelope(
  status: number,
  payload: unknown,
  headerRequestId: string | undefined,
  retryable: boolean,
): ApiClientError {
  const root = asRecord(payload);
  const envelope = asRecord(root?.error);
  const candidateCode = nonEmptyString(envelope?.code);
  const code =
    candidateCode &&
    candidateCode.length <= 96 &&
    /^[a-z][a-z0-9]*(?:_[a-z0-9]+)*$/.test(candidateCode)
      ? candidateCode
      : undefined;
  const bodyRequestId = boundedRequestId(envelope?.request_id);
  const requestId = headerRequestId ?? bodyRequestId;
  const details = asRecord(envelope?.details);

  if (!envelope || !code || typeof envelope.message !== "string" || !bodyRequestId || !details) {
    return new ApiClientError({
      code: "invalid_error_response",
      kind: "invalid_response",
      status,
      requestId,
      retryable,
    });
  }

  return new ApiClientError({
    code,
    kind: "api",
    status,
    requestId,
    details,
    retryable,
  });
}

export function makeTransportError(
  cause: unknown,
  signal: AbortSignal | undefined,
  options: {
    requestId?: string | undefined;
    status?: number | undefined;
    retryable: boolean;
  },
): ApiClientError {
  const aborted =
    signal?.aborted === true || (cause instanceof Error && cause.name === "AbortError");
  return new ApiClientError({
    code: aborted ? "request_aborted" : "network_error",
    kind: aborted ? "aborted" : "network",
    status: options.status,
    requestId: options.requestId,
    retryable: aborted ? false : options.retryable,
  });
}

export function makeInvalidResponseError(options: {
  requestId?: string | undefined;
  status?: number | undefined;
  retryable?: boolean | undefined;
}): ApiClientError {
  return new ApiClientError({
    code: "invalid_response",
    kind: "invalid_response",
    status: options.status,
    requestId: options.requestId,
    retryable: options.retryable ?? false,
  });
}

function asRecord(value: unknown): Record<string, unknown> | undefined {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return undefined;
  return value as Record<string, unknown>;
}

function nonEmptyString(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  const normalized = value.trim();
  return normalized.length > 0 ? normalized : undefined;
}

function boundedRequestId(value: unknown): string | undefined {
  const normalized = nonEmptyString(value);
  return normalized && normalized.length <= 160 ? normalized : undefined;
}
