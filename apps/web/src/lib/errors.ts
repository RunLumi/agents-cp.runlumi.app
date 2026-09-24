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
