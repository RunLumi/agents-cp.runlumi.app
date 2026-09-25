/**
 * Create / edit form for a webhook endpoint.
 *
 * The form mirrors the frozen create/update request shape. It validates the
 * rules an operator can check locally (HTTPS, no userinfo, port 443/8443, at
 * least one exact event name, bounded delivery policy, an auto-disable
 * threshold of at least 10) and states plainly which checks stay server-side:
 * DNS resolution, private/link-local/loopback and cloud-metadata ranges,
 * redirect refusal, and revalidation immediately before each connection.
 */

import { useId, useState } from "react";

import type { CreateWebhookEndpointInput, WebhookEndpoint } from "./api";
import { EventTypePicker } from "./event-type-picker";
import { partitionSubscription, sortEventTypes, validateSubscription } from "./event-types";
import {
  ALLOWED_ENDPOINT_PORTS,
  AUTO_DISABLE_MAX_THRESHOLD,
  AUTO_DISABLE_MIN_THRESHOLD,
  BASE_DELAY_MAX_SECONDS,
  BASE_DELAY_MIN_SECONDS,
  DEFAULT_ENDPOINT_POLICY,
  MAX_ATTEMPTS_MAX,
  MAX_ATTEMPTS_MIN,
  MAX_DELAY_MAX_SECONDS,
  MAX_DELAY_MIN_SECONDS,
  REPLAY_WINDOW_MAX_SECONDS,
  REPLAY_WINDOW_MIN_SECONDS,
  isEndpointInvalid,
  validateEndpointUrl,
} from "./helpers";
import {
  checkboxClass,
  ErrorNotice,
  inputClass,
  Notice,
  primaryButtonClass,
  secondaryButtonClass,
} from "./ui";

export interface EndpointFormValues {
  readonly name: string;
  readonly description: string;
  readonly url: string;
  readonly subscribedEventTypes: readonly string[];
  readonly externalEventTypes: readonly string[];
  readonly enabled: boolean;
  readonly maxAttempts: number;
  readonly baseDelaySeconds: number;
  readonly maxDelaySeconds: number;
  readonly replayWindowSeconds: number;
  readonly autoDisableEnabled: boolean;
  readonly autoDisableThreshold: number;
}

export function emptyEndpointFormValues(): EndpointFormValues {
  return {
    name: "",
    description: "",
    url: "",
    subscribedEventTypes: [],
    externalEventTypes: [],
    enabled: true,
    maxAttempts: DEFAULT_ENDPOINT_POLICY.max_attempts,
    baseDelaySeconds: DEFAULT_ENDPOINT_POLICY.base_delay_seconds,
    maxDelaySeconds: DEFAULT_ENDPOINT_POLICY.max_delay_seconds,
    replayWindowSeconds: DEFAULT_ENDPOINT_POLICY.replay_window_seconds,
    autoDisableEnabled: DEFAULT_ENDPOINT_POLICY.auto_disable_enabled,
    autoDisableThreshold: DEFAULT_ENDPOINT_POLICY.auto_disable_threshold,
  };
}

export function endpointFormValues(endpoint: WebhookEndpoint): EndpointFormValues {
  const { p06, external } = partitionSubscription(endpoint.subscribed_event_types);
  return {
    name: endpoint.name,
    description: endpoint.description ?? "",
    url: endpoint.url,
    subscribedEventTypes: p06,
    externalEventTypes: external,
    enabled: endpoint.enabled,
    maxAttempts: endpoint.max_attempts,
    baseDelaySeconds: endpoint.base_delay_seconds,
    maxDelaySeconds: endpoint.max_delay_seconds,
    replayWindowSeconds: endpoint.replay_window_seconds,
    autoDisableEnabled: endpoint.auto_disable_enabled,
    autoDisableThreshold: endpoint.auto_disable_threshold,
  };
}

export interface EndpointFormValidation {
  readonly input: CreateWebhookEndpointInput | null;
  readonly fieldErrors: Readonly<Record<string, string>>;
}

/** Build the request body, or the field-level reasons it cannot be built. */
export function buildEndpointRequest(values: EndpointFormValues): EndpointFormValidation {
  const fieldErrors: Record<string, string> = {};
  const name = values.name.trim();
  if (name.length === 0)
    fieldErrors["name"] = "Give the endpoint a name an operator will recognize.";
  else if (name.length > 160) fieldErrors["name"] = "The name may be at most 160 characters.";

  const description = values.description.trim();
  if (description.length > 2000) {
    fieldErrors["description"] = "The description may be at most 2000 characters.";
  }

  const urlRejection = validateEndpointUrl(values.url);
  if (urlRejection) fieldErrors["url"] = urlRejection.message;

  const validation = validateSubscription(values.subscribedEventTypes);
  if (!validation.ok) {
    fieldErrors["subscribed_event_types"] = validation.rejections
      .map((rejection) => rejection.message)
      .join(" ");
  }
  if (values.maxAttempts < MAX_ATTEMPTS_MIN || values.maxAttempts > MAX_ATTEMPTS_MAX) {
    fieldErrors["max_attempts"] =
      `Attempts must be between ${MAX_ATTEMPTS_MIN} and ${MAX_ATTEMPTS_MAX}.`;
  }
  if (
    values.baseDelaySeconds < BASE_DELAY_MIN_SECONDS ||
    values.baseDelaySeconds > BASE_DELAY_MAX_SECONDS
  ) {
    fieldErrors["base_delay_seconds"] =
      `Base delay must be between ${BASE_DELAY_MIN_SECONDS} and ${BASE_DELAY_MAX_SECONDS} seconds.`;
  }
  if (
    values.maxDelaySeconds < MAX_DELAY_MIN_SECONDS ||
    values.maxDelaySeconds > MAX_DELAY_MAX_SECONDS
  ) {
    fieldErrors["max_delay_seconds"] =
      `Maximum delay must be between ${MAX_DELAY_MIN_SECONDS} and ${MAX_DELAY_MAX_SECONDS} seconds.`;
  }
  if (values.maxDelaySeconds < values.baseDelaySeconds) {
    fieldErrors["max_delay_seconds"] = "The maximum delay cannot be shorter than the base delay.";
  }
  if (
    values.replayWindowSeconds < REPLAY_WINDOW_MIN_SECONDS ||
    values.replayWindowSeconds > REPLAY_WINDOW_MAX_SECONDS
  ) {
    fieldErrors["replay_window_seconds"] =
      `The replay window must be between ${REPLAY_WINDOW_MIN_SECONDS} and ${REPLAY_WINDOW_MAX_SECONDS} seconds.`;
  }
  if (values.autoDisableEnabled) {
    if (
      values.autoDisableThreshold < AUTO_DISABLE_MIN_THRESHOLD ||
      values.autoDisableThreshold > AUTO_DISABLE_MAX_THRESHOLD
    ) {
      fieldErrors["auto_disable_threshold"] =
        `Auto-disable requires a threshold of at least ${AUTO_DISABLE_MIN_THRESHOLD} consecutive terminal failures.`;
    }
  }

  if (Object.keys(fieldErrors).length > 0) return { input: null, fieldErrors };

  return {
    fieldErrors,
    input: {
      name,
      url: values.url.trim(),
      // One sorted union, so the same logical subscription always serializes
      // identically. The server normalizes the list the same way.
      subscribed_event_types: sortEventTypes([
        ...(validation.ok ? validation.eventTypes : []),
        ...values.externalEventTypes,
      ]),
      description: description.length > 0 ? description : null,
      enabled: values.enabled,
      max_attempts: values.maxAttempts,
      base_delay_seconds: values.baseDelaySeconds,
      max_delay_seconds: values.maxDelaySeconds,
      replay_window_seconds: values.replayWindowSeconds,
      auto_disable_enabled: values.autoDisableEnabled,
      auto_disable_threshold: values.autoDisableEnabled
        ? values.autoDisableThreshold
        : DEFAULT_ENDPOINT_POLICY.auto_disable_threshold,
    },
  };
}

export function EndpointForm({
  mode,
  initialValues,
  busy,
  error,
  onSubmit,
  onCancel,
}: {
  mode: "create" | "edit";
  initialValues: EndpointFormValues;
  busy: boolean;
  error: unknown;
  onSubmit: (input: CreateWebhookEndpointInput) => void;
  onCancel: () => void;
}) {
  const formId = useId();
  const [values, setValues] = useState<EndpointFormValues>(initialValues);
  const [fieldErrors, setFieldErrors] = useState<Readonly<Record<string, string>>>({});

  function update<K extends keyof EndpointFormValues>(key: K, value: EndpointFormValues[K]) {
    setValues((current) => ({ ...current, [key]: value }));
  }

  function submit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const validation = buildEndpointRequest(values);
    setFieldErrors(validation.fieldErrors);
    if (validation.input) onSubmit(validation.input);
  }

  return (
    <form
      onSubmit={(event) => submit(event)}
      className="space-y-5"
      aria-labelledby={`${formId}-title`}
    >
      <div>
        <h3 id={`${formId}-title`} className="text-base font-semibold text-[var(--civic-navy)]">
          {mode === "create" ? "New webhook endpoint" : "Edit webhook endpoint"}
        </h3>
        <p className="mt-1 text-sm leading-5 text-[var(--muted-strong)]">
          The endpoint stores only encrypted secret material and a fingerprint. The signing secret
          is shown once when the endpoint is created or rotated.
        </p>
      </div>

      {error ? <ErrorNotice error={error} title="The endpoint could not be saved" /> : null}
      {isEndpointInvalid(error) ? (
        <Notice tone="warning">
          The server rejected the endpoint configuration. Fix the reported rule, then save again.
        </Notice>
      ) : null}

      <div className="grid gap-4 sm:grid-cols-2">
        <label className="block text-sm font-medium text-[var(--civic-navy)]">
          Name
          <input
            value={values.name}
            onChange={(event) => update("name", event.target.value)}
            maxLength={160}
            required
            disabled={busy}
            aria-invalid={fieldErrors["name"] ? true : undefined}
            className={inputClass}
            placeholder="Billing events"
          />
          {fieldErrors["name"] ? (
            <span role="alert" className="mt-1 block text-xs font-semibold text-[var(--danger)]">
              {fieldErrors["name"]}
            </span>
          ) : null}
        </label>
        <label className="block text-sm font-medium text-[var(--civic-navy)]">
          HTTPS destination
          <input
            value={values.url}
            onChange={(event) => update("url", event.target.value)}
            type="url"
            inputMode="url"
            required
            disabled={busy}
            spellCheck={false}
            aria-invalid={fieldErrors["url"] ? true : undefined}
            className={`${inputClass} font-mono`}
            placeholder="https://hooks.example.com/lumi"
          />
          {fieldErrors["url"] ? (
            <span role="alert" className="mt-1 block text-xs font-semibold text-[var(--danger)]">
              {fieldErrors["url"]}
            </span>
          ) : (
            <span className="mt-1 block text-xs text-[var(--muted)]">
              Ports {ALLOWED_ENDPOINT_PORTS.join(" and ")} only, no credentials in the URL.
            </span>
          )}
        </label>
      </div>

      <label className="block text-sm font-medium text-[var(--civic-navy)]">
        Description <span className="font-normal text-[var(--muted)]">(optional)</span>
        <textarea
          value={values.description}
          onChange={(event) => update("description", event.target.value)}
          rows={2}
          maxLength={2000}
          disabled={busy}
          aria-invalid={fieldErrors["description"] ? true : undefined}
          className={`${inputClass} min-h-[4.5rem] py-2`}
          placeholder="Where these events are consumed"
        />
        {fieldErrors["description"] ? (
          <span role="alert" className="mt-1 block text-xs font-semibold text-[var(--danger)]">
            {fieldErrors["description"]}
          </span>
        ) : null}
      </label>

      <fieldset className="rounded-lg border border-[var(--border)] p-4">
        <legend className="px-1 text-sm font-semibold text-[var(--civic-navy)]">
          Subscribed events
        </legend>
        <div className="mt-2">
          <EventTypePicker
            selected={values.subscribedEventTypes}
            preservedExternal={values.externalEventTypes}
            onChange={(next) => update("subscribedEventTypes", next)}
            disabled={busy}
          />
        </div>
        {fieldErrors["subscribed_event_types"] ? (
          <p role="alert" className="mt-3 text-xs font-semibold text-[var(--danger)]">
            {fieldErrors["subscribed_event_types"]}
          </p>
        ) : null}
      </fieldset>

      <fieldset className="rounded-lg border border-[var(--border)] p-4">
        <legend className="px-1 text-sm font-semibold text-[var(--civic-navy)]">
          Delivery policy
        </legend>
        <p className="text-xs leading-5 text-[var(--muted-strong)]">
          Delivery is at-least-once. A retry keeps the same logical delivery and the same event ID
          and appends a new attempt. Only an HTTP 2xx response is success.
        </p>
        <div className="mt-3 grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          <NumberField
            label="Attempts"
            name="max_attempts"
            value={values.maxAttempts}
            min={MAX_ATTEMPTS_MIN}
            max={MAX_ATTEMPTS_MAX}
            disabled={busy}
            error={fieldErrors["max_attempts"]}
            onChange={(next) => update("maxAttempts", next)}
          />
          <NumberField
            label="Base delay (s)"
            name="base_delay_seconds"
            value={values.baseDelaySeconds}
            min={BASE_DELAY_MIN_SECONDS}
            max={BASE_DELAY_MAX_SECONDS}
            disabled={busy}
            error={fieldErrors["base_delay_seconds"]}
            onChange={(next) => update("baseDelaySeconds", next)}
          />
          <NumberField
            label="Max delay (s)"
            name="max_delay_seconds"
            value={values.maxDelaySeconds}
            min={MAX_DELAY_MIN_SECONDS}
            max={MAX_DELAY_MAX_SECONDS}
            disabled={busy}
            error={fieldErrors["max_delay_seconds"]}
            onChange={(next) => update("maxDelaySeconds", next)}
          />
          <NumberField
            label="Replay window (s)"
            name="replay_window_seconds"
            value={values.replayWindowSeconds}
            min={REPLAY_WINDOW_MIN_SECONDS}
            max={REPLAY_WINDOW_MAX_SECONDS}
            disabled={busy}
            error={fieldErrors["replay_window_seconds"]}
            onChange={(next) => update("replayWindowSeconds", next)}
          />
        </div>
      </fieldset>

      <fieldset className="rounded-lg border border-[var(--border)] p-4">
        <legend className="px-1 text-sm font-semibold text-[var(--civic-navy)]">
          Automatic disable
        </legend>
        <label className="flex min-h-9 items-start gap-2 text-sm text-[var(--civic-navy)]">
          <input
            type="checkbox"
            className={checkboxClass}
            checked={values.autoDisableEnabled}
            disabled={busy}
            onChange={(event) => update("autoDisableEnabled", event.target.checked)}
          />
          <span>
            Disable this endpoint after repeated terminal delivery failures
            <span className="mt-1 block text-xs leading-5 text-[var(--muted-strong)]">
              Off by default. When on, the endpoint is disabled only after at least{" "}
              {AUTO_DISABLE_MIN_THRESHOLD} consecutive terminal failures, and the failure counter is
              shown on the endpoint so an automatic disable is distinguishable from one an operator
              made.
            </span>
          </span>
        </label>
        {values.autoDisableEnabled ? (
          <div className="mt-3 max-w-xs">
            <NumberField
              label="Consecutive failures before disabling"
              name="auto_disable_threshold"
              value={values.autoDisableThreshold}
              min={AUTO_DISABLE_MIN_THRESHOLD}
              max={AUTO_DISABLE_MAX_THRESHOLD}
              disabled={busy}
              error={fieldErrors["auto_disable_threshold"]}
              onChange={(next) => update("autoDisableThreshold", next)}
            />
          </div>
        ) : null}
      </fieldset>

      <label className="flex min-h-9 items-start gap-2 text-sm text-[var(--civic-navy)]">
        <input
          type="checkbox"
          className={checkboxClass}
          checked={values.enabled}
          disabled={busy}
          onChange={(event) => update("enabled", event.target.checked)}
        />
        <span>
          Endpoint enabled
          <span className="mt-1 block text-xs leading-5 text-[var(--muted-strong)]">
            Disabling cancels pending deliveries. Delivered and dead-letter history is kept.
          </span>
        </span>
      </label>

      <Notice tone="info">
        Hostname resolution, loopback, link-local, private, and cloud-metadata ranges, redirect
        refusal, and revalidation immediately before each outbound connection are enforced by the
        API. This form cannot verify them.
      </Notice>

      <div className="flex flex-col-reverse gap-2 sm:flex-row sm:justify-end">
        <button type="button" className={secondaryButtonClass} onClick={onCancel} disabled={busy}>
          Cancel
        </button>
        <button type="submit" className={primaryButtonClass} disabled={busy}>
          {busy
            ? "Saving…"
            : mode === "create"
              ? "Create endpoint and show secret"
              : "Save endpoint changes"}
        </button>
      </div>
      {mode === "edit" ? (
        <p className="text-xs leading-5 text-[var(--muted)]">
          Editing never re-issues the signing secret. Use rotate if the consumer must change keys.
        </p>
      ) : null}
    </form>
  );
}

function NumberField({
  label,
  name,
  value,
  min,
  max,
  disabled,
  error,
  onChange,
}: {
  label: string;
  name: string;
  value: number;
  min: number;
  max: number;
  disabled: boolean;
  error: string | undefined;
  onChange: (value: number) => void;
}) {
  return (
    <label className="block text-xs font-semibold text-[var(--muted-strong)]">
      {label}
      <input
        type="number"
        name={name}
        value={value}
        min={min}
        max={max}
        step={1}
        disabled={disabled}
        aria-invalid={error ? true : undefined}
        onChange={(event) => {
          const next = Number.parseInt(event.target.value, 10);
          onChange(Number.isSafeInteger(next) ? next : min);
        }}
        className={`${inputClass} tabular-nums`}
      />
      <span className="mt-1 block font-normal text-[var(--muted)]">
        {min}–{max}
      </span>
      {error ? (
        <span role="alert" className="mt-1 block font-semibold text-[var(--danger)]">
          {error}
        </span>
      ) : null}
    </label>
  );
}
