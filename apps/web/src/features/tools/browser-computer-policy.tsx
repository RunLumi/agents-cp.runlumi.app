import type { BrowserPolicy, ComputerPolicy, ToolPolicy } from "./helpers";
import {
  ToolDate,
  ToolEmpty,
  ToolError,
  ToolLoading,
  ToolNotice,
  ToolPanel,
  ToolPanelHeader,
  ToolPermission,
  StatusPill,
} from "./ui";

export interface BrowserComputerPolicyProps {
  policy?: ToolPolicy | null;
  loading?: boolean;
  error?: unknown;
  permissionDenied?: boolean;
  onRetry?: () => void;
}

export function BrowserComputerPolicy({
  policy,
  loading = false,
  error,
  permissionDenied = false,
  onRetry,
}: BrowserComputerPolicyProps) {
  if (permissionDenied) {
    return (
      <ToolPanel ariaLabel="Browser and computer policy">
        <ToolPanelHeader
          title="Browser & computer policy"
          description="Server-returned controls for the desktop execution host."
        />
        <div className="p-5">
          <ToolPermission message="Your current organization role cannot view browser or computer policy." />
        </div>
      </ToolPanel>
    );
  }
  if (loading) {
    return (
      <ToolPanel ariaLabel="Browser and computer policy">
        <ToolPanelHeader
          title="Browser & computer policy"
          description="Server-returned controls for the desktop execution host."
        />
        <ToolLoading label="Loading browser and computer policy…" rows={4} />
      </ToolPanel>
    );
  }
  if (error) {
    return (
      <ToolPanel ariaLabel="Browser and computer policy">
        <ToolPanelHeader
          title="Browser & computer policy"
          description="Server-returned controls for the desktop execution host."
        />
        <div className="p-5">
          <ToolError error={error} onRetry={onRetry} />
        </div>
      </ToolPanel>
    );
  }

  const document = policy?.document;
  const expiryTime = policy?.expires_at ? Date.parse(policy.expires_at) : Number.NaN;
  const expired = Number.isFinite(expiryTime) && expiryTime <= Date.now();
  const malformedExpiry = Boolean(policy?.expires_at) && !Number.isFinite(expiryTime);
  const invalid = !document || !document.valid || policy?.policy_state !== "ok" || malformedExpiry;
  const browser = document?.browser;
  const computer = document?.computer;

  return (
    <ToolPanel ariaLabel="Browser and computer policy">
      <ToolPanelHeader
        title="Browser & computer policy"
        description="Effective controls are evaluated on the desktop/runtime host before each sensitive action."
        action={
          <StatusPill tone={invalid || expired ? "danger" : "success"}>
            {invalid ? "Fail closed" : expired ? "Expired" : "Current"}
          </StatusPill>
        }
      />
      <div className="space-y-5 p-5">
        {invalid ? (
          <ToolNotice tone="danger">
            <span className="font-semibold">No usable policy document.</span> Missing, malformed, or
            unsupported sections are treated as denied. The browser does not infer permission from a
            prompt, model response, or local toggle.
            {document?.issues.length ? (
              <span className="mt-1 block text-xs">
                Server validation: {document.issues.join("; ")}
              </span>
            ) : null}
          </ToolNotice>
        ) : expired ? (
          <ToolNotice tone="warning">
            This policy has expired. The runtime must fail closed until it receives a fresh,
            server-authoritative version.
          </ToolNotice>
        ) : (
          <ToolNotice tone="info">
            This is a read-only view of the current policy. Actual browser and computer execution
            remains on the trusted desktop/runtime host.
          </ToolNotice>
        )}

        {policy ? (
          <div className="grid gap-3 sm:grid-cols-3">
            <PolicyFact
              label="Policy version"
              value={String(policy.policy_version || policy.version)}
            />
            <PolicyFact label="Schema" value={String(document?.schema_version ?? "Unavailable")} />
            <PolicyFact
              label="Expires"
              value={policy.expires_at ? <ToolDate value={policy.expires_at} /> : "Not supplied"}
            />
          </div>
        ) : null}

        <PolicySection
          title="Browser"
          description="Domain, transfer, authenticated browsing, clipboard, and external submit controls."
        >
          {browser ? <BrowserPolicyRows policy={browser} /> : <UnavailablePolicy />}
        </PolicySection>

        <PolicySection
          title="Computer use"
          description="Desktop capabilities remain denied unless the server policy explicitly enables them."
        >
          {computer ? <ComputerPolicyRows policy={computer} /> : <UnavailablePolicy />}
        </PolicySection>

        <p className="text-xs leading-5 text-[var(--muted)]">
          Policy precedence is platform hard deny, then organization, project, agent,
          runtime/device, and finally an exact per-run approval. The most restrictive result wins.
        </p>
      </div>
    </ToolPanel>
  );
}

function PolicySection({
  title,
  description,
  children,
}: {
  title: string;
  description: string;
  children: React.ReactNode;
}) {
  return (
    <section className="rounded-lg border border-[var(--border)]">
      <div className="border-b border-[var(--border)] bg-[var(--panel-hover)] px-4 py-3">
        <h3 className="text-sm font-semibold text-[var(--civic-navy)]">{title}</h3>
        <p className="mt-1 text-xs leading-5 text-[var(--muted-strong)]">{description}</p>
      </div>
      <div className="divide-y divide-[var(--border)]">{children}</div>
    </section>
  );
}

function BrowserPolicyRows({ policy }: { policy: BrowserPolicy }) {
  return (
    <>
      <PolicyRow label="Allowed domains" value={<DomainList domains={policy.allowed_domains} />} />
      <PolicyRow label="Blocked domains" value={<DomainList domains={policy.blocked_domains} />} />
      <PolicyRow label="Download" value={<BooleanDecision allowed={policy.allow_download} />} />
      <PolicyRow label="Upload" value={<BooleanDecision allowed={policy.allow_upload} />} />
      <PolicyRow
        label="Authenticated browsing"
        value={<BooleanDecision allowed={policy.allow_authenticated} />}
      />
      <PolicyRow label="Clipboard" value={<BooleanDecision allowed={policy.allow_clipboard} />} />
      <PolicyRow
        label="External submit / send / purchase"
        value={<ExternalSubmitDecision value={policy.external_submit} />}
      />
    </>
  );
}

function ComputerPolicyRows({ policy }: { policy: ComputerPolicy }) {
  return (
    <>
      <PolicyRow
        label="Accessibility"
        value={<BooleanDecision allowed={policy.allow_accessibility} />}
      />
      <PolicyRow
        label="Screen capture"
        value={<BooleanDecision allowed={policy.allow_screen_capture} />}
      />
      <PolicyRow
        label="Keyboard and mouse"
        value={<BooleanDecision allowed={policy.allow_keyboard_mouse} />}
      />
      <PolicyRow
        label="Shell escalation"
        value={<BooleanDecision allowed={policy.allow_shell_escalation} />}
      />
      <PolicyRow
        label="Allowed applications"
        value={
          policy.allowed_applications.length > 0 ? (
            <div className="flex flex-wrap gap-1.5">
              {policy.allowed_applications.map((application) => (
                <StatusPill key={application} tone="info">
                  {application}
                </StatusPill>
              ))}
            </div>
          ) : (
            <span className="text-sm text-[var(--danger)]">No applications allowed</span>
          )
        }
      />
    </>
  );
}

function PolicyRow({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="grid gap-2 px-4 py-3 sm:grid-cols-[minmax(180px,0.8fr)_minmax(0,1.2fr)] sm:items-start sm:gap-4">
      <p className="text-sm font-medium text-[var(--muted-strong)]">{label}</p>
      <div className="min-w-0 text-sm text-[var(--civic-navy)]">{value}</div>
    </div>
  );
}

function BooleanDecision({ allowed }: { allowed: boolean }) {
  return (
    <StatusPill tone={allowed ? "success" : "danger"}>{allowed ? "Allowed" : "Denied"}</StatusPill>
  );
}

function ExternalSubmitDecision({ value }: { value: BrowserPolicy["external_submit"] }) {
  if (value === "allow") return <StatusPill tone="success">Allow</StatusPill>;
  if (value === "require_session_approval") {
    return <StatusPill tone="warning">Session approval</StatusPill>;
  }
  if (value === "require_per_use_approval") {
    return <StatusPill tone="warning">Per-use approval</StatusPill>;
  }
  if (value === "require_approval")
    return <StatusPill tone="warning">Approval required</StatusPill>;
  return <StatusPill tone="danger">Deny</StatusPill>;
}

function DomainList({ domains }: { domains: string[] }) {
  if (domains.length === 0) return <span className="text-sm text-[var(--danger)]">None</span>;
  return (
    <div className="flex flex-wrap gap-1.5">
      {domains.map((domain) => (
        <StatusPill key={domain} tone="neutral">
          {domain}
        </StatusPill>
      ))}
    </div>
  );
}

function UnavailablePolicy() {
  return (
    <ToolEmpty
      title="Section unavailable"
      description="The server did not return a usable section. This capability remains denied until a valid policy is published."
    />
  );
}

function PolicyFact({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="rounded-lg border border-[var(--border)] bg-[var(--panel-hover)] p-3">
      <p className="text-xs text-[var(--muted)]">{label}</p>
      <div className="mt-1 text-sm font-medium text-[var(--civic-navy)]">{value}</div>
    </div>
  );
}
