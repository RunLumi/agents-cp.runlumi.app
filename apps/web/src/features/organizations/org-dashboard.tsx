import {
  lazy,
  Suspense,
  useEffect,
  useId,
  useMemo,
  useRef,
  useState,
  type ComponentType,
} from "react";

import { LumiWordmark } from "@/components/brand";
import {
  IconHome,
  IconLogout,
  IconMenu,
  IconRoute,
  IconRun,
  IconShieldLock,
  IconToolShield,
  IconUsers,
  IconUsersGroup,
  IconX,
} from "@/components/icons";
import { AccountPanel as AccountSecurityPanel } from "@/features/account/account-panel";
import { DevicesPanel } from "@/features/devices/devices-panel";
import { ModelsRoutingPanel } from "@/features/models/models-routing-panel";
import { PolicyPanel } from "@/features/policy/policy-panel";
import { ProjectsPanel } from "@/features/projects/projects-panel";
import {
  changeMemberRole,
  createOrganization,
  createTeam,
  getOrganization,
  inviteMember,
  listMembers,
  listTeams,
  type Membership,
  type MeResponse,
  type Organization,
  type OrganizationSummary,
  type Team,
} from "@/lib/api";
import { presentApiError } from "@/lib/errors";

const RunsPanel = lazy(() =>
  import("@/features/runs/runs-panel").then((module) => ({ default: module.RunsPanel })),
);
const ToolsPanel = lazy(() =>
  import("@/features/tools/tools-panel").then((module) => ({ default: module.ToolsPanel })),
);
const UsageBudgetsPanel = lazy(() =>
  import("@/features/usage/usage-budgets-panel").then((module) => ({
    default: module.UsageBudgetsPanel,
  })),
);

interface OrgDashboardProps {
  me: MeResponse;
  onSignOut: () => void;
  onOrganizationsChanged: () => void;
}

type Section =
  | "overview"
  | "members"
  | "teams"
  | "projects"
  | "runs"
  | "tools"
  | "usage"
  | "devices"
  | "policy"
  | "models"
  | "account";

const sections: { id: Section; label: string; icon: ComponentType<{ className?: string }> }[] = [
  { id: "overview", label: "Overview", icon: IconHome },
  { id: "projects", label: "Projects", icon: IconHome },
  { id: "runs", label: "Agents & runs", icon: IconRun },
  { id: "members", label: "Members", icon: IconUsers },
  { id: "teams", label: "Teams", icon: IconUsersGroup },
  { id: "tools", label: "Tools & approvals", icon: IconToolShield },
  { id: "models", label: "Models & routing", icon: IconRoute },
  { id: "usage", label: "Usage & budgets", icon: IconRoute },
  { id: "devices", label: "Devices", icon: IconUsers },
  { id: "policy", label: "Policy", icon: IconShieldLock },
  { id: "account", label: "Account security", icon: IconShieldLock },
];

type LoadState =
  | { kind: "loading" }
  | { kind: "ready"; organization: Organization; members: Membership[]; teams: Team[] }
  | { kind: "error"; error: unknown };

export function OrgDashboard({ me, onSignOut, onOrganizationsChanged }: OrgDashboardProps) {
  const [selectedId, setSelectedId] = useState(me.organizations[0]?.organization.org_id ?? "");
  const [section, setSection] = useState<Section>(() => {
    const path = window.location.pathname.split("/").at(-1);
    return path === "members" ||
      path === "teams" ||
      path === "projects" ||
      path === "runs" ||
      path === "tools" ||
      path === "usage" ||
      path === "devices" ||
      path === "policy" ||
      path === "models" ||
      path === "account"
      ? path
      : "overview";
  });
  const [refreshKey, setRefreshKey] = useState(0);
  const [load, setLoad] = useState<LoadState>({ kind: "loading" });
  const [showCreateOrg, setShowCreateOrg] = useState(me.organizations.length === 0);
  const [showCreateTeam, setShowCreateTeam] = useState(false);
  const [inviteOpen, setInviteOpen] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const [mobileNavOpen, setMobileNavOpen] = useState(false);
  const requestGeneration = useRef(0);
  const selected = useMemo(
    () => me.organizations.find((organization) => organization.organization.org_id === selectedId),
    [me.organizations, selectedId],
  );
  const canManage = selected?.role === "owner" || selected?.role === "admin";
  const pathSlug = window.location.pathname.match(/^\/org\/([^/]+)/)?.[1];
  const unauthorizedPath = Boolean(
    pathSlug && !me.organizations.some((item) => item.organization.slug === pathSlug),
  );

  useEffect(() => {
    const pathOrg = window.location.pathname.match(/^\/org\/([^/]+)/)?.[1];
    const pathMatch = me.organizations.find((item) => item.organization.slug === pathOrg);
    if (pathMatch && pathMatch.organization.org_id !== selectedId)
      setSelectedId(pathMatch.organization.org_id);
  }, [me.organizations, selectedId]);

  useEffect(() => {
    if (!selectedId) {
      setLoad({ kind: "ready", organization: emptyOrganization(), members: [], teams: [] });
      return;
    }
    const generation = ++requestGeneration.current;
    const controller = new AbortController();
    setLoad({ kind: "loading" });
    setNotice(null);
    void Promise.all([
      getOrganization(selectedId, controller.signal),
      listMembers(selectedId, controller.signal),
      listTeams(selectedId, controller.signal),
    ])
      .then(([organization, members, teams]) => {
        if (generation !== requestGeneration.current) return;
        setLoad({ kind: "ready", organization, members: members.items, teams: teams.items });
      })
      .catch((error: unknown) => {
        if (controller.signal.aborted || generation !== requestGeneration.current) return;
        setLoad({ kind: "error", error });
      });
    return () => controller.abort();
  }, [selectedId, refreshKey]);

  useEffect(() => {
    if (!mobileNavOpen) return;
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") setMobileNavOpen(false);
    };
    document.addEventListener("keydown", onKeyDown);
    return () => document.removeEventListener("keydown", onKeyDown);
  }, [mobileNavOpen]);

  function refresh() {
    setRefreshKey((value) => value + 1);
  }

  function selectOrganization(next: OrganizationSummary) {
    requestGeneration.current += 1;
    setSelectedId(next.organization.org_id);
    setSection("overview");
    setMobileNavOpen(false);
    setLoad({ kind: "loading" });
    window.history.pushState({}, "", `/org/${next.organization.slug}/overview`);
  }

  function navigate(next: Section) {
    setSection(next);
    setMobileNavOpen(false);
    if (selected) window.history.pushState({}, "", `/org/${selected.organization.slug}/${next}`);
  }

  async function refreshOrganizations() {
    onOrganizationsChanged();
  }

  return (
    <div className="min-h-dvh bg-[var(--surface)] text-[var(--foreground)]">
      <header className="sticky top-0 z-20 px-3 pt-3 sm:px-5">
        <div className="glass-surface mx-auto flex min-h-14 max-w-[1440px] items-center justify-between gap-3 rounded-2xl py-2 pl-3 pr-2 sm:pl-4 sm:pr-2.5">
          <div className="flex min-w-0 items-center gap-3 sm:gap-4">
            <div className="flex shrink-0 items-center gap-2">
              <LumiWordmark className="h-7 w-auto" />
              <span className="hidden text-sm font-semibold tracking-[-0.01em] text-[var(--civic-navy)] sm:inline">
                Agents
              </span>
            </div>
            {me.organizations.length > 0 ? (
              <label className="sr-only" htmlFor="org-switcher">
                Active organization
              </label>
            ) : null}
            {me.organizations.length > 0 ? (
              <select
                id="org-switcher"
                value={selectedId}
                onChange={(event) => {
                  const next = me.organizations.find(
                    (item) => item.organization.org_id === event.target.value,
                  );
                  if (next) selectOrganization(next);
                }}
                className="min-h-10 min-w-0 max-w-[220px] shrink rounded-lg border border-[var(--border)] bg-[var(--panel)] px-3 text-sm font-medium outline-none focus-visible:ring-2 focus-visible:ring-[var(--ring)]"
              >
                {me.organizations.map((organization) => (
                  <option
                    key={organization.organization.org_id}
                    value={organization.organization.org_id}
                  >
                    {organization.organization.display_name}
                  </option>
                ))}
              </select>
            ) : null}
          </div>
          <div className="flex items-center gap-2">
            <span className="hidden text-xs text-[var(--muted)] sm:inline">{me.user.email}</span>
            <button type="button" onClick={onSignOut} className={secondaryButton}>
              <IconLogout className="hidden size-4 sm:block" />
              Sign out
            </button>
            <button
              type="button"
              onClick={() => setMobileNavOpen((open) => !open)}
              aria-expanded={mobileNavOpen}
              aria-controls="mobile-nav"
              aria-label={mobileNavOpen ? "Close navigation menu" : "Open navigation menu"}
              className="grid size-11 shrink-0 place-items-center rounded-lg text-[var(--civic-navy)] outline-none transition hover:bg-[var(--panel-hover)] focus-visible:ring-2 focus-visible:ring-[var(--ring)] md:hidden"
            >
              {mobileNavOpen ? <IconX className="size-5" /> : <IconMenu className="size-5" />}
            </button>
          </div>
        </div>

        {mobileNavOpen ? (
          <div id="mobile-nav" className="mt-3 md:hidden">
            <nav aria-label="Organization sections" className="glass-surface rounded-[14px] p-1">
              <ul className="grid gap-1">
                {sections.map(({ id, label, icon: Icon }) => (
                  <li key={id}>
                    <button
                      type="button"
                      onClick={() => navigate(id)}
                      aria-current={section === id ? "page" : undefined}
                      className={[
                        "flex min-h-11 w-full items-center gap-2.5 rounded-[10px] px-3 text-left text-sm outline-none transition focus-visible:ring-2 focus-visible:ring-[var(--ring)]",
                        section === id
                          ? "bg-[var(--panel)] font-semibold text-[var(--lumi-blue)] shadow-[var(--shadow)]"
                          : "text-[var(--muted-strong)] hover:bg-[var(--panel-hover)] hover:text-[var(--foreground)]",
                      ].join(" ")}
                    >
                      <Icon className="size-[18px] shrink-0" />
                      {label}
                    </button>
                  </li>
                ))}
              </ul>
            </nav>
          </div>
        ) : null}
      </header>

      <div className="mx-auto grid max-w-[1440px] grid-cols-1 md:grid-cols-[232px_minmax(0,1fr)]">
        <aside className="hidden min-h-[calc(100dvh-4.25rem)] border-r border-[var(--border)] px-3 py-5 md:block">
          <nav aria-label="Organization navigation">
            <p className="mb-3 px-3 text-[11px] font-semibold tracking-[0.1em] text-[var(--muted)]">
              WORKSPACE
            </p>
            <ul className="space-y-1">
              {sections.map(({ id, label, icon: Icon }) => (
                <NavButton
                  key={id}
                  label={label}
                  icon={Icon}
                  active={section === id}
                  onClick={() => navigate(id)}
                />
              ))}
            </ul>
          </nav>
          <div className="mt-10 border-t border-[var(--border)] pt-4 text-xs leading-5 text-[var(--muted)]">
            <p className="px-3">Signed in as</p>
            <p className="px-3 font-medium text-[var(--muted-strong)]">{me.user.display_name}</p>
          </div>
        </aside>

        <main className="min-w-0 px-4 py-8 sm:px-6 lg:px-10">
          <div className="mx-auto max-w-6xl">
            {unauthorizedPath ? (
              <section
                role="alert"
                className="mx-auto max-w-xl rounded-xl border border-[var(--border)] bg-[var(--panel)] p-6 text-center shadow-[var(--shadow)]"
              >
                <h1 className="text-lg font-semibold text-[var(--civic-navy)]">
                  Organization not found
                </h1>
                <p className="mt-2 text-sm leading-6 text-[var(--muted-strong)]">
                  This organization is not available in your current access scope.
                </p>
              </section>
            ) : me.organizations.length === 0 || showCreateOrg ? (
              <CreateOrganizationPanel
                onCreated={async () => {
                  setShowCreateOrg(false);
                  await refreshOrganizations();
                }}
              />
            ) : load.kind === "loading" ? (
              <LoadingPanel label="Loading organization…" />
            ) : load.kind === "error" ? (
              <ErrorPanel error={load.error} onRetry={() => setSelectedId((value) => `${value}`)} />
            ) : (
              <>
                <div className="mb-7 flex flex-col gap-4 sm:flex-row sm:items-end sm:justify-between">
                  <div>
                    <p className="text-xs font-medium tracking-[0.08em] text-[var(--lumi-blue)]">
                      ORGANIZATION
                    </p>
                    <h1 className="mt-1 text-3xl font-semibold tracking-[-0.035em] text-[var(--civic-navy)]">
                      {load.organization.display_name}
                    </h1>
                    <p className="mt-1 text-sm text-[var(--muted-strong)]">
                      {load.organization.slug} · {load.organization.state}
                    </p>
                  </div>
                  {section === "members" ? (
                    <button
                      type="button"
                      onClick={() => setInviteOpen(true)}
                      className={primaryButton}
                    >
                      Invite member
                    </button>
                  ) : null}
                  {section === "teams" ? (
                    <button
                      type="button"
                      onClick={() => setShowCreateTeam(true)}
                      className={primaryButton}
                    >
                      Create team
                    </button>
                  ) : null}
                </div>

                {notice ? (
                  <p
                    role="status"
                    className="mb-5 rounded-lg border border-[var(--success)]/30 bg-[var(--success)]/5 p-3 text-sm text-[var(--success)]"
                  >
                    {notice}
                  </p>
                ) : null}

                {section === "overview" ? (
                  <OverviewPanel
                    organization={load.organization}
                    memberCount={load.members.length}
                    teamCount={load.teams.length}
                  />
                ) : null}
                {section === "members" ? (
                  <MembersPanel
                    members={load.members}
                    currentMembership={selected}
                    onRoleChange={async (member, role) => {
                      await changeMemberRole(load.organization.org_id, member.membership_id, {
                        role,
                        version: member.version,
                      });
                      refresh();
                    }}
                  />
                ) : null}
                {section === "teams" ? (
                  <TeamsPanel
                    teams={load.teams}
                    onCreate={async (name, slug) => {
                      await createTeam(load.organization.org_id, { display_name: name, slug });
                      setShowCreateTeam(false);
                      refresh();
                    }}
                    open={showCreateTeam}
                    onClose={() => setShowCreateTeam(false)}
                  />
                ) : null}
                {section === "projects" ? (
                  <ProjectsPanel orgId={load.organization.org_id} canManage={canManage} />
                ) : null}
                {section === "runs" || section === "tools" || section === "usage" ? (
                  <Suspense fallback={<LoadingPanel label="Loading control surface…" />}>
                    {section === "runs" ? <RunsPanel orgId={load.organization.org_id} /> : null}
                    {section === "tools" ? (
                      <ToolsPanel
                        orgId={load.organization.org_id}
                        {...(selected ? { membership: { role: selected.role } } : {})}
                      />
                    ) : null}
                    {section === "usage" ? (
                      <UsageBudgetsPanel orgId={load.organization.org_id} />
                    ) : null}
                  </Suspense>
                ) : null}
                {section === "devices" ? (
                  <DevicesPanel orgId={load.organization.org_id} currentUserId={me.user.id} />
                ) : null}
                {section === "policy" ? <PolicyPanel orgId={load.organization.org_id} /> : null}
                {section === "models" ? (
                  <ModelsRoutingPanel orgId={load.organization.org_id} membership={selected} />
                ) : null}
                {section === "account" ? <AccountSecurityPanel me={me} /> : null}
              </>
            )}
          </div>
        </main>
      </div>

      {inviteOpen && load.kind === "ready" ? (
        <InviteDialog
          onClose={() => setInviteOpen(false)}
          onInvited={(message) => {
            setInviteOpen(false);
            setNotice(message);
          }}
          orgId={load.organization.org_id}
        />
      ) : null}
    </div>
  );
}

function CreateOrganizationPanel({ onCreated }: { onCreated: () => Promise<void> }) {
  const [name, setName] = useState("");
  const [slug, setSlug] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const id = useId();
  async function submit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await createOrganization(
        { display_name: name, ...(slug ? { slug } : {}) },
        crypto.randomUUID(),
      );
      await onCreated();
    } catch (requestError) {
      setError(requestError);
    } finally {
      setBusy(false);
    }
  }
  return (
    <section className="mx-auto max-w-xl rounded-xl border border-[var(--border)] bg-[var(--panel)] p-6 shadow-[var(--shadow)] sm:p-8">
      <p className="text-xs font-semibold tracking-[0.1em] text-[var(--lumi-blue)]">GET STARTED</p>
      <h1 className="mt-3 text-2xl font-semibold tracking-[-0.03em] text-[var(--civic-navy)]">
        Create an organization
      </h1>
      <p className="mt-2 text-sm leading-6 text-[var(--muted-strong)]">
        Organizations keep members, teams, and cloud-managed work in one explicit tenant boundary.
      </p>
      <form onSubmit={(event) => void submit(event)} className="mt-7 space-y-4">
        <label className="block text-sm font-medium text-[var(--civic-navy)]" htmlFor={id}>
          Organization name
          <input
            id={id}
            required
            value={name}
            onChange={(event) => setName(event.target.value)}
            className={inputClass}
            placeholder="Acme Research"
          />
        </label>
        <label
          className="block text-sm font-medium text-[var(--civic-navy)]"
          htmlFor={`${id}-slug`}
        >
          Slug <span className="font-normal text-[var(--muted)]">(optional)</span>
          <input
            id={`${id}-slug`}
            value={slug}
            onChange={(event) => setSlug(event.target.value)}
            className={inputClass}
            placeholder="acme-research"
          />
        </label>
        {error ? <ErrorPanel error={error} /> : null}
        <button type="submit" disabled={busy} className={primaryButton}>
          {busy ? "Creating…" : "Create organization"}
        </button>
      </form>
    </section>
  );
}

function OverviewPanel({
  organization,
  memberCount,
  teamCount,
}: {
  organization: Organization;
  memberCount: number;
  teamCount: number;
}) {
  return (
    <div className="space-y-6">
      <div className="grid gap-4 sm:grid-cols-3">
        <Metric label="Members" value={String(memberCount)} detail="Active directory" />
        <Metric label="Teams" value={String(teamCount)} detail="Flat access groups" />
        <Metric
          label="Status"
          value={organization.state}
          detail={`Version ${organization.version}`}
        />
      </div>
      <section className="rounded-xl border border-[var(--border)] bg-[var(--panel)] shadow-[var(--shadow)]">
        <div className="border-b border-[var(--border)] px-5 py-4">
          <h2 className="text-base font-semibold text-[var(--civic-navy)]">Tenant controls</h2>
          <p className="mt-1 text-sm text-[var(--muted-strong)]">
            Every request resolves this organization before reading or changing a resource.
          </p>
        </div>
        <div className="grid gap-4 p-5 sm:grid-cols-2">
          <InfoRow label="Organization ID" value={organization.org_id} mono />
          <InfoRow label="Slug" value={organization.slug} />
          <InfoRow label="Created" value={formatDate(organization.created_at)} />
          <InfoRow label="Access model" value="Owner · Admin · Member · Viewer" />
        </div>
      </section>
    </div>
  );
}

function MembersPanel({
  members,
  currentMembership,
  onRoleChange,
}: {
  members: Membership[];
  currentMembership: OrganizationSummary | undefined;
  onRoleChange: (member: Membership, role: Membership["role"]) => Promise<void>;
}) {
  const [error, setError] = useState<unknown>(null);
  const canManage = currentMembership?.role === "owner" || currentMembership?.role === "admin";
  return (
    <section className="overflow-hidden rounded-xl border border-[var(--border)] bg-[var(--panel)] shadow-[var(--shadow)]">
      <div className="border-b border-[var(--border)] px-5 py-4">
        <h2 className="text-base font-semibold text-[var(--civic-navy)]">Members</h2>
        <p className="mt-1 text-sm text-[var(--muted-strong)]">
          Roles are enforced by the API. The last active owner is protected.
        </p>
      </div>
      {error ? (
        <div className="p-5">
          <ErrorPanel error={error} />
        </div>
      ) : null}
      <div className="relative overflow-x-auto">
        <table className="w-full min-w-[620px] text-left text-sm">
          <thead className="bg-[var(--panel-hover)] text-xs text-[var(--muted)]">
            <tr>
              <th className="px-5 py-3 font-medium">Member</th>
              <th className="px-5 py-3 font-medium">Role</th>
              <th className="px-5 py-3 font-medium">Status</th>
              <th className="px-5 py-3 font-medium">Joined</th>
              {canManage ? <th className="px-5 py-3 font-medium">Action</th> : null}
            </tr>
          </thead>
          <tbody className="divide-y divide-[var(--border)]">
            {members.map((member) => (
              <tr key={member.membership_id}>
                <td className="px-5 py-4">
                  <p className="font-medium text-[var(--civic-navy)]">{member.user_id}</p>
                  <p className="mt-0.5 text-xs text-[var(--muted)]">{member.membership_id}</p>
                </td>
                <td className="px-5 py-4 capitalize">{member.role}</td>
                <td className="px-5 py-4">
                  <StatusPill status={member.status} />
                </td>
                <td className="px-5 py-4 tabular-nums text-[var(--muted-strong)]">
                  {member.joined_at ? formatDate(member.joined_at) : "—"}
                </td>
                {canManage ? (
                  <td className="px-5 py-4">
                    <label className="sr-only" htmlFor={`role-${member.membership_id}`}>
                      Change role for {member.user_id}
                    </label>
                    <select
                      id={`role-${member.membership_id}`}
                      value={member.role}
                      onChange={(event) => {
                        setError(null);
                        void onRoleChange(member, event.target.value as Membership["role"]).catch(
                          setError,
                        );
                      }}
                      className="min-h-10 rounded-lg border border-[var(--border)] bg-[var(--panel)] px-2 text-sm outline-none focus-visible:ring-2 focus-visible:ring-[var(--ring)]"
                    >
                      <option value="owner">Owner</option>
                      <option value="admin">Admin</option>
                      <option value="member">Member</option>
                      <option value="viewer">Viewer</option>
                    </select>
                  </td>
                ) : null}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}

function TeamsPanel({
  teams,
  onCreate,
  open,
  onClose,
}: {
  teams: Team[];
  onCreate: (name: string, slug: string) => Promise<void>;
  open: boolean;
  onClose: () => void;
}) {
  return (
    <div className="space-y-4">
      <section className="overflow-hidden rounded-xl border border-[var(--border)] bg-[var(--panel)] shadow-[var(--shadow)]">
        <div className="border-b border-[var(--border)] px-5 py-4">
          <h2 className="text-base font-semibold text-[var(--civic-navy)]">Teams</h2>
          <p className="mt-1 text-sm text-[var(--muted-strong)]">
            A flat directory for future project, routing, and policy scopes.
          </p>
        </div>
        {teams.length === 0 ? (
          <p className="p-6 text-sm text-[var(--muted)]">No teams yet.</p>
        ) : (
          <ul className="divide-y divide-[var(--border)]">
            {teams.map((team) => (
              <li key={team.team_id} className="flex items-center justify-between gap-4 px-5 py-4">
                <div>
                  <p className="font-medium text-[var(--civic-navy)]">{team.display_name}</p>
                  <p className="mt-1 text-xs text-[var(--muted)]">{team.slug}</p>
                </div>
                <span className="text-xs text-[var(--muted)]">{team.version} members</span>
              </li>
            ))}
          </ul>
        )}
      </section>
      {open ? <CreateTeamDialog onCreate={onCreate} onClose={onClose} /> : null}
    </div>
  );
}

function InviteDialog({
  orgId,
  onClose,
  onInvited,
}: {
  orgId: string;
  onClose: () => void;
  onInvited: (message: string) => void;
}) {
  const [email, setEmail] = useState("");
  const [role, setRole] = useState<"admin" | "member" | "viewer">("member");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [token, setToken] = useState<string | null>(null);
  const [complete, setComplete] = useState(false);
  async function submit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const result = await inviteMember(orgId, { email, role }, crypto.randomUUID());
      setToken(result.development_token ?? null);
      setComplete(true);
    } catch (requestError) {
      setError(requestError);
    } finally {
      setBusy(false);
    }
  }
  function close() {
    onClose();
    if (complete)
      onInvited(
        "Invitation created. Share the one-time invitation through your approved delivery channel.",
      );
  }
  return (
    <div
      className="fixed inset-0 z-30 grid place-items-center bg-[var(--civic-navy)]/30 p-4"
      role="presentation"
    >
      <section
        role="dialog"
        aria-modal="true"
        aria-labelledby="invite-title"
        className="w-full max-w-md rounded-xl border border-[var(--border)] bg-[var(--panel)] p-6 shadow-[var(--shadow)]"
      >
        <div className="flex items-start justify-between gap-4">
          <div>
            <h2 id="invite-title" className="text-lg font-semibold text-[var(--civic-navy)]">
              Invite a member
            </h2>
            <p className="mt-1 text-sm text-[var(--muted-strong)]">
              The invitation is single-use and expires after seven days.
            </p>
          </div>
          <button
            type="button"
            onClick={close}
            className={iconButton}
            aria-label="Close invitation dialog"
          >
            <IconX className="size-5" />
          </button>
        </div>
        <form onSubmit={(event) => void submit(event)} className="mt-6 space-y-4">
          <label className="block text-sm font-medium text-[var(--civic-navy)]">
            Email
            <input
              type="email"
              required
              value={email}
              onChange={(event) => setEmail(event.target.value)}
              className={inputClass}
              placeholder="teammate@company.com"
            />
          </label>
          <label className="block text-sm font-medium text-[var(--civic-navy)]">
            Role
            <select
              value={role}
              onChange={(event) => setRole(event.target.value as typeof role)}
              className={inputClass}
            >
              <option value="member">Member</option>
              <option value="admin">Admin</option>
              <option value="viewer">Viewer</option>
            </select>
          </label>
          {error ? <ErrorPanel error={error} /> : null}
          {token ? (
            <div className="rounded-lg border border-[var(--lumi-blue)]/30 bg-[var(--lumi-blue-soft)] p-3 text-xs text-[var(--civic-navy)]">
              <p className="font-medium">Development invitation token</p>
              <code className="mt-1 block break-all">{token}</code>
            </div>
          ) : null}
          <div className="flex justify-end gap-2">
            <button type="button" onClick={close} className={secondaryButton}>
              {complete ? "Close" : "Cancel"}
            </button>
            <button type="submit" disabled={busy || complete} className={primaryButton}>
              {busy ? "Creating…" : complete ? "Invitation ready" : "Create invitation"}
            </button>
          </div>
        </form>
      </section>
    </div>
  );
}

function CreateTeamDialog({
  onCreate,
  onClose,
}: {
  onCreate: (name: string, slug: string) => Promise<void>;
  onClose: () => void;
}) {
  const [name, setName] = useState("");
  const [slug, setSlug] = useState("");
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  async function submit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await onCreate(name, slug);
    } catch (requestError) {
      setError(requestError);
    } finally {
      setBusy(false);
    }
  }
  return (
    <div className="fixed inset-0 z-30 grid place-items-center bg-[var(--civic-navy)]/30 p-4">
      <section
        role="dialog"
        aria-modal="true"
        aria-labelledby="team-title"
        className="w-full max-w-md rounded-xl border border-[var(--border)] bg-[var(--panel)] p-6 shadow-[var(--shadow)]"
      >
        <h2 id="team-title" className="text-lg font-semibold text-[var(--civic-navy)]">
          Create a team
        </h2>
        <form onSubmit={(event) => void submit(event)} className="mt-5 space-y-4">
          <label className="block text-sm font-medium">
            Name
            <input
              required
              value={name}
              onChange={(event) => setName(event.target.value)}
              className={inputClass}
            />
          </label>
          <label className="block text-sm font-medium">
            Slug
            <input
              required
              value={slug}
              onChange={(event) => setSlug(event.target.value)}
              className={inputClass}
            />
          </label>
          {error ? <ErrorPanel error={error} /> : null}
          <div className="flex justify-end gap-2">
            <button type="button" onClick={onClose} className={secondaryButton}>
              Cancel
            </button>
            <button type="submit" disabled={busy} className={primaryButton}>
              {busy ? "Creating…" : "Create team"}
            </button>
          </div>
        </form>
      </section>
    </div>
  );
}

function NavButton({
  label,
  icon: Icon,
  active,
  onClick,
}: {
  label: string;
  icon: ComponentType<{ className?: string }>;
  active: boolean;
  onClick: () => void;
}) {
  return (
    <li>
      <button
        type="button"
        onClick={onClick}
        aria-current={active ? "page" : undefined}
        className={[
          "flex min-h-11 w-full items-center gap-2.5 rounded-lg border-l-2 px-3 text-left text-sm outline-none transition focus-visible:ring-2 focus-visible:ring-[var(--ring)]",
          active
            ? "border-l-[var(--lumi-blue)] bg-[var(--lumi-blue-soft)] font-semibold text-[var(--lumi-blue)]"
            : "border-l-transparent text-[var(--muted-strong)] hover:bg-[var(--panel-hover)] hover:text-[var(--foreground)]",
        ].join(" ")}
      >
        <Icon className="size-[18px] shrink-0" />
        {label}
      </button>
    </li>
  );
}
function Metric({ label, value, detail }: { label: string; value: string; detail: string }) {
  return (
    <div className="rounded-xl border border-[var(--border)] bg-[var(--panel)] p-4 shadow-[var(--shadow)]">
      <p className="text-xs font-medium text-[var(--muted)]">{label}</p>
      <p className="mt-2 text-xl font-semibold tabular-nums tracking-[-0.02em] text-[var(--civic-navy)]">
        {value}
      </p>
      <p className="mt-1 text-xs text-[var(--muted)]">{detail}</p>
    </div>
  );
}
function InfoRow({ label, value, mono = false }: { label: string; value: string; mono?: boolean }) {
  return (
    <div>
      <p className="text-xs text-[var(--muted)]">{label}</p>
      <p
        className={
          mono
            ? "mt-1 break-all font-mono text-xs text-[var(--muted-strong)]"
            : "mt-1 text-sm text-[var(--civic-navy)]"
        }
      >
        {value}
      </p>
    </div>
  );
}
function StatusPill({ status }: { status: string }) {
  return (
    <span
      className={[
        "inline-flex rounded-full px-2 py-1 text-xs font-medium",
        status === "active"
          ? "bg-[var(--success)]/10 text-[var(--success)]"
          : "bg-[var(--panel-strong)] text-[var(--muted-strong)]",
      ].join(" ")}
    >
      {status}
    </span>
  );
}
function LoadingPanel({ label }: { label: string }) {
  return (
    <div
      className="rounded-xl border border-[var(--border)] bg-[var(--panel)] p-8 text-sm text-[var(--muted)]"
      aria-live="polite"
    >
      {label}
    </div>
  );
}
function ErrorPanel({ error, onRetry }: { error: unknown; onRetry?: () => void }) {
  const presentation = presentApiError(error);
  return (
    <div
      role="alert"
      className="rounded-xl border border-[var(--danger)]/30 bg-[var(--danger)]/5 p-4 text-sm text-[var(--danger)]"
    >
      <p className="font-medium">{presentation.message}</p>
      {presentation.requestId ? (
        <p className="mt-1 text-xs opacity-75">Request {presentation.requestId}</p>
      ) : null}
      {onRetry ? (
        <button
          type="button"
          onClick={onRetry}
          className="mt-3 min-h-10 rounded-lg border border-[var(--danger)]/40 px-3 text-sm font-medium"
        >
          Try again
        </button>
      ) : null}
    </div>
  );
}
function emptyOrganization(): Organization {
  return {
    org_id: "",
    display_name: "",
    slug: "",
    state: "active",
    version: 0,
    created_by_user_id: "",
    created_at: "",
    updated_at: "",
  };
}
function formatDate(value: string): string {
  const date = new Date(value);
  return Number.isNaN(date.getTime())
    ? value
    : date.toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });
}
const inputClass =
  "mt-1.5 min-h-11 w-full rounded-lg border border-[var(--border)] bg-[var(--panel)] px-3 text-sm font-normal text-[var(--foreground)] outline-none transition placeholder:text-[var(--muted)] focus-visible:border-[var(--lumi-blue)] focus-visible:ring-2 focus-visible:ring-[var(--ring)] focus-visible:ring-offset-2 focus-visible:ring-offset-[var(--panel)]";
const primaryButton =
  "min-h-11 rounded-lg bg-[var(--lumi-blue)] px-4 py-2 text-sm font-semibold text-white shadow-[var(--shadow-button)] outline-none transition hover:bg-[var(--lumi-blue-hover)] active:translate-y-px focus-visible:ring-2 focus-visible:ring-[var(--ring)] focus-visible:ring-offset-2 focus-visible:ring-offset-[var(--surface)] disabled:cursor-not-allowed disabled:opacity-50";
const secondaryButton =
  "inline-flex min-h-11 items-center gap-2 whitespace-nowrap rounded-lg border border-[var(--lumi-blue)]/40 bg-[var(--panel)] px-4 py-2 text-sm font-medium text-[var(--lumi-blue)] outline-none transition hover:border-[var(--lumi-blue)]/60 hover:bg-[var(--lumi-blue-soft)] active:translate-y-px focus-visible:ring-2 focus-visible:ring-[var(--ring)] focus-visible:ring-offset-2 focus-visible:ring-offset-[var(--surface)]";
const iconButton =
  "grid size-10 place-items-center rounded-lg text-xl text-[var(--muted)] outline-none hover:bg-[var(--panel-hover)] focus-visible:ring-2 focus-visible:ring-[var(--ring)]";
