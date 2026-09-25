import { useCallback, useEffect, useState } from "react";

import { createProject, listProjects, patchProject, type Project } from "@/lib/api";
import { presentApiError } from "@/lib/errors";

interface ProjectsPanelProps {
  orgId: string;
  canManage: boolean;
}

type ProjectsState =
  | { kind: "loading" }
  | { kind: "ready"; projects: Project[] }
  | { kind: "error"; message: string };

/**
 * Org projects (P03): create, rename, visibility, archive. Workspace
 * bindings and per-project policy surface here in later phases; this panel
 * manages the project scope itself.
 */
export function ProjectsPanel({ orgId, canManage }: ProjectsPanelProps) {
  const [state, setState] = useState<ProjectsState>({ kind: "loading" });
  const [name, setName] = useState("");
  const [visibility, setVisibility] = useState<"org" | "restricted">("org");
  const [busy, setBusy] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setState({ kind: "loading" });
    try {
      const page = await listProjects(orgId);
      setState({ kind: "ready", projects: page.items });
    } catch (error) {
      const presentation = presentApiError(error);
      setState({ kind: "error", message: `${presentation.title}. ${presentation.message}` });
    }
  }, [orgId]);

  useEffect(() => {
    void load();
  }, [load]);

  async function create() {
    const trimmed = name.trim();
    if (!trimmed || busy) return;
    setBusy(true);
    setActionError(null);
    try {
      await createProject(orgId, { name: trimmed, visibility }, `create-project-${Date.now()}`);
      setName("");
      setVisibility("org");
      await load();
    } catch (error) {
      const presentation = presentApiError(error);
      setActionError(
        presentation.code === "project_slug_conflict"
          ? "A project with this name already exists — pick a different name."
          : `${presentation.title}. ${presentation.message}`,
      );
    } finally {
      setBusy(false);
    }
  }

  async function toggleArchive(project: Project) {
    if (busy) return;
    setBusy(true);
    setActionError(null);
    try {
      await patchProject(orgId, project.id, {
        name: project.name,
        visibility: project.visibility,
        archived: !project.archived,
        version: project.version,
      });
      await load();
    } catch (error) {
      const presentation = presentApiError(error);
      setActionError(
        presentation.code === "version_conflict"
          ? "The project changed since you loaded it. Refresh and try again."
          : `${presentation.title}. ${presentation.message}`,
      );
      await load();
    } finally {
      setBusy(false);
    }
  }

  return (
    <section aria-label="Projects" className="space-y-5">
      {canManage ? (
        <div className="rounded-xl border border-[var(--border)] bg-[var(--panel)] p-5 shadow-[var(--shadow)]">
          <h2 className="text-sm font-semibold">Create project</h2>
          <div className="mt-3 flex flex-col gap-2 sm:flex-row">
            <input
              type="text"
              value={name}
              onChange={(event) => setName(event.target.value)}
              placeholder="Project name"
              aria-label="Project name"
              className="min-h-9 flex-1 rounded-lg border border-[var(--border)] bg-[var(--surface)] px-3 py-1.5 text-sm outline-none focus-visible:ring-2 focus-visible:ring-[var(--lumi-blue)]"
            />
            <select
              value={visibility}
              onChange={(event) =>
                setVisibility(event.target.value === "restricted" ? "restricted" : "org")
              }
              aria-label="Project visibility"
              className="min-h-9 rounded-lg border border-[var(--border)] bg-[var(--surface)] px-3 py-1.5 text-sm outline-none focus-visible:ring-2 focus-visible:ring-[var(--lumi-blue)]"
            >
              <option value="org">Org — all members</option>
              <option value="restricted">Restricted — grants only</option>
            </select>
            <button
              type="button"
              onClick={() => void create()}
              disabled={busy || name.trim().length === 0}
              className="min-h-9 rounded-lg bg-[var(--lumi-blue)] px-4 py-1.5 text-sm font-medium text-white outline-none transition hover:bg-[var(--lumi-blue-hover)] focus-visible:ring-2 focus-visible:ring-[var(--lumi-blue)] disabled:cursor-not-allowed disabled:opacity-60"
            >
              {busy ? "Creating…" : "Create"}
            </button>
          </div>
        </div>
      ) : null}

      {actionError ? (
        <p role="alert" className="text-sm text-[var(--danger)]">
          {actionError}
        </p>
      ) : null}

      {state.kind === "loading" ? (
        <p role="status" className="text-sm text-[var(--muted-strong)]">
          Loading projects…
        </p>
      ) : state.kind === "error" ? (
        <p role="alert" className="text-sm text-[var(--danger)]">
          {state.message}
        </p>
      ) : state.projects.length === 0 ? (
        <p className="text-sm text-[var(--muted-strong)]">No projects yet.</p>
      ) : (
        <ul className="divide-y divide-[var(--border)] overflow-hidden rounded-xl border border-[var(--border)] bg-[var(--panel)] shadow-[var(--shadow)]">
          {state.projects.map((project) => (
            <li
              key={project.id}
              className="flex flex-col gap-2 p-4 sm:flex-row sm:items-center sm:justify-between"
            >
              <div className="min-w-0">
                <p className="text-sm font-medium">
                  {project.name}{" "}
                  <span className="ml-1 inline-block rounded-full bg-[var(--panel-strong)] px-2 py-0.5 text-xs text-[var(--muted-strong)]">
                    {project.visibility}
                  </span>
                  {project.archived ? (
                    <span className="ml-1 inline-block rounded-full bg-[var(--danger)]/10 px-2 py-0.5 text-xs text-[var(--danger)]">
                      archived
                    </span>
                  ) : null}
                </p>
                <p className="mt-0.5 truncate font-mono text-xs text-[var(--muted)]">
                  {project.slug} · v{project.version}
                </p>
              </div>
              {canManage ? (
                <button
                  type="button"
                  onClick={() => void toggleArchive(project)}
                  disabled={busy}
                  className="min-h-9 self-start rounded-lg border border-[var(--border)] px-3 py-1.5 text-sm font-medium outline-none transition hover:bg-[var(--panel-hover)] focus-visible:ring-2 focus-visible:ring-[var(--lumi-blue)] disabled:cursor-not-allowed disabled:opacity-60 sm:self-auto"
                >
                  {project.archived ? "Restore" : "Archive"}
                </button>
              ) : null}
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
