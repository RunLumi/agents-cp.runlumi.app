# AGENTS.md

## Mission

Build the Lumi Agents control plane so it feels immediate, calm, and dependable. Speed, performance, UI/UX quality, security, and maintainability are product requirements, not cleanup work.

This file is the operating contract for coding agents in this repository.

## Functional specifications

`docs/specs/` is the authoritative functional contract for the control plane.

Before implementing or changing a product feature:

1. Read `docs/specs/README.md`.
2. Read the specific `fXX-*.md` feature spec(s) involved.
3. Preserve cross-feature invariants for tenant isolation, authorization, audit, secrets, budgets, device policy and data retention.
4. If implementation requires behavior that contradicts a MUST requirement, update the spec/ADR intentionally before changing code.
5. Do not invent a parallel concept when the spec already defines the resource vocabulary.

Feature work is not done if code exists but the relevant acceptance criteria in `docs/specs` are not demonstrably satisfied.

## Read first

Before changing architecture, dependencies, build tooling, public API contracts, authentication, authorization, persistence, or cross-cutting UI behavior:

1. Read the relevant files in `docs/adr/`.
2. Inspect the existing implementation before proposing abstractions.
3. Prefer the smallest change that satisfies the requirement.
4. Add or update an ADR when a durable architectural decision changes.

## Non-negotiable stack

### Backend

- Rust.
- Cloudflare Workers through `workers-rs`.
- Axum 0.8 using the `worker` crate's `http` + `axum` bridge.
- Target `wasm32-unknown-unknown`.
- No Node backend.
- No Tokio or another native async runtime unless Cloudflare officially supports the exact use case and an ADR records the decision.
- Every dependency must compile for the Worker WASM target.

### Frontend

- React 19.
- Vite 8.
- TypeScript 7 in strict mode.
- Tailwind CSS 4.
- shadcn/ui with **Base UI** primitives.
- **Never introduce Radix UI packages or Radix imports.**
- Prefer Tabler for iconography when icons are needed.
- No Next.js, SSR framework, meta-framework, or CSS-in-JS layer without an ADR.

### Repository

- pnpm workspace for JS/TS.
- Cargo workspace for Rust.
- Do not add Turborepo/Nx until there are enough independent packages/tasks for measured task caching to justify it.

## Architecture

```text
repo/
├── apps/
│   ├── api/      # Rust Worker, HTTP/API boundary
│   └── web/      # Vite SPA, control-plane UI
└── docs/adr/     # durable architectural decisions
```

Keep the root boring. New package boundaries are allowed only when there are at least two real consumers or a clear deployment/security boundary.

Do not create `packages/ui`, `packages/utils`, or generic "shared" packages because code might become reusable someday.

## Backend rules

- Keep route handlers thin.
- Domain rules move outside transport parsing as the product grows.
- Return stable JSON error codes, not strings clients must parse.
- Validate all external input at the boundary.
- Never trust tenant/org/resource IDs from the client as authorization evidence.
- Authorization is enforced server-side.
- Keep request context explicit.
- Prefer stateless request handling.
- Do not hold mutable global state across requests.
- Avoid heavy crates. WASM size is a latency and deployability cost.
- Wrap Cloudflare bindings in small adapters instead of spreading raw `Env` throughout domain code.
- Long-running or retryable work belongs in Queues/Workflows when introduced, not synchronous request handlers.
- Never log secrets, credentials, authorization headers, raw tokens, or sensitive prompts.

## Frontend rules

### Performance

- No application barrel files.
- Route-level code split once multiple substantive routes exist.
- Avoid dependencies for behavior the platform, React, Base UI, Tailwind, or a few lines of code can provide.
- Keep provider nesting shallow.
- Do not put server state in a global client store by default.
- Measure before adding memoization.
- Avoid broad context providers that invalidate large subtrees.
- Lists that can grow unbounded must paginate or virtualize.
- Expensive visualizations load on demand.
- Never ship a large chart/editor/highlighting library in the initial route unless the route requires it.

### UI/UX

- Prefer dense, quiet, high-information admin UI over decorative dashboards.
- Every interactive element must be keyboard reachable.
- Preserve visible focus states.
- Respect `prefers-reduced-motion`.
- Use semantic HTML first, Base UI for non-trivial interactions, shadcn components for product UI.
- Every async surface needs intentional loading, empty, success, and error states.
- Destructive actions require clear consequence copy and an appropriate confirmation pattern.
- Do not hide essential actions behind hover-only UI.
- Optimistic updates are allowed only when rollback is safe and understandable.
- Use animation sparingly to clarify state or spatial change.
- Never trade contrast, target size, or focus behavior for visual minimalism.

### shadcn / Base UI

- `apps/web/components.json` is authoritative.
- Generated components live in `apps/web/src/components/ui`.
- Before accepting generated code, verify imports come from `@base-ui/react`, never `@radix-ui/*`.
- Do not mass-add shadcn components.
- Preserve semantic design tokens instead of scattering one-off colors.

## Agent-friendly development

Vite browser error forwarding is enabled so coding agents see runtime browser failures in the terminal.

When debugging:

1. Reproduce.
2. Find the smallest failing boundary.
3. Add a regression test where valuable.
4. Fix the cause, not the symptom.
5. Run the narrowest check first, then `pnpm check`.

Do not rewrite unrelated code during a focused fix.

## Dependency policy

Before adding a runtime dependency, answer:

1. What user or engineering problem does it solve?
2. Can the browser, Rust std, Axum, React, Base UI, Tailwind, or Cloudflare platform solve it already?
3. What is its browser/WASM size cost?
4. What maintenance/security surface does it add?
5. Is it compatible with the runtime?

A dependency that saves ten lines but adds a large transitive tree is usually a bad trade.

Core build tooling is pinned deliberately. Review release notes before upgrades.

## Performance budgets

### Web production baseline

- Initial JS target: <= 170 KiB gzip.
- Initial CSS target: <= 35 KiB gzip.
- New route chunk target: <= 80 KiB gzip unless objectively required.
- CLS: < 0.1.
- INP: < 200 ms p75.
- LCP: < 2.5 s p75, target < 2.0 s for the authenticated shell.
- No application-caused main-thread long task > 200 ms during normal navigation.

### Developer loop

- Keep Vite plugin count minimal.
- Cold Vite startup target: < 1.5 s on a modern development laptop.
- Typical HMR feedback target: < 200 ms.
- Do not enable experimental Vite bundled-dev mode globally without a repository benchmark.

### API

- Health/simple in-memory handler compute target: < 10 ms p95 inside Worker execution.
- Normal control-plane request target: < 200 ms p95 excluding third-party upstream time.
- No blocking I/O.
- Track Worker bundle size and investigate substantial increases before merge.

Budgets become automated CI gates once representative production routes exist.

## Testing

- Rust domain logic: unit tests near the module.
- HTTP behavior: integration tests around router/service boundaries where practical.
- Web logic: Vitest.
- Browser-critical flows: Playwright once real flows exist.
- Test behavior, not implementation details.
- Tests must be isolated and deterministic.
- Multi-tenant features require explicit cross-tenant negative tests.

Do not chase line coverage. Cover security invariants, business rules, critical paths, and expensive regressions.

## Commands

```bash
pnpm dev
pnpm build

pnpm format
pnpm format:check
pnpm lint
pnpm typecheck
pnpm test
pnpm rust:check
pnpm check

pnpm ui:add -- button
```

Rust-only:

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo check --workspace --target wasm32-unknown-unknown
```

## Git discipline

- Small cohesive commits.
- No drive-by formatting.
- Never commit secrets, `.dev.vars`, generated Worker output, `dist`, or `node_modules`.
- Do not force-update shared branches.
- Explain architectural trade-offs in the PR, not only what changed.

## Definition of Done

A change is done when:

- behavior matches the requirement;
- server-side security invariants hold;
- keyboard/focus/error/loading behavior is correct for UI work;
- relevant tests exist and pass;
- format, lint, typecheck, Rust checks, and build pass;
- performance impact is understood;
- no unnecessary dependency or abstraction was added;
- docs/ADR are updated when durable architecture changed.

If a fast solution makes the system harder to reason about tomorrow, it is not actually fast.
