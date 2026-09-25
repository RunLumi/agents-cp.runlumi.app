# Lumi Agents Control Plane

A fast, edge-native organization control plane for Lumi Agents.

## Architecture

```text
apps/web  ── /api/* ──>  apps/api
React 19.3              Rust + Axum
Vite 8                  Cloudflare Workers
shadcn/Base UI          workers-rs
Tailwind CSS 4
```

The repository deliberately starts with **one web app and one API worker**. We use pnpm workspaces + Cargo workspaces and avoid an additional task orchestrator until the repository is large enough for remote task caching to pay for its complexity.

## Stack

- Rust + Axum 0.8 on Cloudflare Workers via `workers-rs`
- React 19.3 + Vite 8 + TypeScript 7
- shadcn/ui using **Base UI**, never Radix
- Tailwind CSS 4
- pnpm 12
- Oxlint + Oxfmt
- Vitest
- Wrangler 4

## Start

Prerequisites: Node 24 LTS, pnpm 12, stable Rust, and `wasm32-unknown-unknown`.

```bash
corepack enable
pnpm install --frozen-lockfile
rustup target add wasm32-unknown-unknown
cargo install --locked worker-build --version "^0.8"
pnpm db:migrate:local
pnpm dev
```

- Web: http://localhost:5173
- API: http://localhost:8787
- Health through web proxy: http://localhost:5173/api/health
- Local development selects Wrangler's `development` environment. Production API calls do not register the internal foundation-check routes.
- D1 schema changes are append-only files in `apps/api/migrations/`. Apply pending migrations locally with `pnpm db:migrate:local`; inspect the local ledger with `pnpm db:migrations:list:local`.
- Run `pnpm smoke:local` to apply the local migration, start development and production-config Wrangler workers plus Vite, verify request/correlation ID propagation into D1, test principal/organization idempotency scope isolation and transactional rollback after a stale claim, exercise replay and different-body conflict through the Vite proxy, confirm the internal route is absent in production, and wait for Queue delivery. It uses only synthetic test fixtures.
- D1 migrations are forward-only. Fix an applied migration with a new migration; a rollback of production data requires a separately reviewed restore procedure.

## Adding backend routes and migrations

- Put pure value types and domain rules in `apps/api/src/core/` or a named domain module. Do not import `worker::Env`, Axum, or D1 from core code.
- Put Cloudflare bindings in `apps/api/src/adapters/`; keep route parsing and response formatting in `apps/api/src/http/` and `apps/api/src/routes/`.
- Keep SQL in repositories and bind dynamic values through prepared statements. Use a D1 batch when statements form one invariant.
- Create D1 changes with `pnpm --filter @runlumi/agents-cp-api exec wrangler d1 migrations create lumi-agents-control-plane <short-name>`. Never edit an already-applied migration; add the next numbered migration.
- Add deterministic domain and repository tests beside the owning module or under `apps/api/tests/`. Test idempotency, tenant scoping, and log/body redaction where the feature uses them.
- Product APIs belong under `/api/v1`. Normalize errors with the frozen `ApiError` envelope; clients branch on its machine-readable code.

## Quality

```bash
pnpm format
pnpm lint
pnpm typecheck
pnpm test
pnpm rust:check
pnpm check
```

GitHub Actions runs the same check set from `.github/workflows/checks.yml`, then builds the web app and performs a production-environment Wrangler dry run. The CI install requires the committed `pnpm-lock.yaml` and uses the repository-pinned package manager.

Read `AGENTS.md` and `docs/adr/` before substantial work.

The workspace lockfile is now present and CI requires it (`pnpm install --frozen-lockfile`). The current pinned pnpm also explicitly allows build scripts only for the exact esbuild/workerd versions needed for the web and Worker toolchains.

## License

**Proprietary. All rights reserved. This repository is not open source.**

Copyright © 2026 CLOUDJET SOLUTIONS PTE. LTD.

Access to, possession of, or accidental/public disclosure of this source code does **not** grant permission to use, execute, deploy, copy, modify, distribute, host, sublicense, or commercialize it. See [LICENSE](./LICENSE) for the complete terms. Third-party dependencies remain subject to their own licenses.
